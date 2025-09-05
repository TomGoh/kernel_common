// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>
#include <asm/spectre.h>

#include <nvhe/early_alloc.h>
#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/modules.h>
#include <nvhe/spinlock.h>

/*
 * Hypervisor 自己的页表，用于管理 Hypervisor 在 EL2 的虚拟地址空间
 * 包括：
 *  - 管理 Hypervisor 代码，数据和栈的虚拟地址映射
 *  - 处理 Hypervisor 内部虚拟地址到物理地址的转换
 * 通过这个页表 Hypervisor 能够控制自己可以访问哪些物理内存，
 * 确保 Hypervisor 内存与 Host Kernel 和 Guest pVM 的内存完全隔离
 *
 * 注意： 这个页表不负责 Host 与 Guest pVM 的页表转换，仅仅是 Hypervisor 自用
*/
struct kvm_pgtable pkvm_pgtable;
hyp_spinlock_t pkvm_pgd_lock;

// 使用定义在 /include/linux/memblock.h 中的 memblock_region
// 记录 Hypervisor 被分配的内存区域，内存隔离的物理基础
struct memblock_region hyp_memory[HYP_MEMBLOCK_REGIONS];
// 使用一个无符号数记录 hypervisor 实际使用的区域数量
unsigned int hyp_memblock_nr;

// Hypervisor 私有虚拟地址分配的基地址指针，
// 用于跟踪hypervisor私有VA空间的分配位置, 随着新的私有映射创建而动态增长
// 确保私有VA分配不会重叠
// 在 hyp_create_idmap() 中初始化其值 
// 在 pkvm_alloc_private_va_range() 中作为分配起点
static u64 __io_map_base;

/*
 * 临时映射槽位结构，用于hypervisor的临时页面映射
 * 为hypervisor提供临时的、可动态修改的页面映射，无需分配新的页表页
 * 
 * 使用示例：
 *   // 临时映射一个物理页面进行访问
 *   void *ptr = hyp_fixmap_map(phys_addr);
 *   // 使用ptr访问该物理页面
 *   // 完成后解除映射
 *   hyp_fixmap_unmap();
 */
struct hyp_fixmap_slot {
	// 该 fixmap槽对应的虚拟地址
	u64 addr;
	// 页表项指针，指向该虚拟地址对应的页表项，用于快速修改映射
	kvm_pte_t *ptep;
	// 页表层级，用于标注该页表项所在的层级
	u8 level;
};
static DEFINE_PER_CPU(struct hyp_fixmap_slot, fixmap_slots);

/*
 * pKVM的核心映射函数，负责在 hypervisor 页表 pkvm_pgtable 中创建虚拟地址到物理地址的映射
 * 
 * 函数参数：
 * - start：虚拟地址起始位置
 * - size: 映射区域大小
 * - phys: 物理地址起始位置
 * - prot: 页面保护属性（可读/可写/可执行等）
 * 
 * 返回值： 映射结果(0=成功，负数=错误)
 */
static int __pkvm_create_mappings(unsigned long start, unsigned long size,
				  unsigned long phys, enum kvm_pgtable_prot prot)
{
	int err;

	// 保护pkvm_pgtable页表的并发访问
	hyp_spin_lock(&pkvm_pgd_lock);
	// 实际的页表映射操作，所有参数直接传给底层API kvm_pgtable_hyp_map
	err = kvm_pgtable_hyp_map(&pkvm_pgtable, start, size, phys, prot);
	// 释放锁
	hyp_spin_unlock(&pkvm_pgd_lock);

	return err;
}

static int __pkvm_alloc_private_va_range(unsigned long start, size_t size)
{
	unsigned long cur;

	hyp_assert_lock_held(&pkvm_pgd_lock);

	if (!start || start < __io_map_base)
		return -EINVAL;

	/* The allocated size is always a multiple of PAGE_SIZE */
	cur = start + PAGE_ALIGN(size);

	/* Are we overflowing on the vmemmap ? */
	if (cur > __hyp_vmemmap)
		return -ENOMEM;

	__io_map_base = cur;

	return 0;
}

/**
 * pkvm_alloc_private_va_range - Allocates a private VA range.
 * @size:	The size of the VA range to reserve.
 * @haddr:	The hypervisor virtual start address of the allocation.
 *
 * The private virtual address (VA) range is allocated above __io_map_base
 * and aligned based on the order of @size.
 *
 * Return: 0 on success or negative error code on failure.
 */
int pkvm_alloc_private_va_range(size_t size, unsigned long *haddr)
{
	unsigned long addr;
	int ret;

	hyp_spin_lock(&pkvm_pgd_lock);
	addr = __io_map_base;
	ret = __pkvm_alloc_private_va_range(addr, size);
	hyp_spin_unlock(&pkvm_pgd_lock);

	*haddr = addr;

	return ret;
}

int __pkvm_create_private_mapping(phys_addr_t phys, size_t size,
				  enum kvm_pgtable_prot prot,
				  unsigned long *haddr)
{
	unsigned long addr;
	int err;

	size = PAGE_ALIGN(size + offset_in_page(phys));
	err = pkvm_alloc_private_va_range(size, &addr);
	if (err)
		return err;

	err = __pkvm_create_mappings(addr, size, phys, prot);
	if (err)
		return err;

	*haddr = addr + offset_in_page(phys);
	return err;
}

int __hyp_allocator_map(unsigned long va, phys_addr_t phys)
{
	return __pkvm_create_mappings(va, PAGE_SIZE, phys, PAGE_HYP);
}

#ifdef CONFIG_NVHE_EL2_DEBUG
static unsigned long mod_range_start = ULONG_MAX;
static unsigned long mod_range_end;
static DEFINE_HYP_SPINLOCK(mod_range_lock);

static void update_mod_range(unsigned long addr, size_t size)
{
	hyp_spin_lock(&mod_range_lock);
	mod_range_start = min(mod_range_start, addr);
	mod_range_end = max(mod_range_end, addr + size);
	hyp_spin_unlock(&mod_range_lock);
}

void assert_in_mod_range(unsigned long addr)
{
	/*
	 * This is not entirely watertight if there are private range
	 * allocations between modules being loaded, but in practice that is
	 * probably going to be allocation initiated by the modules themselves.
	 */
	hyp_spin_lock(&mod_range_lock);
	WARN_ON(addr < mod_range_start || mod_range_end <= addr);
	hyp_spin_unlock(&mod_range_lock);
}
#else
static inline void update_mod_range(unsigned long addr, size_t size) { }
#endif

void *__pkvm_alloc_module_va(u64 nr_pages)
{
	size_t size = nr_pages << PAGE_SHIFT;
	unsigned long addr = 0;

	if (!pkvm_alloc_private_va_range(size, &addr))
		update_mod_range(addr, size);

	return (void *)addr;
}

int __pkvm_map_module_page(u64 pfn, void *va, enum kvm_pgtable_prot prot, bool is_protected)
{
	unsigned long addr = (unsigned long)va;
	int ret;

	assert_in_mod_range(addr);

	if (!is_protected) {
		ret = __pkvm_host_donate_hyp(pfn, 1);
		if (ret)
			return ret;
	}

	ret = __pkvm_create_mappings(addr, PAGE_SIZE, hyp_pfn_to_phys(pfn), prot);
	if (ret && !is_protected)
		WARN_ON(__pkvm_hyp_donate_host(pfn, 1));

	return ret;
}

void __pkvm_unmap_module_page(u64 pfn, void *va)
{
	WARN_ON(__pkvm_hyp_donate_host(pfn, 1));
	pkvm_remove_mappings(va, va + PAGE_SIZE);
}

int pkvm_create_mappings_locked(void *from, void *to, enum kvm_pgtable_prot prot)
{
	unsigned long start = (unsigned long)from;
	unsigned long end = (unsigned long)to;
	unsigned long virt_addr;
	phys_addr_t phys;

	hyp_assert_lock_held(&pkvm_pgd_lock);

	start = start & PAGE_MASK;
	end = PAGE_ALIGN(end);

	for (virt_addr = start; virt_addr < end; virt_addr += PAGE_SIZE) {
		int err;

		phys = hyp_virt_to_phys((void *)virt_addr);
		err = kvm_pgtable_hyp_map(&pkvm_pgtable, virt_addr, PAGE_SIZE,
					  phys, prot);
		if (err)
			return err;
	}

	return 0;
}

int pkvm_create_mappings(void *from, void *to, enum kvm_pgtable_prot prot)
{
	int ret;

	hyp_spin_lock(&pkvm_pgd_lock);
	ret = pkvm_create_mappings_locked(from, to, prot);
	hyp_spin_unlock(&pkvm_pgd_lock);

	return ret;
}

void pkvm_remove_mappings(void *from, void *to)
{
	unsigned long size = (unsigned long)to - (unsigned long)from;

	hyp_spin_lock(&pkvm_pgd_lock);
	WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, (u64)from, size) != size);
	hyp_spin_unlock(&pkvm_pgd_lock);
}

int hyp_back_vmemmap(phys_addr_t back)
{
	unsigned long i, start, size, end = 0;
	int ret;

	for (i = 0; i < hyp_memblock_nr; i++) {
		start = hyp_memory[i].base;
		start = ALIGN_DOWN((u64)hyp_phys_to_page(start), PAGE_SIZE);
		/*
		 * The begining of the hyp_vmemmap region for the current
		 * memblock may already be backed by the page backing the end
		 * the previous region, so avoid mapping it twice.
		 */
		start = max(start, end);

		end = hyp_memory[i].base + hyp_memory[i].size;
		end = PAGE_ALIGN((u64)hyp_phys_to_page(end));
		if (start >= end)
			continue;

		size = end - start;
		ret = __pkvm_create_mappings(start, size, back, PAGE_HYP);
		if (ret)
			return ret;

		memset(hyp_phys_to_virt(back), 0, size);
		back += size;
	}

	return 0;
}

static void *__hyp_bp_vect_base;
int pkvm_cpu_set_vector(enum arm64_hyp_spectre_vector slot)
{
	void *vector;

	switch (slot) {
	case HYP_VECTOR_DIRECT: {
		vector = __kvm_hyp_vector;
		break;
	}
	case HYP_VECTOR_SPECTRE_DIRECT: {
		vector = __bp_harden_hyp_vecs;
		break;
	}
	case HYP_VECTOR_INDIRECT:
	case HYP_VECTOR_SPECTRE_INDIRECT: {
		vector = (void *)__hyp_bp_vect_base;
		break;
	}
	default:
		return -EINVAL;
	}

	vector = __kvm_vector_slot2addr(vector, slot);
	*this_cpu_ptr(&kvm_hyp_vector) = (unsigned long)vector;

	return 0;
}

int hyp_map_vectors(void)
{
	phys_addr_t phys;
	unsigned long bp_base;
	int ret;

	if (!kvm_system_needs_idmapped_vectors()) {
		__hyp_bp_vect_base = __bp_harden_hyp_vecs;
		return 0;
	}

	phys = __hyp_pa(__bp_harden_hyp_vecs);
	ret = __pkvm_create_private_mapping(phys, __BP_HARDEN_HYP_VECS_SZ,
					    PAGE_HYP_EXEC, &bp_base);
	if (ret)
		return ret;

	__hyp_bp_vect_base = (void *)bp_base;

	return 0;
}

static void *fixmap_map_slot(struct hyp_fixmap_slot *slot, phys_addr_t phys)
{
	kvm_pte_t pte, *ptep = slot->ptep;

	pte = *ptep;
	pte &= ~kvm_phys_to_pte(KVM_PHYS_INVALID);
	pte |= kvm_phys_to_pte(phys) | KVM_PTE_VALID;
	WRITE_ONCE(*ptep, pte);
	dsb(ishst);

	return (void *)slot->addr + offset_in_page(phys);
}

void *hyp_fixmap_map(phys_addr_t phys)
{
	return fixmap_map_slot(this_cpu_ptr(&fixmap_slots), phys);
}

static void fixmap_clear_slot(struct hyp_fixmap_slot *slot)
{
	kvm_pte_t *ptep = slot->ptep;
	u64 addr = slot->addr;

	WRITE_ONCE(*ptep, *ptep & ~KVM_PTE_VALID);

	/*
	 * Irritatingly, the architecture requires that we use inner-shareable
	 * broadcast TLB invalidation here in case another CPU speculates
	 * through our fixmap and decides to create an "amalagamation of the
	 * values held in the TLB" due to the apparent lack of a
	 * break-before-make sequence.
	 *
	 * https://lore.kernel.org/kvm/20221017115209.2099-1-will@kernel.org/T/#mf10dfbaf1eaef9274c581b81c53758918c1d0f03
	 */
	dsb(ishst);
	__tlbi_level(vale2is, __TLBI_VADDR(addr, 0), slot->level);
	dsb(ish);
	isb();
}

void hyp_fixmap_unmap(void)
{
	fixmap_clear_slot(this_cpu_ptr(&fixmap_slots));
}

static int __create_fixmap_slot_cb(const struct kvm_pgtable_visit_ctx *ctx,
				   enum kvm_pgtable_walk_flags visit)
{
	struct hyp_fixmap_slot *slot = (struct hyp_fixmap_slot *)ctx->arg;

	if (!kvm_pte_valid(ctx->old) || ctx->level != slot->level)
		return -EINVAL;

	slot->addr = ctx->addr;
	slot->ptep = ctx->ptep;

	/*
	 * Clear the PTE, but keep the page-table page refcount elevated to
	 * prevent it from ever being freed. This lets us manipulate the PTEs
	 * by hand safely without ever needing to allocate memory.
	 */
	fixmap_clear_slot(slot);

	return 0;
}

static int create_fixmap_slot(u64 addr, u64 cpu)
{
	struct kvm_pgtable_walker walker = {
		.cb	= __create_fixmap_slot_cb,
		.flags	= KVM_PGTABLE_WALK_LEAF,
		.arg = (void *)per_cpu_ptr(&fixmap_slots, cpu),
	};

	per_cpu_ptr(&fixmap_slots, cpu)->level = KVM_PGTABLE_MAX_LEVELS - 1;

	return kvm_pgtable_walk(&pkvm_pgtable, addr, PAGE_SIZE, &walker);
}

#ifndef CONFIG_ARM64_64K_PAGES
static struct hyp_fixmap_slot hyp_fixblock_slot;
static DEFINE_HYP_SPINLOCK(hyp_fixblock_lock);

void *hyp_fixblock_map(phys_addr_t phys)
{
	WARN_ON(!IS_ALIGNED(phys, PMD_SIZE));

	hyp_spin_lock(&hyp_fixblock_lock);
	return fixmap_map_slot(&hyp_fixblock_slot, phys);
}

void hyp_fixblock_unmap(void)
{
	fixmap_clear_slot(&hyp_fixblock_slot);
	hyp_spin_unlock(&hyp_fixblock_lock);
}

static int create_fixblock(void)
{
	struct kvm_pgtable_walker walker = {
		.cb	= __create_fixmap_slot_cb,
		.flags	= KVM_PGTABLE_WALK_LEAF,
		.arg = (void *)&hyp_fixblock_slot,
	};
	unsigned long addr;
	phys_addr_t phys;
	int ret, i;

	/* Find a RAM phys address, PMD aligned */
	for (i = 0; i < hyp_memblock_nr; i++) {
		phys = ALIGN(hyp_memory[i].base, PMD_SIZE);
		if (phys + PMD_SIZE < (hyp_memory[i].base + hyp_memory[i].size))
			break;
	}

	/* Really? Your RAM isn't larger than a couple of times PMD_SIZE? */
	if (i >= hyp_memblock_nr)
		return -EINVAL;

	hyp_spin_lock(&pkvm_pgd_lock);
	addr = ALIGN(__io_map_base, PMD_SIZE);
	ret = __pkvm_alloc_private_va_range(addr, PMD_SIZE);
	if (ret)
		goto unlock;

	ret = kvm_pgtable_hyp_map(&pkvm_pgtable, addr, PMD_SIZE, phys, PAGE_HYP);
	if (ret)
		goto unlock;

	hyp_fixblock_slot.level = KVM_PGTABLE_MAX_LEVELS - 2;
	ret = kvm_pgtable_walk(&pkvm_pgtable, addr, PMD_SIZE, &walker);
unlock:
	hyp_spin_unlock(&pkvm_pgd_lock);

	return ret;
}
#else
void hyp_fixblock_unmap(void) { WARN_ON(1); }
void *hyp_fixblock_map(phys_addr_t phys) { return NULL; }
static int create_fixblock(void) { return 0; }
#endif

int hyp_create_fixmap(void)
{
	unsigned long addr, i;
	int ret;

	for (i = 0; i < hyp_nr_cpus; i++) {
		ret = pkvm_alloc_private_va_range(PAGE_SIZE, &addr);
		if (ret)
			return ret;

		ret = kvm_pgtable_hyp_map(&pkvm_pgtable, addr, PAGE_SIZE,
					  __hyp_pa(__hyp_bss_start), PAGE_HYP);
		if (ret)
			return ret;

		ret = create_fixmap_slot(addr, i);
		if (ret)
			return ret;
	}

	return create_fixblock();
}

/*
 * 为 Hypervisor 创建恒等映射（iddentical mapping），同时初始化虚拟地址空间布局，
 * 为IO映射和vmemmap预留独立空间，确保不同用途的VA区域不会重叠
 * 划分完成后调用 __pkvm_create_mappings 创建恒等映射
 * 
 * 在 __pkvm_init 中通过 recreate_hyp_mappings 被调用
 * 
 * 输入参数:
 *  - `hyp_va_bits`： Hypervisor 虚拟地址的位数，一般为 39 或 48 位
 * 
 * 返回值：
 *  - 调用 `__pkvm_create_mappings` 进行映射创建的具体结果
 */
int hyp_create_idmap(u32 hyp_va_bits)
{
	unsigned long start, end;
	
	// 计算恒等映射需要的范围，包括起始地址，结束地址
	// 起始地址来自于链接时 vmlinux.lds.S 的定义
	start = hyp_virt_to_phys((void *)__hyp_idmap_text_start);
	// 页对齐
	start = ALIGN_DOWN(start, PAGE_SIZE);

	// 终止位置一样来自与链接文件的定义
	end = hyp_virt_to_phys((void *)__hyp_idmap_text_end);
	end = ALIGN(end, PAGE_SIZE);

	/*
	 * One half of the VA space is reserved to linearly map portions of
	 * memory -- see va_layout.c for more details. The other half of the VA
	 * space contains the trampoline page, and needs some care. Split that
	 * second half in two and find the quarter of VA space not conflicting
	 * with the idmap to place the IOs and the vmemmap. IOs use the lower
	 * half of the quarter and the vmemmap the upper half.
	 */

	/*
	 * 取start地址的 hyp_va_bits - 2 位
	 * 
	 * BIT(hyp_va_bits - 2) = 第(hyp_va_bits-2)位设为1
	 * BIT 生成一个特定位的掩码，通过将数字 1 左移指定的位数 (nr) 
	 * 以39位为例：BIT(37) = 0x2000000000 (第37位为1)
	 * start & BIT(37) 提取start地址的第37位
	 * 结果： 要么是0，要么是0x2000000000，假设为0
	 */
	__io_map_base = start & BIT(hyp_va_bits - 2);
	/* 
	 * 翻转第 hyp_va_bits - 2 位
	 * 
	 * 如果上一步结果是0，异或后变成0x2000000000
	 * 如果上一步结果是0x2000000000，异或后变成0
	 * 目的： 确保IO映射区域与idmap不在同一个VA空间半区
	 */
	__io_map_base ^= BIT(hyp_va_bits - 2);
	/*
	 * 在IO区域基础上设置第(hyp_va_bits-3)位
	 * 
	 * BIT(hyp_va_bits - 3) = 第(hyp_va_bits-3)位设为1
	 * 以39位为例：BIT(36) = 0x1000000000
	 * __io_map_base | BIT(36) 在IO基地址基础上加上这一位
	 * __hyp_vmemmap = 0x2000000000 + 0x1000000000 = 0x3000000000
	 * 结果： vmemmap区域在IO区域的上半部分
	*/
	__hyp_vmemmap = __io_map_base | BIT(hyp_va_bits - 3);

	/*
	 * 
	 *
	 *   VA空间分布 (39位 = 512GB)：
  ┌─────────────────────┐ 0x8000000000 (512GB)
  │   Linear Mapping       │ ← 上半部分 (256GB)
  │   (物理内存线性映射)  │
  ├─────────────────────┤ 0x4000000000 (256GB)
  │     vmemmap          │ ← 第四象限 (64GB)
  ├─────────────────────┤ 0x3000000000 (192GB)
  │   IO Mapping        │ ← 第三象限 (64GB)
  ├─────────────────────┤ 0x2000000000 (128GB)
  │    idmap/其他      │ ← 第二象限 (128GB)
  ├─────────────────────┤
  │      预留区        │ ← 第一象限
  └─────────────────────┘ 0x0000000000
	 *
   	 */

	return __pkvm_create_mappings(start, end - start, start, PAGE_HYP_EXEC);
}

int pkvm_create_stack(phys_addr_t phys, unsigned long *haddr)
{
	unsigned long addr, prev_base;
	size_t size;
	int ret;

	hyp_spin_lock(&pkvm_pgd_lock);

	prev_base = __io_map_base;
	/*
	 * Efficient stack verification using the PAGE_SHIFT bit implies
	 * an alignment of our allocation on the order of the size.
	 */
	size = PAGE_SIZE * 2;
	addr = ALIGN(__io_map_base, size);

	ret = __pkvm_alloc_private_va_range(addr, size);
	if (!ret) {
		/*
		 * Since the stack grows downwards, map the stack to the page
		 * at the higher address and leave the lower guard page
		 * unbacked.
		 *
		 * Any valid stack address now has the PAGE_SHIFT bit as 1
		 * and addresses corresponding to the guard page have the
		 * PAGE_SHIFT bit as 0 - this is used for overflow detection.
		 */
		ret = kvm_pgtable_hyp_map(&pkvm_pgtable, addr + PAGE_SIZE,
					  PAGE_SIZE, phys, PAGE_HYP);
		if (ret)
			__io_map_base = prev_base;
	}
	hyp_spin_unlock(&pkvm_pgd_lock);

	*haddr = addr + size;

	return ret;
}

/*
 * pKVM 管理的核心桥梁函数，负责将 Host 拥有的物理页面转移给 Hypervisor 使用
 * 
 * 参数：
 *  - arg： 一个指向 struct kvm_hyp_memcache* host_mc 的指针，是 Host 提供的内存缓存
 *  - order: 页面分配的阶数，和 Linux 的批量分配连续物理页面机制相关。简而言之直接对应需要的页面数量：
 * 			页面数量= 2 ^ （阶数），这在页面大小确定的情况下也间接指定了需要的内存的大小。
 * 
 * 返回值：
 * 	- 成功则返回转移的页面在 hypervisor 内对应的虚拟地址，失败则返回 NULL。
 */
static void *admit_host_page(void *arg, unsigned long order)
{
	phys_addr_t p;
	struct kvm_hyp_memcache *host_mc = arg;
	unsigned long mc_order;

	// 首先使用 Host 的 memcache 验证是否还有页面可用，没有就返回 NULL
	if (!host_mc->nr_pages)
		return NULL;

	// Host 的 memcache 中的 head部分同时编码了：
	// - memcache 中管理的阶数大小
	// - memcache 对应的页面物理地址
	// 首先从 Host 的 memcache 中提取其阶数信息
	mc_order = FIELD_GET(~PAGE_MASK, host_mc->head);
	// 如果 Host 的 memcache 阶数和所要求的的阶数不一致则失败，这是因为：
	// 阶数实质上是 host memcache 进行页面管理的单位，若是不匹配则无法精准确定
	// 被转移的页面区块，memcache 管理的都是固定大小的块
	BUG_ON(order != mc_order);
	// 获得页面物理地址
	p = host_mc->head & PAGE_MASK;
	/*
	 * The host still owns the pages in its memcache, so we need to go
	 * through a full host-to-hyp donation cycle to change it. Fortunately,
	 * __pkvm_host_donate_hyp() takes care of races for us, so if it
	 * succeeds we're good to go.
	 */
	/*
	 * 检查完基础信息过后，进行从 Host memcache 到 Hypervisor 的所有权转移
	 * 1 << order 指定了需要的页面的个数
	 * 转移完成后 host 不再拥有这部分页面的所有权
	 */
	if (__pkvm_host_donate_hyp(hyp_phys_to_pfn(p), 1 << order))
		return NULL;
	/*
	 * 由于进行了从 Host 到 hypervisor 的页面转移，因此需要更新 Host 的 memcache，
	 * 从 Host 的memcache 中移除对应的页面，返回这些转移到 Hypervisor 名下的页面
	 * 在Hypervisor 地址空间中的虚拟地址
	 */
	return pop_hyp_memcache(host_mc, hyp_phys_to_virt, &order);
}

/* Refill our local memcache by poping pages from the one provided by the host. */
int refill_memcache(struct kvm_hyp_memcache *mc, unsigned long min_pages,
		    struct kvm_hyp_memcache *host_mc)
{
	struct kvm_hyp_memcache tmp = *host_mc;
	int ret;

	ret =  __topup_hyp_memcache(mc, min_pages, admit_host_page,
				    hyp_virt_to_phys, &tmp, 0);
	*host_mc = tmp;

	return ret;
}

phys_addr_t __pkvm_private_range_pa(void *va)
{
	kvm_pte_t pte;
	u32 level;

	hyp_spin_lock(&pkvm_pgd_lock);
	WARN_ON(kvm_pgtable_get_leaf(&pkvm_pgtable, (u64)va, &pte, &level));
	hyp_spin_unlock(&pkvm_pgd_lock);

	BUG_ON(!kvm_pte_valid(pte));

	return kvm_pte_to_phys(pte) + offset_in_page(va);
}

/* The host passed a mc, fill a pool with the pages in it. */
int refill_hyp_pool(struct hyp_pool *pool, struct kvm_hyp_memcache *host_mc)
{
	unsigned long order;
	void *p;

	while (host_mc->nr_pages) {
		order = FIELD_GET(~PAGE_MASK, host_mc->head);
		p = admit_host_page(host_mc, order);
		if (!p)
			return -EINVAL;
		hyp_virt_to_page(p)->order = order;
		hyp_set_page_refcounted(hyp_virt_to_page(p));
		hyp_put_page(pool, p);
	}

	return 0;
}

/*
 * Remove target pages from the pool and put them in a memcache,
 * so the host can reclaim them.
 */
int reclaim_hyp_pool(struct hyp_pool *pool, struct kvm_hyp_memcache *host_mc,
		     int nr_pages)
{
	void *p;
	struct hyp_page *page;

	while (nr_pages > 0) {
		p = hyp_alloc_pages(pool, 0);
		if (!p)
			return -ENOMEM;
		page = hyp_virt_to_page(p);
		nr_pages -= (1 << page->order);
		push_hyp_memcache(host_mc, p, hyp_virt_to_phys, page->order);
		WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(p), 1 << page->order));
		memset(page, 0, sizeof(struct hyp_page));
	}

	return 0;
}
