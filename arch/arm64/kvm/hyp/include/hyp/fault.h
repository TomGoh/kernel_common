// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#ifndef __ARM64_KVM_HYP_FAULT_H__
#define __ARM64_KVM_HYP_FAULT_H__

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

/*
 * 使用 `__kvm_at` 指令将 FAR_EL2 寄存器中的 Guest 虚拟地址转译为 HPFAR_EL2 格式的物理地址
*/
static inline bool __translate_far_to_hpfar(u64 far, u64 *hpfar)
{
	u64 par, tmp;

	/*
	 * Resolve the IPA the hard way using the guest VA.
	 *
	 * Stage-1 translation already validated the memory access
	 * rights. As such, we can use the EL1 translation regime, and
	 * don't have to distinguish between EL0 and EL1 access.
	 *
	 * We do need to save/restore PAR_EL1 though, as we haven't
	 * saved the guest context yet, and we may return early...
	 */


	// 1. 保存当前PAR_EL1寄存器状态
	// PAR_EL1 (Physical Address Result, Exception Level 1)
	// 作用：存储AT指令的地址翻译结果
	par = read_sysreg_par();
	// 2. 使用AT指令进行 stage-1 地址翻译
	if (!__kvm_at("s1e1r", far))
		tmp = read_sysreg_par(); // 翻译成功，读取结果
	else
		tmp = SYS_PAR_EL1_F; // 翻译失败，设置失败标志，最终将返回 Guest
	// 3. 恢复PAR_EL1寄存器
	write_sysreg(par, par_el1);

	// 4. 检查翻译是否成功
	if (unlikely(tmp & SYS_PAR_EL1_F))
		return false; // 翻译失败，返回 false，最终将返回 Guest

	// 5. 将PAR格式转换为HPFAR格式
	*hpfar = PAR_TO_HPFAR(tmp);
	return true;
}

/*
 * 获得故障信息，主要是从系统寄存器中提取故障地址信息，填充到vCPU的故障信息结构中
*/
static inline bool __get_fault_info(u64 esr, struct kvm_vcpu_fault_info *fault)
{
	u64 hpfar, far;
	// 首先读取 FAR_EL2 寄存器，该寄存器中存储了导致异常的虚拟地址
	// 该虚拟地址是 Guest 产生数据访问异常时试图访问的虚拟地址
	far = read_sysreg_el2(SYS_FAR);

  /*
   * 处理 HPFAR_EL2 (Hypervisor Physical Fault Address Register)
   * HPFAR在以下情况可能无效:
   * 1. stage 2故障不是在stage 1页表遍历时发生的 (ESR_EL2.S1PTW bit清零)
   * 2. 满足以下任一条件:
   *    - 故障是权限故障
   *    - 处理器存在errata 834220问题
   */

   // 检查 ESR_EL2的S1PTW位没有清零 && (ARM errata 834220 || 为权限故障)
   // ESR_EL2 的 S1PTW 如果清零，说明 Stage 2故障不是在 Stage 1页表遍历过程发生的
   // 也就是说：
   // 在 故障不是在 Stage 1 遍历过程发生 &&  (Arm 834220 勘误 || Guest 访问没有权限的页面) 时
   // HPFAR_EL2 寄存器时无效的
	if (!(esr & ESR_ELx_S1PTW) &&
	    (cpus_have_final_cap(ARM64_WORKAROUND_834220) ||
	     (esr & ESR_ELx_FSC_TYPE) == ESR_ELx_FSC_PERM)) {
		// 当 HPFAR 无效时，需要手动进行地址翻译，
		// 将 FAR 中的 Guest 虚拟地址翻译为 Hypervisor 管理下 HPFAR 格式的物理地址
		// 结果将存入 hpfar 这一内存变量
		if (!__translate_far_to_hpfar(far, &hpfar))
			// 如果翻译失败，返回 false，最终将再次进入 Guest
			return false;
	} else {
		// HPFAR_EL2 寄存器有效，直接读取
		hpfar = read_sysreg(hpfar_el2);
	}

	// 设置错误信息中的地址信息，包括虚拟地址和物理地址，返回 true 代表错误信息收集成功
	fault->far_el2 = far;
	fault->hpfar_el2 = hpfar;
	return true;
}

#endif
