/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 *
 * Operations for vmcs.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/vmx.h>

#include "slimvm.h"
#include "vmcs.h"

void vmcs_clear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (ASM_VMX_VMCLEAR_RAX "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");

	if (error)
		slimvm_error("vmclear fail: %p/%llx\n", vmcs, phys_addr);
}

void vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (ASM_VMX_VMPTRLD_RAX "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");

	if (error)
		slimvm_error("vmx: vmptrld %p/%llx failed\n", vmcs, phys_addr);
}

void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (ASM_VMX_VMWRITE_RAX_RDX "; setna %0"
		      : "=q"(error) : "a"(value), "d"(field) : "cc");

	if (unlikely(error))
		slimvm_error("vmx: vmcs write 0x%lx value 0x%lx failed\n",
			field, value);
}

void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}
