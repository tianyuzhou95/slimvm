/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 */

#ifndef __VMCS_H
#define __VMCS_H

#ifndef ASM_VMX_VMCLEAR_RAX
#define ASM_VMX_VMCLEAR_RAX       ".byte 0x66, 0x0f, 0xc7, 0x30"
#endif
#ifndef ASM_VMX_VMLAUNCH
#define ASM_VMX_VMLAUNCH          ".byte 0x0f, 0x01, 0xc2"
#endif
#ifndef ASM_VMX_VMRESUME
#define ASM_VMX_VMRESUME          ".byte 0x0f, 0x01, 0xc3"
#endif
#ifndef ASM_VMX_VMPTRLD_RAX
#define ASM_VMX_VMPTRLD_RAX       ".byte 0x0f, 0xc7, 0x30"
#endif
#ifndef ASM_VMX_VMREAD_RDX_RAX
#define ASM_VMX_VMREAD_RDX_RAX    ".byte 0x0f, 0x78, 0xd0"
#endif
#ifndef ASM_VMX_VMWRITE_RAX_RDX
#define ASM_VMX_VMWRITE_RAX_RDX   ".byte 0x0f, 0x79, 0xd0"
#endif
#ifndef ASM_VMX_VMWRITE_RSP_RDX
#define ASM_VMX_VMWRITE_RSP_RDX   ".byte 0x0f, 0x79, 0xd4"
#endif
#ifndef ASM_VMX_VMXOFF
#define ASM_VMX_VMXOFF            ".byte 0x0f, 0x01, 0xc4"
#endif
#ifndef ASM_VMX_VMXON_RAX
#define ASM_VMX_VMXON_RAX         ".byte 0xf3, 0x0f, 0xc7, 0x30"
#endif
#ifndef ASM_VMX_INVEPT
#define ASM_VMX_INVEPT            ".byte 0x66, 0x0f, 0x38, 0x80, 0x08"
#endif
#ifndef ASM_VMX_INVVPID
#define ASM_VMX_INVVPID           ".byte 0x66, 0x0f, 0x38, 0x81, 0x08"
#endif

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct vmcs_config {
	int size;
	int order;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
};

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (ASM_VMX_VMREAD_RDX_RAX
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

static __always_inline u16 vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

static __always_inline u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((u64)vmcs_readl(field+1) << 32);
#endif
}

extern void vmcs_clear(struct vmcs *vmcs);
extern void vmcs_load(struct vmcs *vmcs);
extern void vmcs_writel(unsigned long field, unsigned long value);
extern void vmcs_write16(unsigned long field, u16 value);
extern void vmcs_write32(unsigned long field, u32 value);
extern void vmcs_write64(unsigned long field, u64 value);

#endif /* __VMCS_H */
