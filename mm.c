/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <asm/uaccess.h>
#include "instance.h"
#include "vmx.h"
#include "mm.h"

#define ADDR_INVAL ((unsigned long) -1)

/*
 * Must be called under instance->mm_mutex
 */
int check_mem_region(struct instance *instp, int num)
{
	struct mem_region *region = instp->memp;
	int i;

	/* General sanity checks */
	for (i = 0; i < num; i++) {
		if (region->size & (PAGE_SIZE - 1))
			return -EINVAL;

		if (region->gpa & (PAGE_SIZE - 1))
			return -EINVAL;

		if (region->gpa + region->size < region->gpa)
			return -EINVAL;

		region++;
	}

	return 0;
}

unsigned long hva_to_gpa(struct instance *instp, unsigned long hva)
{
	unsigned long gpa = ADDR_INVAL;
	int i;
	struct mem_region *region = instp->memp;

	for (i = 0; i < instp->mem_region_num; i++) {
		if (region->hva <= hva && region->hva + region->size > hva) {
			off_t off = hva - region->hva;
			gpa = region->gpa + off;
			break;
		}
		region++;
	}

	return gpa;
}

unsigned long gpa_to_hva(struct instance *instp, unsigned long gpa)
{
	unsigned long hva = ADDR_INVAL;
	struct mem_region *region = instp->memp;
	int i;

	for (i = 0; i < instp->mem_region_num; i++) {
		if (region->gpa <= gpa && region->gpa + region->size > gpa) {
			off_t off = gpa - region->gpa;
			hva = region->hva + off;
			break;
		}
		region++;
	}

	return hva;
}

int slimvm_set_tss_addr(struct instance *instp, unsigned long gpa, u32 size)
{
	if (size) {
		unsigned long hva;

		hva = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, 0);
		if (IS_ERR((void *) hva))
			return PTR_ERR((void *)hva);
	}

	return 0;
}
