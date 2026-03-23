/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 */

#ifndef __SLIMVM_MEMORY_REGION_H_
#define __SLIMVM_MEMORY_REGION_H_

struct mem_region {
	unsigned long hva; // host virtual address
	unsigned long gpa; // guest physical address
	unsigned long size;
};

int slimvm_set_tss_addr(struct instance *instp, unsigned long gpa, u32 size);
unsigned long hva_to_gpa(struct instance *instp, unsigned long hva);
unsigned long gpa_to_hva(struct instance *instp, unsigned long gpa);
int check_mem_region(struct instance *instp, int num);

#endif

