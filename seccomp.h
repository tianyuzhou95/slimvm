/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 */

#ifndef _SLIMVM_SECCOMP_H_
#define _SLIMVM_SECCOMP_H_
#include "vmx.h"

int do_seccomp_filter(struct vmx_vcpu *vcpu);
#endif
