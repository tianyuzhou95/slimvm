/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Ant Group Corporation.
 */

#include <linux/errno.h>
#include <linux/sysctl.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/version.h>

#include "proc.h"
#include "slimvm.h"
#include "vmx.h"
#include "instance.h"

#define SLIMVM_OP_RECLAIM_LEAKED_INSTANCES 100678677

static struct ctl_table_header *slimvm_sysctl_header;
static int slimvm_vcpu_num;
static int slimvm_vm_num;
static long slimvm_operation_code;

int slimvm_debug_enable;

static struct proc_dir_entry *slimvm_proc_dir;
static struct proc_dir_entry *vm_mem_stat;

static int read_vcpu_num(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	slimvm_vcpu_num = instance_get_vcpu_num();
	proc_dointvec(table, write, buffer, lenp, ppos);

	return 0;
}

static int read_vm_num(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	slimvm_vm_num = instance_get_vm_num();
	proc_dointvec(table, write, buffer, lenp, ppos);

	return 0;
}

static int slimvm_do_operation(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	proc_doulongvec_minmax(table, write, buffer, lenp, ppos);

	if (write) {
		switch (slimvm_operation_code) {
		case SLIMVM_OP_RECLAIM_LEAKED_INSTANCES:
			slimvm_reclaim_leaked_instances();
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

struct ctl_table slimvm_table[] = {
	{
		.procname	= "slimvm_vcpu_num",
		.data		= &slimvm_vcpu_num,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= read_vcpu_num
	},
	{
		.procname	= "slimvm_vm_num",
		.data		= &slimvm_vm_num,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= read_vm_num
	},
	{
		.procname	= "slimvm_operation",
		.data		= &slimvm_operation_code,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0200,
		.proc_handler	= slimvm_do_operation,
	},
	{
		.procname	= "slimvm_debug_enable",
		.data		= &slimvm_debug_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};
struct ctl_table slimvm_sysctl_table[] = {
	{
		.procname	= "slimvm",
		.mode		= 0555,
		.child		= slimvm_table,
	},
	{ }
};

static void ept_show_vm_mem_stat(struct instance *instp, void *data)
{
	char buf[128];
	struct seq_file *seq = data;

	sprintf(buf, "%lx %lld %lld %lld %llx %lld\n",
		instp->sid, instp->ept_4k_pages, instp->ept_2m_pages,
		instp->ept_invl_count, instp->ept_invl_range,
		instp->ept_invl_ipi);
	seq_puts(seq, buf);
}

static int ept_stat_show(struct seq_file *seq, void *offset)
{
	seq_puts(seq, "SID 4K 2M invl_count invl_range invl_ipi\n");
	on_each_vm_instance(ept_show_vm_mem_stat, seq);

	return 0;
}

static int ept_stat_open(struct inode *inode, struct file *file)
{
	return single_open(file, ept_stat_show, NULL);
}

static const struct proc_ops vm_mem_stat_fops = {
	.proc_open	= ept_stat_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

bool slimvm_sysctl_init(void)
{
	char buf[64];

	slimvm_sysctl_header = register_sysctl_table(slimvm_sysctl_table);
	if (!slimvm_sysctl_header)
		return false;

	sprintf(buf, "slimvm");
	slimvm_proc_dir = proc_mkdir(buf, NULL);
	if (slimvm_proc_dir)
		vm_mem_stat = proc_create("vm_mem_stat", 0444,
				slimvm_proc_dir, &vm_mem_stat_fops);

	return true;
}

void slimvm_sysctl_exit(void)
{
	if (vm_mem_stat)
		proc_remove(vm_mem_stat);
	if (slimvm_proc_dir)
		proc_remove(slimvm_proc_dir);

	if (slimvm_sysctl_header) {
		unregister_sysctl_table(slimvm_sysctl_header);
		slimvm_sysctl_header = NULL;
	}
}
