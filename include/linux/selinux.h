/*
 * SELinux services exported to the rest of the kernel.
 *
 * Author: James Morris <jmorris@redhat.com>
 *
 * Copyright (C) 2005 Red Hat, Inc., James Morris <jmorris@redhat.com>
 * Copyright (C) 2006 Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 * Copyright (C) 2006 IBM Corporation, Timothy R. Chavez <tinytim@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 */
#ifndef _LINUX_SELINUX_H
#define _LINUX_SELINUX_H

#include <linux/mutex.h>

struct selinux_audit_rule;
struct audit_context;
struct kern_ipc_perm;

struct file_security_struct {
	u32 sid;		/* SID of open file description */
	u32 fown_sid;		/* SID of file owner (for SIGIO) */
	u32 isid;		/* SID of inode at the time of file open */
	u32 pseqno;		/* Policy seqno at the time of file open */
};

struct inode_security_struct {
	struct inode *inode;	/* back pointer to inode object */
	struct list_head list;	/* list of inode_security_struct */
	u32 task_sid;		/* SID of creating task */
	u32 sid;		/* SID of this object */
	u16 sclass;		/* security class of this object */
	unsigned char initialized;	/* initialization flag */
	u32 tag;		/* Per-File-Encryption tag */
	void *pfk_data; /* Per-File-Key data from ecryptfs */
	struct mutex lock;
};

#ifdef CONFIG_SECURITY_SELINUX

/**
 * selinux_is_enabled - is SELinux enabled?
 */
bool selinux_is_enabled(void);
#else

static inline bool selinux_is_enabled(void)
{
	return false;
}
#endif	/* CONFIG_SECURITY_SELINUX */

#endif /* _LINUX_SELINUX_H */
