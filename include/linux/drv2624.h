/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */
#ifndef _DRV2624_H_
#define _DRV2624_H_

#ifdef CONFIG_INPUT_DRV2624_HAPTICS
void drv2624_disable_haptics(void);
void drv2624_enable_haptics(void);
#else
static inline void drv2624_disable_haptics(void)
{
}
static inline void drv2624_enable_haptics(void)
{
}
#endif

#endif /* _DRV2624_H_ */
