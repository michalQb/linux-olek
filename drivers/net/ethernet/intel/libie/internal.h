// SPDX-License-Identifier: GPL-2.0-only
/* libie internal declarations not to be used in drivers.
 *
 * Copyright(c) 2023 Intel Corporation.
 */

#ifndef __LIBIE_INTERNAL_H
#define __LIBIE_INTERNAL_H

#include <linux/export.h>

#define LIBIE_EXPORT_SYMBOL(s)		EXPORT_SYMBOL_NS_GPL(s, LIBIE)

#endif /* __LIBIE_INTERNAL_H */
