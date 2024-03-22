/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef __LIBETH_CACHE_H
#define __LIBETH_CACHE_H

#include <linux/cache.h>

/* __aligned_largest is architecture-dependent. Get the actual alignment */
#define __LIBETH_LARGEST_ALIGN						    \
	sizeof(struct { long __UNIQUE_ID(long_); } __aligned_largest)

#define __libeth_cacheline_group_begin(grp)				    \
	__cacheline_group_begin(grp)					    \
	__aligned(__LIBETH_LARGEST_ALIGN) ____cacheline_aligned
#define __libeth_cacheline_group_end(grp)				    \
	__cacheline_group_end(grp) __aligned(__LIBETH_LARGEST_ALIGN)

#if defined(CONFIG_64BIT) && L1_CACHE_BYTES == 64
#define __libeth_cacheline_group_assert(type, grp, sz)			    \
	static_assert(offsetof(type, __cacheline_group_end__##grp) -	    \
		      offsetofend(type, __cacheline_group_begin__##grp) ==  \
		      ALIGN(sz, __LIBETH_LARGEST_ALIGN))
#define __libeth_cacheline_struct_assert(type, sz)			    \
	static_assert(sizeof(type) == ALIGN(sz, __LIBETH_LARGEST_ALIGN))
#else /* !CONFIG_64BIT || L1_CACHE_BYTES != 64 */
#define __libeth_cacheline_group_assert(type, grp, sz)			    \
	static_assert(offsetof(type, __cacheline_group_end__##grp) -	    \
		      offsetofend(type, __cacheline_group_begin__##grp) <=  \
		      ALIGN(sz, __LIBETH_LARGEST_ALIGN))
#define __libeth_cacheline_struct_assert(type, sz)
#endif /* !CONFIG_64BIT || L1_CACHE_BYTES != 64 */

#define __libeth_cacheline_set_assert(type, ro, rw, c)			    \
	__libeth_cacheline_group_assert(type, read_mostly, ro);		    \
	__libeth_cacheline_group_assert(type, read_write, rw);		    \
	__libeth_cacheline_group_assert(type, cold, c);			    \
	__libeth_cacheline_struct_assert(type, L1_CACHE_ALIGN(ro) +	    \
					       L1_CACHE_ALIGN(rw) +	    \
					       L1_CACHE_ALIGN(c))

#endif /* __LIBETH_CACHE_H */
