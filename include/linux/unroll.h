/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef __LINUX_UNROLL_H
#define __LINUX_UNROLL_H

#include <linux/build_bug.h>

#ifdef CONFIG_CC_IS_CLANG
#define __pick_unrolled(x, y)	_Pragma(#x)
#elif CONFIG_GCC_VERSION >= 80000
#define __pick_unrolled(x, y)	_Pragma(#y)
#else
#define __pick_unrolled(x, y)	/* not supported */
#endif

#define unrolled							    \
	__pick_unrolled(clang loop unroll(enable), /* nothing */)
#define unrolled_count(n)						    \
	__pick_unrolled(clang loop unroll_count(n), GCC unroll n)
#define unrolled_full							    \
	__pick_unrolled(clang loop unroll(full), GCC unroll 65534)
#define unrolled_none							    \
	__pick_unrolled(clang loop unroll(disable), GCC unroll 1)

/**
 * unrolled_call - explicitly unroll a loop, for use in cases where doing so
 * is performance critical
 * @times: number of times to call @fn
 * @fn: function to call repeatedly
 *
 * Ideally we'd rely upon the compiler to provide this but there's no commonly
 * available means to do so. For example GCC's `#pragma GCC unroll`
 * functionality would be ideal but is only available from GCC 8 onwards.
 * Using `-funroll-loops` is an option but GCC tends to make poor choices when
 * compiling string functions. `-funroll-all-loops` leads to massive code
 * bloat, even if only applied to the string functions.
 */
#define unrolled_call(times, fn, ...) do {				    \
	static_assert(__builtin_constant_p(times));			    \
									    \
	switch (times) {						    \
	case 32: fn(__VA_ARGS__); fallthrough;				    \
	case 31: fn(__VA_ARGS__); fallthrough;				    \
	case 30: fn(__VA_ARGS__); fallthrough;				    \
	case 29: fn(__VA_ARGS__); fallthrough;				    \
	case 28: fn(__VA_ARGS__); fallthrough;				    \
	case 27: fn(__VA_ARGS__); fallthrough;				    \
	case 26: fn(__VA_ARGS__); fallthrough;				    \
	case 25: fn(__VA_ARGS__); fallthrough;				    \
	case 24: fn(__VA_ARGS__); fallthrough;				    \
	case 23: fn(__VA_ARGS__); fallthrough;				    \
	case 22: fn(__VA_ARGS__); fallthrough;				    \
	case 21: fn(__VA_ARGS__); fallthrough;				    \
	case 20: fn(__VA_ARGS__); fallthrough;				    \
	case 19: fn(__VA_ARGS__); fallthrough;				    \
	case 18: fn(__VA_ARGS__); fallthrough;				    \
	case 17: fn(__VA_ARGS__); fallthrough;				    \
	case 16: fn(__VA_ARGS__); fallthrough;				    \
	case 15: fn(__VA_ARGS__); fallthrough;				    \
	case 14: fn(__VA_ARGS__); fallthrough;				    \
	case 13: fn(__VA_ARGS__); fallthrough;				    \
	case 12: fn(__VA_ARGS__); fallthrough;				    \
	case 11: fn(__VA_ARGS__); fallthrough;				    \
	case 10: fn(__VA_ARGS__); fallthrough;				    \
	case 9: fn(__VA_ARGS__); fallthrough;				    \
	case 8: fn(__VA_ARGS__); fallthrough;				    \
	case 7: fn(__VA_ARGS__); fallthrough;				    \
	case 6: fn(__VA_ARGS__); fallthrough;				    \
	case 5: fn(__VA_ARGS__); fallthrough;				    \
	case 4: fn(__VA_ARGS__); fallthrough;				    \
	case 3: fn(__VA_ARGS__); fallthrough;				    \
	case 2: fn(__VA_ARGS__); fallthrough;				    \
	case 1: fn(__VA_ARGS__); fallthrough;				    \
	case 0:								    \
		break;							    \
	default:							    \
		/*							    \
		 * Either the iteration count is unreasonable or we need    \
		 * to add more cases above.				    \
		 */							    \
		BUILD_BUG_ON_MSG(1, "Unsupported unroll count: " #times);   \
		break;							    \
	}								    \
} while (0)

#endif /* __LINUX_UNROLL_H */
