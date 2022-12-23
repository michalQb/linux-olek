// SPDX-License-Identifier: GPL-2.0-only
/*
 * Various library functions needed for the pre-boot code.
 *
 * Copyright (C) 2020-2022, Intel Corporation.
 */

/* bsearch() uses NOKPROBE_SYMBOL(), define a stub */
#define _LINUX_KPROBES_H
#define NOKPROBE_SYMBOL(fname)

#include "../../../../lib/sort.c"
#include "../../../../lib/bsearch.c"

#include "../../../../lib/extable.c"

#define ORC_COMPRESSED_BOOT
#include "../../lib/orc.c"

#if BITS_PER_LONG == 64
static unsigned long cached;
static bool valid;

static u32 kaslr_get_random_u32(void)
{
	if (!valid) {
		cached = kaslr_get_random_long(NULL);
		valid = true;

		return upper_32_bits(cached);
	} else {
		valid = false;

		return lower_32_bits(cached);
	}
}

#define get_random_u32		kaslr_get_random_u32
#else /* BITS_PER_LONG == 32 */
#define get_random_u32()	kaslr_get_random_long(NULL)
#endif /* BITS_PER_LONG == 32 */

/*
 * drivers/char/random.c:__get_random_u32_below(). Required by shuffle_array().
 */
u32 __get_random_u32_below(u32 ceil)
{
	u32 rand = get_random_u32();
	u64 mult;

	if (unlikely(!ceil))
		return rand;

	mult = (u64)ceil * rand;
	if (unlikely((u32)mult < ceil)) {
		u32 bound = -ceil % ceil;
		while (unlikely((u32)mult < bound))
			mult = (u64)ceil * get_random_u32();
	}
	return mult >> 32;
}
