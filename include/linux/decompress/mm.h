/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/compr_mm.h
 *
 * Memory management for pre-boot and ramdisk uncompressors
 *
 * Authors: Alain Knaff <alain@knaff.lu>
 *
 */

#ifndef DECOMPR_MM_H
#define DECOMPR_MM_H

#ifdef STATIC

/* Code active when included from pre-boot environment: */

/*
 * Some architectures want to ensure there is no local data in their
 * pre-boot environment, so that data can arbitrarily relocated (via
 * GOT references).  This is achieved by defining STATIC_RW_DATA to
 * be null.
 */
#ifndef STATIC_RW_DATA
#define STATIC_RW_DATA static
#endif

/*
 * When an architecture needs to share the malloc()/free() implementation
 * between compilation units, it needs to have non-local visibility.
 */
#ifndef MALLOC_VISIBLE
#define MALLOC_VISIBLE static
#endif

#ifndef MALLOC_HIST_SIZE
#define MALLOC_HIST_SIZE	16
#endif
#ifndef MALLOC_ALIGN
#define MALLOC_ALIGN		4
#endif
#define MALLOC_MASK		(MALLOC_ALIGN - 1)

#if MALLOC_HIST_SIZE
STATIC_RW_DATA unsigned int malloc_hist[MALLOC_HIST_SIZE];
#endif
STATIC_RW_DATA typeof(free_mem_ptr) malloc_ptr;
STATIC_RW_DATA unsigned int malloc_count;

MALLOC_VISIBLE void *malloc(int size)
{
	void *p;

	if (size < 0)
		return NULL;

#if MALLOC_HIST_SIZE
	if (malloc_count == MALLOC_HIST_SIZE)
		return NULL;
#endif

	if (!malloc_ptr || !malloc_count)
		malloc_ptr =
			(typeof(malloc_ptr))
			(((unsigned long)free_mem_ptr + MALLOC_MASK) &
			 ~MALLOC_MASK);

	size = (size + MALLOC_MASK) & ~MALLOC_MASK;

	if (free_mem_end_ptr && malloc_ptr + size >= free_mem_end_ptr)
		return NULL;

	p = (void *)malloc_ptr;
	malloc_ptr += size;

#if MALLOC_HIST_SIZE
	malloc_hist[malloc_count] = size;
#endif
	malloc_count++;

	return p;
}

MALLOC_VISIBLE void free(void *where)
{
#if MALLOC_HIST_SIZE
	if (malloc_count &&
	    (void *)malloc_ptr - malloc_hist[malloc_count - 1] == where)
		malloc_ptr = (typeof(malloc_ptr))where;
#endif
	malloc_count--;
}

#define large_malloc(a) malloc(a)
#define large_free(a) free(a)

#define INIT

#else /* STATIC */

/* Code active when compiled standalone for use when loading ramdisk: */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/* Use defines rather than static inline in order to avoid spurious
 * warnings when not needed (indeed large_malloc / large_free are not
 * needed by inflate */

#define malloc(a) kmalloc(a, GFP_KERNEL)
#define free(a) kfree(a)

#define large_malloc(a) vmalloc(a)
#define large_free(a) vfree(a)

#define INIT __init
#define STATIC

#include <linux/init.h>

#endif /* STATIC */

#endif /* DECOMPR_MM_H */
