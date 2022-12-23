/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_RANDOM_H
#define _LINUX_RANDOM_H

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/once.h>

#include <uapi/linux/random.h>

struct notifier_block;

void add_device_randomness(const void *buf, size_t len);
void __init add_bootloader_randomness(const void *buf, size_t len);
void add_input_randomness(unsigned int type, unsigned int code,
			  unsigned int value) __latent_entropy;
void add_interrupt_randomness(int irq) __latent_entropy;
void add_hwgenerator_randomness(const void *buf, size_t len, size_t entropy);

#if defined(LATENT_ENTROPY_PLUGIN) && !defined(__CHECKER__)
static inline void add_latent_entropy(void)
{
	add_device_randomness((const void *)&latent_entropy, sizeof(latent_entropy));
}
#else
static inline void add_latent_entropy(void) { }
#endif

#if IS_ENABLED(CONFIG_VMGENID)
void add_vmfork_randomness(const void *unique_vm_id, size_t len);
int register_random_vmfork_notifier(struct notifier_block *nb);
int unregister_random_vmfork_notifier(struct notifier_block *nb);
#else
static inline int register_random_vmfork_notifier(struct notifier_block *nb) { return 0; }
static inline int unregister_random_vmfork_notifier(struct notifier_block *nb) { return 0; }
#endif

void get_random_bytes(void *buf, size_t len);
u8 get_random_u8(void);
u16 get_random_u16(void);
u32 get_random_u32(void);
u64 get_random_u64(void);
static inline unsigned long get_random_long(void)
{
#if BITS_PER_LONG == 64
	return get_random_u64();
#else
	return get_random_u32();
#endif
}

u32 __get_random_u32_below(u32 ceil);

/*
 * Returns a random integer in the interval [0, ceil), with uniform
 * distribution, suitable for all uses. Fastest when ceil is a constant, but
 * still fast for variable ceil as well.
 */
static inline u32 get_random_u32_below(u32 ceil)
{
	if (!__builtin_constant_p(ceil))
		return __get_random_u32_below(ceil);

	/*
	 * For the fast path, below, all operations on ceil are precomputed by
	 * the compiler, so this incurs no overhead for checking pow2, doing
	 * divisions, or branching based on integer size. The resultant
	 * algorithm does traditional reciprocal multiplication (typically
	 * optimized by the compiler into shifts and adds), rejecting samples
	 * whose lower half would indicate a range indivisible by ceil.
	 */
	BUILD_BUG_ON_MSG(!ceil, "get_random_u32_below() must take ceil > 0");
	if (ceil <= 1)
		return 0;
	for (;;) {
		if (ceil <= 1U << 8) {
			u32 mult = ceil * get_random_u8();
			if (likely(is_power_of_2(ceil) || (u8)mult >= (1U << 8) % ceil))
				return mult >> 8;
		} else if (ceil <= 1U << 16) {
			u32 mult = ceil * get_random_u16();
			if (likely(is_power_of_2(ceil) || (u16)mult >= (1U << 16) % ceil))
				return mult >> 16;
		} else {
			u64 mult = (u64)ceil * get_random_u32();
			if (likely(is_power_of_2(ceil) || (u32)mult >= -ceil % ceil))
				return mult >> 32;
		}
	}
}

/*
 * On 64-bit architectures, protect against non-terminated C string overflows
 * by zeroing out the first byte of the canary; this leaves 56 bits of entropy.
 */
#ifdef CONFIG_64BIT
# ifdef __LITTLE_ENDIAN
#  define CANARY_MASK 0xffffffffffffff00UL
# else /* big endian, 64 bits: */
#  define CANARY_MASK 0x00ffffffffffffffUL
# endif
#else /* 32 bits: */
# define CANARY_MASK 0xffffffffUL
#endif

static inline unsigned long get_random_canary(void)
{
	return get_random_long() & CANARY_MASK;
}

/**
 * __shuffle_do - use Fisher-Yates algorithm to shuffle an arbitrary object.
 * @_op: operation to perform on each iteration
 * @priv: pointer to the object, will be passed to @_op
 * @nents: the number of elements in the array
 * @...: prefixes for the local variables generated via __UNIQUE_ID()
 *
 * Performs one Fisher-Yates loop over the passed entity and calls @_op once
 * per each iterations. @_op takes 3 arguments: @priv, i and j, where i goes
 * during the loop from `nents - 1` to 1 and j is random [0, j] each time.
 * The most common operation to perform is to swap elements i and j in @priv.
 * Does compile-time check for the @nents type to use the more optimized
 * random function if suitable, which is most of cases. Consumes one
 * `get_random_typeof_nents()` per iteration.
 * Does nothing when @nents is not positive.
 */
#define __shuffle_do(_op, priv, nents, __priv, __nents, __i, __j) ({	     \
	typeof(*(priv)) *__priv = (priv);				     \
	typeof(nents) __nents = (nents);				     \
									     \
	if (unlikely(__nents <= 0))					     \
		/* Don't enter the loop */				     \
		__nents = 1;						     \
									     \
	for (typeof(__nents) __i = __nents - 1; __i > 0; __i--) {	     \
		typeof(__nents) __j;					     \
									     \
		if ((__builtin_constant_p(__nents) && __nents <= U32_MAX) || \
		    type_max(typeof(__nents)) <= U32_MAX)		     \
			__j = get_random_u32_below(__i + 1);		     \
		else							     \
			div64_u64_rem(get_random_u64(), __i + 1,	     \
				      (u64 *)&__j);			     \
									     \
		_op(__priv, __i, __j);					     \
	}								     \
})

#define _shuffle_swap_arr(arr, i, j)	swap(arr[i], arr[j])

/**
 * shuffle_array - use Fisher-Yates algorithm to shuffle an array.
 * @arr: pointer to the array
 * @nents: the number of elements in the array
 *
 * Convenient wrapper for __shuffle_do() to shuffle an array of arbitrary type.
 */
#define shuffle_array(arr, nents)					     \
	__shuffle_do(_shuffle_swap_arr, arr, nents, __UNIQUE_ID(priv_),	     \
		     __UNIQUE_ID(nents_), __UNIQUE_ID(i_), __UNIQUE_ID(j_))

void __init random_init_early(const char *command_line);
void __init random_init(void);
bool rng_is_initialized(void);
int wait_for_random_bytes(void);

/* Calls wait_for_random_bytes() and then calls get_random_bytes(buf, nbytes).
 * Returns the result of the call to wait_for_random_bytes. */
static inline int get_random_bytes_wait(void *buf, size_t nbytes)
{
	int ret = wait_for_random_bytes();
	get_random_bytes(buf, nbytes);
	return ret;
}

#define declare_get_random_var_wait(name, ret_type) \
	static inline int get_random_ ## name ## _wait(ret_type *out) { \
		int ret = wait_for_random_bytes(); \
		if (unlikely(ret)) \
			return ret; \
		*out = get_random_ ## name(); \
		return 0; \
	}
declare_get_random_var_wait(u8, u8)
declare_get_random_var_wait(u16, u16)
declare_get_random_var_wait(u32, u32)
declare_get_random_var_wait(u64, u32)
declare_get_random_var_wait(long, unsigned long)
#undef declare_get_random_var

/*
 * This is designed to be standalone for just prandom
 * users, but for now we include it from <linux/random.h>
 * for legacy reasons.
 */
#include <linux/prandom.h>

#include <asm/archrandom.h>

/*
 * Called from the boot CPU during startup; not valid to call once
 * secondary CPUs are up and preemption is possible.
 */
#ifndef arch_get_random_seed_longs_early
static inline size_t __init arch_get_random_seed_longs_early(unsigned long *v, size_t max_longs)
{
	WARN_ON(system_state != SYSTEM_BOOTING);
	return arch_get_random_seed_longs(v, max_longs);
}
#endif

#ifndef arch_get_random_longs_early
static inline bool __init arch_get_random_longs_early(unsigned long *v, size_t max_longs)
{
	WARN_ON(system_state != SYSTEM_BOOTING);
	return arch_get_random_longs(v, max_longs);
}
#endif

#ifdef CONFIG_SMP
int random_prepare_cpu(unsigned int cpu);
int random_online_cpu(unsigned int cpu);
#endif

#ifndef MODULE
extern const struct file_operations random_fops, urandom_fops;
#endif

#endif /* _LINUX_RANDOM_H */
