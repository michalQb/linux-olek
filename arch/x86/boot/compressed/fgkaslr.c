// SPDX-License-Identifier: GPL-2.0-only
/*
 * Routines needed to reorder kernel text at early boot time.
 *
 * Copyright (C) 2020-2022, Intel Corporation.
 */

#include <asm/text-patching.h>
#include <linux/bsearch.h>
#include <linux/extable.h>
#include <linux/sizes.h>
#include <linux/sort.h>
#include <linux/string.h>
#include "misc.h"
#include <linux/random.h>

#include "error.h"
#include "../voffset.h"
#include "../../include/asm/extable.h"
#include "../../include/asm/orc_types.h"

#ifndef ARCH_SHF_SMALL
#define ARCH_SHF_SMALL	0
#endif

#define sym_addr(sym)	VO_##sym

/*
 * "Special" text (noinstr, entry, sched, thunks etc.) can currently be
 * treated only as a single element per its start/stop symbols when
 * randomizing. Must be kept in sync with `kernel/vmlinux.lds.S` and
 * fully cover the [noinstr, FG_KASLR_TEXT) range.
 */
static const struct special_entry {
	Elf_Addr	start;
	Elf_Addr	stop;
	size_t		align;
} specials[] = {
#define SPECIAL(s, e, ...) {			\
	.start		= sym_addr(s),		\
	.stop		= sym_addr(e),		\
	.align		= (__VA_ARGS__ + 0),	\
}
	/* Doesn't get randomized, used to differentiate _[s]text */
	SPECIAL(_text, _text + CONFIG_FUNCTION_ALIGNMENT - 1),

	SPECIAL(__noinstr_text_start, __noinstr_text_end),
	SPECIAL(__ref_text_start, __ref_text_end),
	SPECIAL(__sched_text_start, __sched_text_end),
	SPECIAL(__cpuidle_text_start, __cpuidle_text_end),
	SPECIAL(__lock_text_start, __lock_text_end),
	SPECIAL(__kprobes_text_start, __kprobes_text_end),
	SPECIAL(__softirqentry_text_start, __softirqentry_text_end),
	SPECIAL(__indirect_thunk_start, __indirect_thunk_end),
	SPECIAL(__static_call_text_start, __static_call_text_end),
	SPECIAL(__entry_text_start, __entry_text_end,
		PMD_SIZE * IS_ENABLED(CONFIG_X86_64)),

	/* Doesn't get randomized, used to adjust _etext address */
	SPECIAL(_etext, _etext + CONFIG_FUNCTION_ALIGNMENT - 1),
#undef SPECIAL
};

static bool enabled;

/* Array of randomizable entries, incl. "specials" */
static struct rand_entry {
	u32		rel;	/* abs_addr - sym_addr(_text) */
	u32		size;
	union {
		u32	align;
		s32	offset;	/* Offset diff between vmlinux & randomized */
	};
} *randents;
/* Total number of entries to randomize */
static u32 randents_num;

/* Those match kernel symbols with the same name */
static int *kallsyms_offsets;
static unsigned long kallsyms_relative_base;
/* Offsets of each symbol name in @kallsyms_names */
static u32 *kallsyms_names_offs;

/* Used in cmp_section_addr() to distinguish ORC addresses */
static bool cur_sect_addr_orc;

/* Fortified, handles array_size() return value, prints fancy messages */
static void __alloc_size(1) *malloc_verbose(size_t len, const char *reason)
{
	void *addr;

	if (unlikely(!len))
		return NULL;

	if (unlikely(len == SIZE_MAX)) {
		error_putstr("Array size overflow");
		goto put_reason;
	}

	addr = malloc(len);
	if (!addr)
		goto print_err;

	debug_putstr("Allocated 0x");
	debug_puthex(len);
	debug_putstr(" bytes");

	if (reason) {
		debug_putstr(" for ");
		debug_putstr(reason);
	}

	debug_putstr("\n");

	return addr;

print_err:
	error_putstr("Failed to allocate 0x");
	error_puthex(len);
	error_putstr(" bytes");

put_reason:
	if (reason) {
		error_putstr(" for ");
		error_putstr(reason);
	}

	error_putstr("\n");

	return NULL;
}

static __always_inline void __alloc_size(1, 2) *
malloc_array(size_t n, size_t entsz, const char *reason)
{
	return malloc_verbose(array_size(n, entsz), reason);
}

/* "Gracefully" downgrade FG-KASLR to KASLR if something goes wrong */
static void downgrade_boot_layout_mode(void)
{
	warn("FG-KASLR disabled: no enough heap space");

	set_boot_layout_mode(BOOT_LAYOUT_FGKASLR - 1);
	enabled = false;
}

static bool is_text(long addr)
{
	return (addr >= sym_addr(_text) && addr < sym_addr(_etext)) ||
	       (addr >= sym_addr(_sinittext) && addr < sym_addr(_einittext)) ||
	       (addr >= sym_addr(__altinstr_replacement) &&
		addr < sym_addr(__altinstr_replacement_end));
}

static bool is_orc_unwind(long addr)
{
	return addr >= sym_addr(__start_orc_unwind_ip) &&
	       addr < sym_addr(__stop_orc_unwind_ip);
}

static bool is_percpu(long pc, long offset)
{
	long addr = pc + offset + 4;

	return addr >= sym_addr(__per_cpu_start) &&
	       addr < sym_addr(__per_cpu_end);
}

static Elf_Addr entry_site_addr(const struct rand_entry *entry)
{
	return sym_addr(_text) + entry->rel;
}

/*
 * Here @a is the address of the symbol which is being searched and @b is
 * the pointer to either current entry site or index of the current section.
 */
static int cmp_section_addr(const void *a, const void *b)
{
	const struct rand_entry *entry = b;
	Elf_Addr start = entry_site_addr(entry);
	Elf_Addr end = start + entry->size;
	long address = (long)a;

	/* ORC relocations can be one past the end of the section */
	if (cur_sect_addr_orc)
		end++;

	return address < start ? -1 : address < end ? 0 : 1;
}

/*
 * Discover if the address is in a randomized entry and if so, return
 * the saved offset.
 */
static Elf_Off get_offset(long address)
{
	const struct rand_entry *res;

	if (!enabled)
		return 0;

	res = bsearch((const void *)address, randents, randents_num,
		      sizeof(*randents), cmp_section_addr);

	return res ? res->offset : 0;
}

static Elf_Off get_relative_offset(long pc, long value, Elf_Off sh_off)
{
	if (!enabled)
		return 0;

	/*
	 * ORC IP addresses are sorted at build time after relocs have been
	 * applied, making the relocs no longer valid. Skip any relocs for
	 * the orc_unwind_ip table. These will be updated separately.
	 */
	if (is_orc_unwind(pc))
		return 0;

	/*
	 * Calculate the address that this offset would call and adjust if
	 * it is in a section that was randomized.
	 * If the target is text, the offset being updated is relative to the
	 * next instruction and we need to add 32 bits to the PC.
	 * If the PC that this offset was calculated for was in a section that
	 * has been randomized, the value needs to be adjusted by the same
	 * amount as the randomized section was adjusted from it's original
	 * location.
	 */
	return get_offset(pc + is_text(pc) * 4 + value) - sh_off;
}

static unsigned long kallsym_addr(int offset)
{
	return offset < 0 ? kallsyms_relative_base - offset - 1 : offset;
}

static u32 kallsym_len(const u8 *pos)
{
	u32 len = *pos;

	/* ULEB128 */
	if (len & BIT(7))
		return 2 + ((pos[1] << 7) | (len & ~BIT(7)));
	else
		return 1 + len;
}

static int kallsyms_cmp(const void *a, const void *b)
{
	return kallsym_addr(*(int *)a) - kallsym_addr(*(int *)b);
}

static void kallsyms_swp(void *a, void *b, int size)
{
	u32 i, j;

	/* @i and @j are indexes in the arrays */
	i = (const int *)a - kallsyms_offsets;
	j = (const int *)b - kallsyms_offsets;

	swap(kallsyms_offsets[i], kallsyms_offsets[j]);
	swap(kallsyms_names_offs[i], kallsyms_names_offs[j]);
}

static void kallsyms_update_save_names_offs(const u8 *names, u32 num_syms)
{
	kallsyms_names_offs = malloc_array(num_syms,
					   sizeof(*kallsyms_names_offs),
					   "kallsyms offset table");
	if (!kallsyms_names_offs)
		error("Out of memory");

	for (u32 name_off = 0, i = 0; i < num_syms; i++) {
		int *offset = &kallsyms_offsets[i];
		Elf_Off sh_off;

		sh_off = get_offset(kallsym_addr(*offset));
		*offset += *offset < 0 ? -sh_off : sh_off;

		kallsyms_names_offs[i] = name_off;
		name_off += kallsym_len(&names[name_off]);
	}
}

static void kallsyms_rewrite_names(u8 *names, u32 *markers, u32 num_syms)
{
	size_t names_len;
	u32 offset = 0;
	u8 *new_names;

	names_len = sym_addr(kallsyms_markers) - sym_addr(kallsyms_names);

	new_names = malloc_verbose(names_len, "kallsyms string table");
	if (!new_names)
		error("Out of memory");

	for (u32 mi = 0, i = 0; i < num_syms; i++) {
		const u8 *old_sym = names + kallsyms_names_offs[i];
		u32 sym_len = kallsym_len(old_sym);

		if (!(i % 256))
			markers[mi++] = offset;

		memcpy(new_names + offset, old_sym, sym_len);
		offset += sym_len;
	}

	memcpy(names, new_names, offset);

	free(new_names);
	free(kallsyms_names_offs);
}

static void update_kallsyms(unsigned long map)
{
	unsigned long rel;
	u32 *markers;
	u32 num_syms;
	u8 *names;

	kallsyms_offsets = (int *)(sym_addr(kallsyms_offsets) + map);
	rel = *(const unsigned long *)(sym_addr(kallsyms_relative_base) + map);
	kallsyms_relative_base = rel;
	num_syms = *(const u32 *)(sym_addr(kallsyms_num_syms) + map);
	names = (u8 *)(sym_addr(kallsyms_names) + map);
	markers = (u32 *)(sym_addr(kallsyms_markers) + map);

	debug_putstr("\nUpdating kallsyms...\n");
	kallsyms_update_save_names_offs(names, num_syms);

	debug_putstr("Re-sorting kallsyms...\n");
	sort(kallsyms_offsets, num_syms, sizeof(*kallsyms_offsets),
	     kallsyms_cmp, kallsyms_swp);
	kallsyms_rewrite_names(names, markers, num_syms);
}

static void update_ex_table(unsigned long map)
{
	struct exception_table_entry *ex_table;
	u32 nents;

	ex_table = (typeof(ex_table))(sym_addr(__start___ex_table) + map);
	nents = sym_addr(__stop___ex_table) - sym_addr(__start___ex_table);
	nents /= sizeof(*ex_table);

	debug_putstr("Updating exception table...\n");

	for (u32 i = 0; i < nents; i++) {
		struct exception_table_entry *x = &ex_table[i];

		x->fixup += get_offset(ex_fixup_addr(x) - map);
		x->insn += get_offset(ex_to_insn(x) - map);
	}

	debug_putstr("Re-sorting exception table...\n");
	sort_extable(ex_table, ex_table + nents);
}

static void update_orc_table(unsigned long map)
{
	struct orc_entry *orc_table;
	int *ip_table;
	u32 n;

	orc_table = (struct orc_entry *)(sym_addr(__start_orc_unwind) + map);
	ip_table = (int *)(sym_addr(__start_orc_unwind_ip) + map);
	n = sym_addr(__stop_orc_unwind_ip) - sym_addr(__start_orc_unwind_ip);
	n /= sizeof(*ip_table);

	debug_putstr("Updating ORC tables...\n");
	cur_sect_addr_orc = true;

	for (u32 i = 0; i < n; i++)
		ip_table[i] += get_offset(orc_ip(&ip_table[i]) - map);

	cur_sect_addr_orc = false;

	debug_putstr("Re-sorting ORC tables... ");
	orc_sort(ip_table, orc_table, n);
}

static void __apply_relocs(const struct apply_relocs_params *params)
{
	unsigned long addr;
	const int *reloc;
	long extended;

	for (reloc = params->reloc; *reloc; reloc--) {
		/*
		 * If using FG-KASLR, the address of the relocation might've
		 * been moved. Check it to see if it needs adjusting.
		 */
		extended = *reloc + get_offset(*reloc) + params->map;

		addr = (unsigned long)extended;
		if (addr < params->min_addr || addr > params->max_addr)
			error("32-bit relocation outside of kernel!");

		/*
		 * If using FG-KASLR, the value of the relocation might need to
		 * be changed because it referred to an address that has moved.
		 */
		*(u32 *)addr += get_offset(*(s32 *)addr) + params->delta;
	}

#ifdef CONFIG_X86_64
	for (reloc--; *reloc; reloc--) {
		Elf_Off off;
		long pc;

		pc = *reloc;
		off = get_offset(pc);
		extended = pc + off + params->map;

		addr = (unsigned long)extended;
		if (addr < params->min_addr || addr > params->max_addr)
			error("inverse 32-bit relocation outside of kernel!");

		/*
		 * If using FG-KASLR, these relocs will contain relative
		 * offsets which might need to be changed because it referred
		 * to an address that has moved.
		 * Only percpu symbols need to have their values adjusted for
		 * base address KASLR since relative offsets within the text
		 * are ok wrt each other.
		 */
		*(s32 *)addr += get_relative_offset(pc, *(s32 *)addr, off) -
				is_percpu(pc, *(s32 *)addr) * params->delta;
	}

	for (reloc--; *reloc; reloc--) {
		extended = *reloc + get_offset(*reloc) + params->map;

		addr = (unsigned long)extended;
		if (addr < params->min_addr || addr > params->max_addr)
			error("64-bit relocation outside of kernel!");

		*(u64 *)addr += get_offset(*(s64 *)addr) + params->delta;
	}
#endif /* CONFIG_X86_64 */
}

void apply_relocs(const struct apply_relocs_params *params)
{
	if (enabled)
		update_kallsyms(params->map);

	__apply_relocs(params);

	if (!enabled)
		return;

	update_ex_table(params->map);
	update_orc_table(params->map);

	free(randents);
}

static void randomize_text(void *dest, const void *source,
			   const Elf_Phdr *phdr)
{
	Elf_Addr cur_addr = sym_addr(_text);
	size_t text_len, copied = 0;
	u32 *shuffled;
	void *text;

	debug_putstr("Shuffling 0x");
	debug_puthex(randents_num);
	debug_putstr(" entries...\n");

	text_len = sym_addr(_etext) - sym_addr(_text);

	text = malloc_verbose(text_len, "shuffled kernel text");
	if (!text)
		goto out_memmove;

	shuffled = malloc_array(randents_num, sizeof(*shuffled),
				"shuffled entries index table");
	if (!shuffled)
		goto out_free_text;

	for (u32 i = 0; i < randents_num; i++)
		shuffled[i] = i;

	/* Exclude _[s]text and _etext */
	shuffle_array(&shuffled[1], randents_num - 2);

	for (u32 i = 0; i < randents_num; i++) {
		struct rand_entry *entry = &randents[shuffled[i]];
		Elf_Addr addr = entry_site_addr(entry);
		u32 len, align = entry->align;
		const void *src;

		/* Gaps between functions must be padded with int3 */
		len = ALIGN(cur_addr, align) - cur_addr;
		memset(text + copied, INT3_INSN_OPCODE, len);
		copied += len;
		cur_addr += len;

		src = source + addr - sym_addr(_text);
		/* Will be used later for adjusting relocs */
		entry->offset = cur_addr - addr;

		len = entry->size;
		memcpy(text + copied, src, len);
		copied += len;
		cur_addr += len;

		/* Tail padding */
		len = ALIGN(cur_addr, align) - cur_addr;
		memset(text + copied, INT3_INSN_OPCODE, len);
		copied += len;
		cur_addr += len;
	}

	if (likely(copied <= text_len)) {
		/*
		 * Starting from this memcpy(), no "soft" rollback is possible
		 * as it overwrites the source text.
		 */
		memcpy(dest, text, copied);
		memset(dest + copied, INT3_INSN_OPCODE, text_len - copied);
		copied = text_len;
	} else {
		error_putstr("_etext overrun\n");
		copied = 0;
	}

	free(shuffled);
out_free_text:
	free(text);

out_memmove:
	if (!copied) {
		downgrade_boot_layout_mode();
		free(randents);
	}

	/*
	 * Move the remainder of the segment. If one of the allocations above
	 * failed or overrun happened, this will act just like regular KASLR.
	 */
	memmove(dest + copied, source + copied, phdr->p_filesz - copied);
}

static int randents_cmp(const void *a, const void *b)
{
	const struct rand_entry *ea = a;
	const struct rand_entry *eb = b;

	return entry_site_addr(ea) - entry_site_addr(eb);
}

static void randents_swp(void *a, void *b, int size)
{
	u32 i, j;

	/* @i and @j are indexes in the array */
	i = (const struct rand_entry *)a - randents;
	j = (const struct rand_entry *)b - randents;

	swap(randents[i], randents[j]);
}

static void add_rand_entry(Elf_Addr addr, u32 size, u32 align)
{
	struct rand_entry *entry = &randents[randents_num++];

	entry->rel = addr - sym_addr(_text);
	entry->size = size;
	entry->align = align ? : CONFIG_FUNCTION_ALIGNMENT;
}

static bool alloc_randents(u32 num)
{
	randents = malloc_array(num + ARRAY_SIZE(specials), sizeof(*randents),
				"sorted entry sites table");
	if (!randents)
		return false;

	for (u32 last = 0, i = 0; i < ARRAY_SIZE(specials); i++) {
		const struct special_entry *sp = &specials[i];
		u32 size = sp->stop - sp->start;

		if (!size)
			continue;

		/*
		 * When specials[i - 1].stop == specials[i].start, there is no
		 * way to distinguish symbols `__i_minus_1_end` and
		 * `__i_start`. The only thing can be done is merging these two
		 * blocks, so that the mentioned start and stop will have the
		 * same offset.
		 */
		if (randents_num && specials[last].stop == sp->start) {
			struct rand_entry *entry = &randents[randents_num - 1];

			entry->align = max_t(u32, entry->align, sp->align);
			entry->size += size;
		} else {
			/* `size + 1` to cover *_text_end symbols */
			add_rand_entry(sp->start, size + 1, sp->align);
			last = i;
		}
	}

	return true;
}

#ifdef CONFIG_FG_KASLR_OBJTOOL

/* .entry_sites are located in a separate PHDR (init) */
static const Elf_Phdr *find_init_phdr(const Elf_Ehdr *ehdr,
				      const Elf_Phdr *phdrs)
{
	for (u32 i = 0; i < ehdr->e_phnum; i++) {
		const Elf_Phdr *phdr = &phdrs[i];

		if (phdr->p_type == PT_LOAD &&
		    phdr->p_vaddr <= sym_addr(__start_entry_sites) &&
		    phdr->p_vaddr + phdr->p_filesz >=
		    sym_addr(__stop_entry_site_aux))
			return phdr;
	}

	return NULL;
}

static void collect_randents_impl(const void *output, const Elf_Ehdr *ehdr,
				  const Elf_Phdr *phdrs)
{
	const s32 *entry_sites;
	const Elf_Phdr *init;
	/* .entry_site_aux entries format */
	const struct {
		u32	size;
		u32	align;
	} *entry_aux;
	u32 snum;

	init = find_init_phdr(ehdr, phdrs);
	if (unlikely(!init))
		return;

	entry_sites = output + init->p_offset +
		      sym_addr(__start_entry_sites) - init->p_vaddr;
	entry_aux = output + init->p_offset +
		    sym_addr(__start_entry_site_aux) - init->p_vaddr;

	snum = sym_addr(__stop_entry_sites) - sym_addr(__start_entry_sites);
	snum /= sizeof(*entry_sites);
	BUILD_BUG_ON(!snum);

	if (!alloc_randents(snum))
		return;

	for (u32 i = 0; i < snum; i++) {
		u32 size = entry_aux[i].size;
		bool special = false;
		Elf_Addr addr;

		if (unlikely(!size))
			continue;

		/* abs_addr = entry + *entry */
		addr = sym_addr(__start_entry_sites) +
		       i * sizeof(*entry_sites) + entry_sites[i];

		for (u32 j = 0; j < ARRAY_SIZE(specials); j++) {
			if (addr >= specials[j].start &&
			    addr + size <= specials[j].stop) {
				special = true;
				break;
			}
		}

		if (!special)
			add_rand_entry(addr, size, entry_aux[i].align);
	}
}

static size_t ext_heap_sz_impl(size_t base)
{
	u32 max_nents;
	size_t add;

	add = sym_addr(__stop_entry_sites) - sym_addr(__start_entry_sites);
	max_nents = add / sizeof(s32);
	/* From alloc_randents() */
	max_nents += ARRAY_SIZE(specials);

	add = max_nents * sizeof(*randents);
	/* From randomize_text() */
	add += max_nents * sizeof(u32);

	return base + add;
}

#else /* !CONFIG_FG_KASLR_OBJTOOL */

static void collect_randents_impl(const void *output, const Elf_Ehdr *ehdr,
				  const Elf_Phdr *phdrs)
{
	const Elf_Shdr *sechdrs = output + ehdr->e_shoff;
	const Elf_Shdr *shdr = &sechdrs[SHN_UNDEF];
	const char *secstrings;
	u32 shnum, si;

	shnum = ehdr->e_shnum != SHN_UNDEF ? ehdr->e_shnum : shdr->sh_size;
	si = ehdr->e_shstrndx != SHN_XINDEX ? ehdr->e_shstrndx : shdr->sh_link;
	secstrings = output + sechdrs[si].sh_offset;

	if (!alloc_randents(shnum))
		return;

	for (u32 i = 0; i < shnum; i++) {
		shdr = &sechdrs[i];

		if ((shdr->sh_flags & SHF_ALLOC) &&
		    (shdr->sh_flags & SHF_EXECINSTR) &&
		    !(shdr->sh_flags & ARCH_SHF_SMALL) &&
		    strstarts(secstrings + shdr->sh_name, ".text.") &&
		    likely(shdr->sh_size))
			add_rand_entry(shdr->sh_addr, shdr->sh_size,
				       shdr->sh_addralign);
	}
}

/* shnum is not known in advance, just add some % on top to be sure */
#define ext_heap_sz_impl(base)	((base) + ((base) >> 4))

#endif /* !CONFIG_FG_KASLR_OBJTOOL */

static void collect_entries(const void *output, const Elf_Ehdr *ehdr,
			    const Elf_Phdr *phdrs)
{
	debug_putstr("\nLooking for text entries...\n");
	collect_randents_impl(output, ehdr, phdrs);

	/* _[s]text + _etext + minimum 2 elements to randomize */
	if (unlikely(randents_num < 4))
		downgrade_boot_layout_mode();
	else
		sort(randents, randents_num, sizeof(*randents), randents_cmp,
		     randents_swp);
}

void layout_image(void *output, Elf_Ehdr *ehdr, Elf_Phdr *phdrs)
{
	Elf_Addr entry;

	if (enabled)
		collect_entries(output, ehdr, phdrs);

	for (u32 i = 0; i < ehdr->e_phnum; i++) {
		const Elf_Phdr *phdr = &phdrs[i];
		const void *src;
		void *dest;

		if (phdr->p_type != PT_LOAD)
			continue;

		if (IS_ENABLED(CONFIG_X86_64) &&
		    !IS_ALIGNED(phdr->p_align, MIN_KERNEL_ALIGN))
			error("Alignment of LOAD segment isn't multiple of 2MB");

		dest = output + phdr->p_paddr - LOAD_PHYSICAL_ADDR;
		src = output + phdr->p_offset;

		if (phdr->p_vaddr == sym_addr(_text) && enabled)
			randomize_text(dest, src, phdr);
		else
			memmove(dest, src, phdr->p_filesz);
	}

	/* Adjust the entry point if it's in a randomized section */
	entry = sym_addr(_text) + ehdr->e_entry - LOAD_PHYSICAL_ADDR;
	ehdr->e_entry += get_offset(entry);

	debug_putaddr(0xffffffff81ebe000 + get_offset(0xffffffff81ebe000));
}

/*
 * FG-KASLR needs additional heap space. The peak usage is _etext - _text +
 * @randents and @shuffled during randomize_text(). The rest, such as kallsyms
 * names, happen after the text copy is freed and fit into that slot.
 * The function adds the total value to the required output size, so that the
 * KASLR function searching for a free slot in the memory will provide us with
 * it. Then, if it was found, @free_mem_ptr{,_end} get initialized with it to
 * make that space available via malloc().
 */
void choose_random_location(unsigned long input, unsigned long input_size,
			    unsigned long *output, unsigned long output_size,
			    unsigned long *virt_addr)
{
	unsigned long orig_output = *output;
	size_t ext_heap_sz;

	enabled = get_boot_layout_mode() >= BOOT_LAYOUT_FGKASLR;
	if (!enabled) {
		__choose_random_location(input, input_size, output,
					 output_size, virt_addr);
		return;
	}

	ext_heap_sz = sym_addr(_etext) - sym_addr(_text);
	ext_heap_sz += BOOT_HEAP_SIZE;
	ext_heap_sz = ext_heap_sz_impl(ext_heap_sz);

	output_size = ALIGN(output_size, PAGE_SIZE);
	ext_heap_sz = ALIGN(ext_heap_sz, PAGE_SIZE);
	if (IS_ENABLED(CONFIG_X86_64))
		ext_heap_sz = ALIGN(ext_heap_sz, MIN_KERNEL_ALIGN);

	__choose_random_location(input, input_size, output,
				 output_size + ext_heap_sz,
				 virt_addr);

	if (*output == orig_output)
		/* No free slot was found and no extra heap is available */
		downgrade_boot_layout_mode();
	else
		init_malloc((void *)*output + output_size, ext_heap_sz);
}
