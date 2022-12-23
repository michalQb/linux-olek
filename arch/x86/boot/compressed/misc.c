// SPDX-License-Identifier: GPL-2.0
/*
 * misc.c
 *
 * This is a collection of several routines used to extract the kernel
 * which includes KASLR relocation, decompression, ELF parsing, and
 * relocation processing. Additionally included are the screen and serial
 * output functions and related debugging support functions.
 *
 * malloc by Hannu Savolainen 1993 and Matthias Urlichs 1994
 * puts by Nick Holloway 1993, better puts by Martin Mares 1995
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */

#include "misc.h"
#include "error.h"
#include "pgtable.h"
#include "../string.h"
#include "../voffset.h"
#include <asm/bootparam_utils.h>

/*
 * WARNING!!
 * This code is compiled with -fPIC and it is relocated dynamically at
 * run time, but no relocation processing is performed. This means that
 * it is not safe to place pointers in static structures.
 */

static void *free_mem_ptr;
static void *free_mem_end_ptr;

/* Macros used by the included decompressor code below. */
#define STATIC		static
/* Define an externally visible malloc()/free(). */
#define MALLOC_VISIBLE
#include <linux/decompress/mm.h>

/*
 * Provide definitions of memzero and memmove as some of the decompressors will
 * try to define their own functions if these are not defined as macros.
 */
#define memzero(s, n)	memset((s), 0, (n))
#ifndef memmove
#define memmove		memmove
/* Functions used by the included decompressor code below. */
void *memmove(void *dest, const void *src, size_t n);
#endif

/*
 * This is set up by the setup-routine at boot-time
 */
struct boot_params *boot_params;

struct port_io_ops pio_ops;

static char *vidmem;
static int vidport;

/* These might be accessed before .bss is cleared, so use .data instead. */
static int lines __section(".data");
static int cols __section(".data");

u32 __boot_layout_mode = BOOT_LAYOUT_STATIC;

#ifdef CONFIG_KERNEL_GZIP
#include "../../../../lib/decompress_inflate.c"
#endif

#ifdef CONFIG_KERNEL_BZIP2
#include "../../../../lib/decompress_bunzip2.c"
#endif

#ifdef CONFIG_KERNEL_LZMA
#include "../../../../lib/decompress_unlzma.c"
#endif

#ifdef CONFIG_KERNEL_XZ
#include "../../../../lib/decompress_unxz.c"
#endif

#ifdef CONFIG_KERNEL_LZO
#include "../../../../lib/decompress_unlzo.c"
#endif

#ifdef CONFIG_KERNEL_LZ4
#include "../../../../lib/decompress_unlz4.c"
#endif

#ifdef CONFIG_KERNEL_ZSTD
#include "../../../../lib/decompress_unzstd.c"
#endif
/*
 * NOTE: When adding a new decompressor, please update the analysis in
 * ../header.S.
 */

static void scroll(void)
{
	int i;

	memmove(vidmem, vidmem + cols * 2, (lines - 1) * cols * 2);
	for (i = (lines - 1) * cols * 2; i < lines * cols * 2; i += 2)
		vidmem[i] = ' ';
}

#define XMTRDY          0x20

#define TXR             0       /*  Transmit register (WRITE) */
#define LSR             5       /*  Line Status               */
static void serial_putchar(int ch)
{
	unsigned timeout = 0xffff;

	while ((inb(early_serial_base + LSR) & XMTRDY) == 0 && --timeout)
		cpu_relax();

	outb(ch, early_serial_base + TXR);
}

void __putstr(const char *s)
{
	int x, y, pos;
	char c;

	if (early_serial_base) {
		const char *str = s;
		while (*str) {
			if (*str == '\n')
				serial_putchar('\r');
			serial_putchar(*str++);
		}
	}

	if (lines == 0 || cols == 0)
		return;

	x = boot_params->screen_info.orig_x;
	y = boot_params->screen_info.orig_y;

	while ((c = *s++) != '\0') {
		if (c == '\n') {
			x = 0;
			if (++y >= lines) {
				scroll();
				y--;
			}
		} else {
			vidmem[(x + cols * y) * 2] = c;
			if (++x >= cols) {
				x = 0;
				if (++y >= lines) {
					scroll();
					y--;
				}
			}
		}
	}

	boot_params->screen_info.orig_x = x;
	boot_params->screen_info.orig_y = y;

	pos = (x + cols * y) * 2;	/* Update cursor position */
	outb(14, vidport);
	outb(0xff & (pos >> 9), vidport+1);
	outb(15, vidport);
	outb(0xff & (pos >> 1), vidport+1);
}

void __puthex(unsigned long value)
{
	char alpha[2] = "0";
	int bits;

	for (bits = sizeof(value) * 8 - 4; bits >= 0; bits -= 4) {
		unsigned long digit = (value >> bits) & 0xf;

		if (digit < 0xA)
			alpha[0] = '0' + digit;
		else
			alpha[0] = 'a' + (digit - 0xA);

		__putstr(alpha);
	}
}

void init_malloc(void *start, size_t len)
{
	if (unlikely(!len)) {
		error_putstr("Invalid allocation source\n");
		return;
	}

	if (malloc_count) {
		error_putstr("Overwriting non-empty allocation state\n");
		memset(malloc_hist, 0, sizeof(malloc_hist));
		malloc_count = 0;
	}

	free_mem_ptr = start;
	free_mem_end_ptr = free_mem_ptr + len;

	debug_putstr("Heap is initialized with 0x");
	debug_puthex(free_mem_end_ptr - free_mem_ptr);
	debug_putstr(" bytes\n");
}

static void init_boot_layout_mode(void)
{
	set_boot_layout_mode(BOOT_LAYOUT_STATIC);

	if (__BOOT_LAYOUT_MAX == BOOT_LAYOUT_STATIC)
		return;

	if (cmdline_find_option_bool("nokaslr")) {
		warn("KASLR disabled: 'nokaslr' on cmdline.");
		return;
	}

	set_boot_layout_mode(BOOT_LAYOUT_KASLR);

	if (__BOOT_LAYOUT_MAX == BOOT_LAYOUT_KASLR)
		return;

	if (cmdline_find_option_bool("nofgkaslr"))
		warn("FG-KASLR disabled: 'nofgkaslr' on cmdline.");
	else
		set_boot_layout_mode(BOOT_LAYOUT_FGKASLR);
}

#ifdef CONFIG_X86_NEED_RELOCS
#ifndef CONFIG_FG_KASLR
static void apply_relocs(const struct apply_relocs_params *params)
{
	unsigned long ptr;
	const int *reloc;
	long extended;

	/*
	 * Process relocations: 32 bit relocations first then 64 bit after.
	 * Three sets of binary relocations are added to the end of the kernel
	 * before compression. Each relocation table entry is the kernel
	 * address of the location which needs to be updated stored as a
	 * 32-bit value which is sign extended to 64 bits.
	 *
	 * Format is:
	 *
	 * kernel bits...
	 * 0 - zero terminator for 64 bit relocations
	 * 64 bit relocation repeated
	 * 0 - zero terminator for inverse 32 bit relocations
	 * 32 bit inverse relocation repeated
	 * 0 - zero terminator for 32 bit relocations
	 * 32 bit relocation repeated
	 *
	 * So we work backwards from the end of the decompressed image.
	 */
	for (reloc = params->reloc; *reloc; reloc--) {
		extended = *reloc + params->map;

		ptr = (unsigned long)extended;
		if (ptr < params->min_addr || ptr > params->max_addr)
			error("32-bit relocation outside of kernel!\n");

		*(u32 *)ptr += params->delta;
	}
#ifdef CONFIG_X86_64
	for (reloc--; *reloc; reloc--) {
		extended = *reloc + params->map;

		ptr = (unsigned long)extended;
		if (ptr < params->min_addr || ptr > params->max_addr)
			error("inverse 32-bit relocation outside of kernel!\n");

		*(s32 *)ptr -= params->delta;
	}
	for (reloc--; *reloc; reloc--) {
		extended = *reloc + params->map;

		ptr = (unsigned long)extended;
		if (ptr < params->min_addr || ptr > params->max_addr)
			error("64-bit relocation outside of kernel!\n");

		*(u64 *)ptr += params->delta;
	}
#endif /* CONFIG_X86_64 */
}
#endif /* !CONFIG_FG_KASLR */

static void handle_relocations(void *output, unsigned long output_len,
			       unsigned long virt_addr)
{
	struct apply_relocs_params params;

	params.min_addr = (unsigned long)output;
	params.max_addr = params.min_addr + (VO___bss_start - VO__text);

	/*
	 * Calculate the delta between where vmlinux was linked to load
	 * and where it was actually loaded.
	 */
	params.delta = params.min_addr - LOAD_PHYSICAL_ADDR;

	/*
	 * The kernel contains a table of relocation addresses. Those
	 * addresses have the final load address of the kernel in virtual
	 * memory. We are currently working in the self map. So we need to
	 * create an adjustment for kernel memory addresses to the self map.
	 * This will involve subtracting out the base address of the kernel.
	 */
	params.map = params.delta - __START_KERNEL_map;

	/*
	 * 32-bit always performs relocations. 64-bit relocations are only
	 * needed if KASLR has chosen a different starting address offset
	 * from __START_KERNEL_map.
	 */
	if (IS_ENABLED(CONFIG_X86_64))
		params.delta = virt_addr - LOAD_PHYSICAL_ADDR;

	/*
	 * It is possible to have delta be zero and still have enabled
	 * FG-KASLR. We need to perform relocations for it regardless
	 * of whether the base address has moved.
	 */
	if (get_boot_layout_mode() < BOOT_LAYOUT_FGKASLR && !params.delta) {
		debug_putstr("No relocation needed... ");
		return;
	}

	debug_putstr("Performing relocations... ");

	params.reloc = output + output_len - sizeof(*params.reloc);
	apply_relocs(&params);
}
#else /* !CONFIG_X86_NEED_RELOCS */
static inline void handle_relocations(void *output, unsigned long output_len,
				      unsigned long virt_addr)
{
}
#endif /* !CONFIG_X86_NEED_RELOCS */

#ifndef CONFIG_FG_KASLR
static void layout_image(void *output, Elf_Ehdr *ehdr, Elf_Phdr *phdrs)
{
	for (u32 i = 0; i < ehdr->e_phnum; i++) {
		const Elf_Phdr *phdr = &phdrs[i];
		void *dest;

		if (phdr->p_type != PT_LOAD)
			/* Ignore other PT_* */
			continue;

		if (IS_ENABLED(CONFIG_X86_64) &&
		    !IS_ALIGNED(phdr->p_align, MIN_KERNEL_ALIGN))
			error("Alignment of LOAD segment isn't multiple of 2MB");

#ifdef CONFIG_RELOCATABLE
		dest = output + phdr->p_paddr - LOAD_PHYSICAL_ADDR;
#else
		dest = (void *)phdr->p_paddr;
#endif
		memmove(dest, output + phdr->p_offset, phdr->p_filesz);
	}
}
#endif /* !CONFIG_FG_KASLR */

static Elf_Off parse_elf(void *output)
{
	Elf_Phdr *phdrs;
	Elf_Ehdr ehdr;
	size_t phsize;

	memcpy(&ehdr, output, sizeof(ehdr));
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
		error("Kernel is not a valid ELF file");

	debug_putstr("Parsing ELF... ");

	phsize = array_size(ehdr.e_phnum, sizeof(*phdrs));

	phdrs = malloc(phsize);
	if (!phdrs)
		error("Failed to allocate space for phdrs");

	memcpy(phdrs, output + ehdr.e_phoff, phsize);
	layout_image(output, &ehdr, phdrs);
	free(phdrs);

	return ehdr.e_entry - LOAD_PHYSICAL_ADDR;
}

/*
 * The compressed kernel image (ZO), has been moved so that its position
 * is against the end of the buffer used to hold the uncompressed kernel
 * image (VO) and the execution environment (.bss, .brk), which makes sure
 * there is room to do the in-place decompression. (See header.S for the
 * calculations.)
 *
 *                             |-----compressed kernel image------|
 *                             V                                  V
 * 0                       extract_offset                      +INIT_SIZE
 * |-----------|---------------|-------------------------|--------|
 *             |               |                         |        |
 *           VO__text      startup_32 of ZO          VO__end    ZO__end
 *             ^                                         ^
 *             |-------uncompressed kernel image---------|
 *
 */
asmlinkage __visible void *extract_kernel(void *rmode, memptr heap,
				  unsigned char *input_data,
				  unsigned long input_len,
				  unsigned char *output,
				  unsigned long output_len)
{
	const unsigned long kernel_total_size = VO__end - VO__text;
	unsigned long virt_addr = LOAD_PHYSICAL_ADDR;
	unsigned long needed_size;
	Elf_Off entry_offset;

	/* Retain x86 boot parameters pointer passed from startup_32/64. */
	boot_params = rmode;

	/* Clear flags intended for solely in-kernel use. */
	boot_params->hdr.loadflags &= ~KASLR_FLAG;

	sanitize_boot_params(boot_params);

	if (boot_params->screen_info.orig_video_mode == 7) {
		vidmem = (char *) 0xb0000;
		vidport = 0x3b4;
	} else {
		vidmem = (char *) 0xb8000;
		vidport = 0x3d4;
	}

	lines = boot_params->screen_info.orig_video_lines;
	cols = boot_params->screen_info.orig_video_cols;

	init_default_io_ops();

	/*
	 * Detect TDX guest environment.
	 *
	 * It has to be done before console_init() in order to use
	 * paravirtualized port I/O operations if needed.
	 */
	early_tdx_detect();

	console_init();

	/*
	 * Save RSDP address for later use. Have this after console_init()
	 * so that early debugging output from the RSDP parsing code can be
	 * collected.
	 */
	boot_params->acpi_rsdp_addr = get_rsdp_addr();

	debug_putstr("early console in extract_kernel\n");

	init_malloc((void *)heap, BOOT_HEAP_SIZE);

	/*
	 * The memory hole needed for the kernel is the larger of either
	 * the entire decompressed kernel plus relocation table, or the
	 * entire decompressed kernel plus .bss and .brk sections.
	 *
	 * On X86_64, the memory is mapped with PMD pages. Round the
	 * size up so that the full extent of PMD pages mapped is
	 * included in the check against the valid memory table
	 * entries. This ensures the full mapped area is usable RAM
	 * and doesn't include any reserved areas.
	 */
	needed_size = max(output_len, kernel_total_size);
#ifdef CONFIG_X86_64
	needed_size = ALIGN(needed_size, MIN_KERNEL_ALIGN);
#endif

	/* Report initial kernel position details. */
	debug_putaddr(input_data);
	debug_putaddr(input_len);
	debug_putaddr(output);
	debug_putaddr(output_len);
	debug_putaddr(kernel_total_size);
	debug_putaddr(needed_size);

#ifdef CONFIG_X86_64
	/* Report address of 32-bit trampoline */
	debug_putaddr(trampoline_32bit);
#endif

	init_boot_layout_mode();
	choose_random_location((unsigned long)input_data, input_len,
				(unsigned long *)&output,
				needed_size,
				&virt_addr);

	/* Validate memory location choices. */
	if ((unsigned long)output & (MIN_KERNEL_ALIGN - 1))
		error("Destination physical address inappropriately aligned");
	if (virt_addr & (MIN_KERNEL_ALIGN - 1))
		error("Destination virtual address inappropriately aligned");
#ifdef CONFIG_X86_64
	if (heap > 0x3fffffffffffUL)
		error("Destination address too large");
	if (virt_addr + max(output_len, kernel_total_size) > KERNEL_IMAGE_SIZE)
		error("Destination virtual address is beyond the kernel mapping area");
#else
	if (heap > ((-__PAGE_OFFSET-(128<<20)-1) & 0x7fffffff))
		error("Destination address too large");
#endif
#ifndef CONFIG_RELOCATABLE
	if (virt_addr != LOAD_PHYSICAL_ADDR)
		error("Destination virtual address changed when not relocatable");
#endif

	debug_putstr("\nDecompressing Linux... ");
	__decompress(input_data, input_len, NULL, NULL, output, output_len,
			NULL, error);
	entry_offset = parse_elf(output);
	handle_relocations(output, output_len, virt_addr);

	debug_putstr("done.\nBooting the kernel (entry_offset: 0x");
	debug_puthex(entry_offset);
	debug_putstr(").\n");

	/* Disable exception handling before booting the kernel */
	cleanup_exception_handling();

	return output + entry_offset;
}

void fortify_panic(const char *name)
{
	error("detected buffer overflow");
}
