/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RELOCS_H
#define RELOCS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <elf.h>
#include <byteswap.h>
#define USE_BSD
#include <endian.h>
#include <regex.h>
#include <tools/le_byteshift.h>

__attribute__((__format__(printf, 1, 2)))
void die(char *fmt, ...) __attribute__((noreturn));

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum symtype {
	S_ABS,
	S_REL,
	S_SEG,
	S_LIN,
	S_NSYMTYPES
};

struct process_params {
	FILE		*fp;
	unsigned int	use_real_mode:1;
	unsigned int	as_text:1;
	unsigned int	show_absolute_syms:1;
	unsigned int	show_absolute_relocs:1;
	unsigned int	show_reloc_info:1;
	unsigned int	text_pcrel:1;
};

void process_32(const struct process_params *params);
void process_64(const struct process_params *params);
#endif /* RELOCS_H */
