/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PARISC_EXTABLE_H
#define __PARISC_EXTABLE_H

/*
 * The exception table contains two values: the first is the relative offset to
 * the address of the instruction that is allowed to fault, and the second is
 * the relative offset to the address of the fixup routine. Since relative
 * addresses are used, 32bit values are sufficient even on 64bit kernel.
 */

#define ARCH_HAS_RELATIVE_EXTABLE
struct exception_table_entry {
	int insn;	/* relative address of insn that is allowed to fault. */
	int fixup;	/* relative address of fixup routine */
};

struct pt_regs;
int fixup_exception(struct pt_regs *regs);

#endif /* __PARISC_EXTABLE_H */
