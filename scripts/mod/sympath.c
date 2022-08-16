// SPDX-License-Identifier: GPL-2.0-only
/*
 * The utility finds %STT_FILE symbol in an object file and rewrites its name
 * in strtab to the provided string. If no symbol is found, it adds a new one.
 * Used to replace plain filenames with relative paths to use them for kallsyms
 * later on.
 */

#define _GNU_SOURCE 1 /* fstat64() */

#include <linux/const.h>
#include <errno.h>
#include <getopt.h>

#include "modpost.h"

#define Elf_Off		Elf_Addr
#define h(x)		TO_NATIVE(x)
#define t(x)		TO_NATIVE(x)

#define LOCAL_EXISTS	(1UL << 0)
#define LOCAL_FIXED	(1UL << 1)

static const struct option longopts[] = {
	{ "path",	required_argument,	NULL,	'p' },
	{ /* Sentinel */ },
};

struct state {
	void		*buf;
	void		*pos;

	Elf_Ehdr	*eh;
	Elf_Shdr	*sh;

	Elf_Shdr	*symh;
	Elf_Shdr	*strh;

	void		*symtab;
	void		*strtab;
};

struct opts {
	const char	*path;
	const char	*target;
};

static int parse_args(struct opts *opts, int argc, char *argv[])
{
	while (1) {
		int opt, idx;

		opt = getopt_long(argc, argv, "p:", longopts, &idx);
		if (opt < 0)
			break;

		switch (opt) {
		case 'p':
			opts->target = optarg;
			break;
		default:
			return -EINVAL;
		}
	}

	if (optind != argc - 1)
		return -EINVAL;

	opts->path = argv[optind];

	return 0;
}

static size_t move_code(struct state *st, void *start, Elf_Off off)
{
	Elf_Off addralign = sizeof(addralign);
	Elf_Ehdr *eh = st->eh;

	/*
	 * Find the largest alignment across the sections going after the
	 * target address and pick one that would work for all of them.
	 */
	for (Elf_Shdr *iter = st->sh,
	     *end = (void *)st->sh + h(eh->e_shnum) * h(eh->e_shentsize);
	     iter < end; iter = (void *)iter + h(eh->e_shentsize)) {
		if (h(iter->sh_offset) >= start - st->buf &&
		    h(iter->sh_addralign) > addralign)
			addralign = h(iter->sh_addralign);
	}

	off = __ALIGN_KERNEL(off, addralign);

	if ((void *)st->symh > start)
		st->symh = (void *)st->symh + off;

	if ((void *)st->strh > start)
		st->strh = (void *)st->strh + off;

	if (h(eh->e_shoff) > start - st->buf)
		eh->e_shoff = t(h(eh->e_shoff) + off);

	if (h(eh->e_phoff) > start - st->buf)
		eh->e_phoff = t(h(eh->e_phoff) + off);

	memmove(start + off, start, st->pos - start);
	memset(start, 0, off);

	st->pos += off;
	st->sh = st->buf + h(eh->e_shoff);

	for (Elf_Shdr *iter = st->sh,
	     *end = (void *)st->sh + h(eh->e_shnum) * h(eh->e_shentsize);
	     iter < end; iter = (void *)iter + h(eh->e_shentsize)) {
		if (h(iter->sh_offset) >= start - st->buf)
			iter->sh_offset = t(h(iter->sh_offset) + off);
	}

	st->symtab = st->buf + h(st->symh->sh_offset);
	st->strtab = st->buf + h(st->strh->sh_offset);

	return off;
}

static void fix_strtab(struct state *st, const char *target, Elf_Sym *sym)
{
	Elf_Off off = h(st->strh->sh_size);
	Elf_Off len = strlen(target) + 1;

	sym->st_name = t(off);

	move_code(st, st->strtab + off, len);
	st->strh->sh_size = t(h(st->strh->sh_size) + len);

	memcpy(st->strtab + off, target, len);
}

static void add_file_sym(struct state *st, const char *target)
{
	const Elf_Ehdr *eh = st->eh;
	Elf_Sym *pos = NULL;

	/*
	 * Num:    Value          Size Type    Bind   Vis      Ndx Name
	 *   0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
	 *   1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS usr/initramfs_data.S
	 *   2: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT    4 __irf_start
	 */
	for (Elf_Sym *iter = st->symtab,
	     *end = st->symtab + h(st->symh->sh_size);
	     iter < end; iter = (void *)iter + h(st->symh->sh_entsize)) {
		if (iter->st_shndx) {
			pos = iter;
			break;
		}
	}

	if (!pos)
		return;

	/* Move all the sections after symtab by the aligned entsize */
	move_code(st, st->symtab + h(st->symh->sh_size),
		  h(st->symh->sh_entsize));

	/* Move all the symtab symbols starting from @pos by the entsize */
	memmove((void *)pos + h(st->symh->sh_entsize), pos,
		h(st->symh->sh_size) - ((void *)pos - st->symtab));
	memset(pos, 0, h(st->symh->sh_entsize));

	st->symh->sh_size = t(h(st->symh->sh_size) + h(st->symh->sh_entsize));
	st->symh->sh_info = t(h(st->symh->sh_info) + 1);

	pos->st_info = t((STB_LOCAL << 4) | STT_FILE);
	pos->st_shndx = t(SHN_ABS);
	fix_strtab(st, target, pos);

	for (Elf_Shdr *iter = st->sh,
	     *end = (void *)st->sh + h(eh->e_shnum) * h(eh->e_shentsize);
	     iter < end; iter = (void *)iter + h(eh->e_shentsize)) {
		if (h(iter->sh_type) != SHT_RELA)
			continue;

		for (Elf_Rela *rela = st->buf + h(iter->sh_offset),
		     *rend = st->buf + h(iter->sh_offset) + h(iter->sh_size);
		     rela < rend; rela = (void *)rela + h(iter->sh_entsize)) {
			Elf_Off info = h(rela->r_info);
			__u32 shift = sizeof(info) * 4;
			__u32 idx = info >> shift;

			if (idx >= pos - (typeof(pos))st->symtab) {
				info &= (Elf_Off)~0ULL >> shift;
				info |= ((Elf_Off)idx + 1) << shift;

				rela->r_info = t(info);
			}
		}
	}
}

static int mangle_elf(const struct opts *opts)
{
	Elf_Sym *file_loc = NULL;
	struct stat64 stat = { };
	struct state st = { };
	Elf_Off readlen;
	Elf_Off maxoff;
	size_t state;
	ssize_t ret;
	int fd;

	fd = open(opts->path, O_RDWR);
	if (fd < 0)
		return -errno;

	ret = fstat64(fd, &stat);
	if (ret)
		return -errno;

	st.buf = malloc(stat.st_size + 32768);
	if (!st.buf) {
		ret = -ENOMEM;
		goto close;
	}

	readlen = sizeof(*st.eh);

	ret = read(fd, st.buf, readlen);
	if (ret != readlen) {
		ret = -ENODATA;
		goto free;
	}

	st.pos = st.buf + readlen;
	st.eh = st.buf;
	ret = -EINVAL;

	if (memcmp(st.eh->e_ident, ELFMAG, SELFMAG))
		goto free;

	if (st.eh->e_ident[EI_CLASS] != ELFCLASS64) {
		ret = 0;
		goto free;
	}

	if (h(st.eh->e_type) != ET_REL)
		goto free;

	if (!st.eh->e_shnum || !st.eh->e_shentsize)
		goto free;

	readlen = h(st.eh->e_shoff);
	readlen += h(st.eh->e_shnum) * h(st.eh->e_shentsize);
	readlen -= st.pos - st.buf;

	ret = read(fd, st.pos, readlen);
	if (ret != readlen) {
		ret = -ENODATA;
		goto free;
	}

	st.pos += readlen;
	st.sh = st.buf + h(st.eh->e_shoff);
	ret = -EINVAL;

	for (Elf_Shdr *iter = st.sh,
	     *end = (void *)st.sh + h(st.eh->e_shnum) * h(st.eh->e_shentsize);
	     iter < end; iter = (void *)iter + h(st.eh->e_shentsize)) {
		switch (h(iter->sh_type)) {
		case SHT_SYMTAB:
			if (st.symh)
				goto free;

			st.symh = iter;
			break;
		case SHT_STRTAB:
			if (!st.strh)
				st.strh = iter;

			break;
		}
	}

	if (!st.symh || !st.strh) {
		ret = 0;
		goto free;
	}

	maxoff = st.pos - st.buf;
	if (maxoff < h(st.symh->sh_offset) + h(st.symh->sh_size))
		maxoff = h(st.symh->sh_offset) + h(st.symh->sh_size);
	if (maxoff < h(st.strh->sh_offset) + h(st.strh->sh_size))
		maxoff = h(st.strh->sh_offset) + h(st.strh->sh_size);

	if (maxoff == st.pos - st.buf)
		goto look;

	readlen = maxoff - (st.pos - st.buf);

	ret = read(fd, st.pos, readlen);
	if (ret != readlen) {
		ret = -ENODATA;
		goto free;
	}

	st.pos += readlen;

look:
	st.symtab = st.buf + h(st.symh->sh_offset);
	st.strtab = st.buf + h(st.strh->sh_offset);
	ret = -EINVAL;

	for (Elf_Sym *iter = st.symtab, *end = st.symtab + h(st.symh->sh_size);
	     iter < end; iter = (void *)iter + h(st.symh->sh_entsize)) {
		if (ELF_ST_TYPE(h(iter->st_info)) == STT_FILE &&
		    ELF_ST_BIND(h(iter->st_info)) == STB_LOCAL) {
			if (file_loc)
				goto free;

			file_loc = iter;
		}
	}

	state = 0;
	if (file_loc)
		state |= LOCAL_EXISTS;
	if (file_loc && !strcmp(st.strtab + h(file_loc->st_name),
				opts->target))
		state |= LOCAL_FIXED;

	switch (state) {
	case 0:
		add_file_sym(&st, opts->target);
		break;
	case LOCAL_EXISTS:
		fix_strtab(&st, opts->target, file_loc);
		break;
	case LOCAL_EXISTS | LOCAL_FIXED:
		break;
	default:
		goto free;
	}

	readlen = stat.st_size - maxoff;

	ret = read(fd, st.pos, readlen);
	if (ret != readlen) {
		ret = -ENODATA;
		goto free;
	}

	st.pos += readlen;

	ret = pwrite(fd, st.buf, st.pos - st.buf, 0);
	if (ret != st.pos - st.buf) {
		ret = -EAGAIN;
		goto free;
	}

	ret = 0;

free:
	free(st.buf);
close:
	close(fd);

	return ret;
}

int main(int argc, char *argv[])
{
	struct opts opts = { };
	int ret;

	ret = parse_args(&opts, argc, argv);
	if (ret)
		return ret;

	if (!opts.path || !opts.target)
		return -EINVAL;

	ret = mangle_elf(&opts);
	if (ret)
		return ret;

	return 0;
}
