// SPDX-License-Identifier: GPL-2.0
#include "relocs.h"

void die(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

static void usage(void)
{
	die("relocs [--abs-syms|--abs-relocs|--reloc-info|--text|--realmode|--text-pcrel] vmlinux\n");
}

int main(int argc, char **argv)
{
	struct process_params params = { };
	unsigned char e_ident[EI_NIDENT];
	const char *fname = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (*arg == '-') {
			if (strcmp(arg, "--abs-syms") == 0) {
				params.show_absolute_syms = 1;
				continue;
			}
			if (strcmp(arg, "--abs-relocs") == 0) {
				params.show_absolute_relocs = 1;
				continue;
			}
			if (strcmp(arg, "--reloc-info") == 0) {
				params.show_reloc_info = 1;
				continue;
			}
			if (strcmp(arg, "--text") == 0) {
				params.as_text = 1;
				continue;
			}
			if (strcmp(arg, "--realmode") == 0) {
				params.use_real_mode = 1;
				continue;
			}
			if (strcmp(arg, "--text-pcrel") == 0) {
				params.text_pcrel = 1;
				continue;
			}
		}
		else if (!fname) {
			fname = arg;
			continue;
		}
		usage();
	}
	if (!fname) {
		usage();
	}
	params.fp = fopen(fname, "r");
	if (!params.fp) {
		die("Cannot open %s: %s\n", fname, strerror(errno));
	}
	if (fread(&e_ident, 1, EI_NIDENT, params.fp) != EI_NIDENT) {
		die("Cannot read %s: %s", fname, strerror(errno));
	}
	rewind(params.fp);
	if (e_ident[EI_CLASS] == ELFCLASS64)
		process_64(&params);
	else
		process_32(&params);
	fclose(params.fp);
	return 0;
}
