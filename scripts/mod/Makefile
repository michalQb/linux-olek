# SPDX-License-Identifier: GPL-2.0
OBJECT_FILES_NON_STANDARD := y
CFLAGS_REMOVE_empty.o += $(CC_FLAGS_LTO)

hostprogs-always-y	+= modpost mk_elfconfig
always-y		+= empty.o

modpost-objs	:= modpost.o file2alias.o sumversion.o

devicetable-offsets-file := devicetable-offsets.h

$(obj)/$(devicetable-offsets-file): $(obj)/devicetable-offsets.s FORCE
	$(call filechk,offsets,__DEVICETABLE_OFFSETS_H__)

targets += $(devicetable-offsets-file) devicetable-offsets.s

# dependencies on generated files need to be listed explicitly

$(obj)/modpost.o $(obj)/file2alias.o $(obj)/sumversion.o: $(obj)/elfconfig.h
$(obj)/file2alias.o: $(obj)/$(devicetable-offsets-file)

quiet_cmd_elfconfig = MKELF   $@
      cmd_elfconfig = $(obj)/mk_elfconfig < $< > $@

$(obj)/elfconfig.h: $(obj)/empty.o $(obj)/mk_elfconfig FORCE
	$(call if_changed,elfconfig)

targets += elfconfig.h

# sympath: used to rewrite STT_FILE in object files from just filenames
# to paths relative to $(srctree)
hostprogs-always-$(CONFIG_KALLSYMS_PATHS)	+= sympath

$(obj)/sympath: $(obj)/elfconfig.h

# skip sympath for empty.o: makes no sense and creates a circular dependency
$(obj)/empty.o: skip-sympath := 1
