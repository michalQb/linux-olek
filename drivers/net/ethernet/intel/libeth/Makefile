# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024 Intel Corporation

obj-$(CONFIG_LIBETH)		+= libeth.o

libeth-objs			+= netdev.o
libeth-objs			+= rx.o
libeth-objs			+= stats.o
libeth-objs			+= tx.o

obj-$(CONFIG_LIBETH_XDP)	+= libeth_xdp.o

libeth_xdp-objs			+= xdp.o
libeth_xdp-objs			+= xsk.o
