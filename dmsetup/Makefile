#
# Copyright (C) 2001 Sistina Software (UK) Limited.
#
# This file is released under the LGPL.
#

srcdir = .
top_srcdir = ..
VPATH = .
SHELL = /bin/sh

CC = gcc
RANLIB = ranlib
SHELL = /bin/sh
INSTALL = /usr/bin/install -c
LN_S = ln -s

prefix = /usr
libdir = ${prefix}/lib
incdir = ${prefix}/include
kernelsrcdir = /scratch/alphalinux/linux

OWNER=root
GROUP=root

INCLUDES=-I${kernelsrcdir}/include
CFLAGS+=-Wall
#CFLAGS+=-O2
CFLAGS+=-g -fno-omit-frame-pointer
#CFLAGS+=-pg
#LD_FLAGS=-pg

SUFFIXES=
SUFFIXES=.c .o .so

%.o: %.c
	$(CC) -c $(INCLUDES) $(CFLAGS) $< -o $@

dmsetup: dmsetup.o libdevmapper.so
	$(CC) -o dmsetup dmsetup.o $(LD_FLAGS) -L../lib -ldevmapper

clean:
	$(RM) dmsetup

distclean: clean

.PHONY: install test clean distclean

