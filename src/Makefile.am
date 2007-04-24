# The input Makefile for the main mpq-tools

# Why does automake build libtool files for binaries if the
# source tree includes a shared library?

CFLAGS = -DLIBMPQ_LISTDB_PATH=\"$(datadir)/libmpq/db\" @CFLAGS@

bin_PROGRAMS			= mpq-extract mpq-info

mpq_extract_SOURCES		= mpq-extract.c
mpq_extract_LDADD		= ../libmpq/libmpq.la
mpq_extract_DEPENDENCIES	= ../libmpq/libmpq.la

mpq_info_SOURCES		= mpq-info.c
mpq_info_LDADD			= ../libmpq/libmpq.la
mpq_info_DEPENDENCIES		= ../libmpq/libmpq.la
