# the autoconf initilization.
AC_INIT(mpq-tools, 0.4.0, [Maik Broemme <mbroemme@plusserver.de>], [mpq-tools])

# detect the canonical host and target build environment.
AC_CANONICAL_SYSTEM

# initialize autoconf and automake system.
AM_INIT_AUTOMAKE([no-dependencies])
AC_CONFIG_HEADERS([config.h:config.h.in])

# notices.
AC_PREREQ(2.53)
AC_REVISION($Revision: 1.6 $)

# checking for programs.
AC_DISABLE_SHARED
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_CC
CCAS="$CC"
CCASFLAGS=""
AC_SUBST(CCAS)
AC_SUBST(CCASFLAGS)

# check for zlib library.
AC_CHECK_HEADER([zlib.h], [], [AC_MSG_ERROR([*** zlib.h is required, install zlib header files])])
AC_CHECK_LIB([z], [inflateEnd], [], [AC_MSG_ERROR([*** inflateEnd is required, install zlib library files])])

# creating files.
AC_OUTPUT([
Makefile
src/Makefile
libmpq/Makefile
])
