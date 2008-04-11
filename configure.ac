# the autoconf initilization.
AC_INIT(libmpq, 0.4.1, [mbroemme@plusserver.de], [libmpq])

# detect the canonical host and target build environment.
AC_CANONICAL_SYSTEM

# initialize autoconf and automake system.
AM_INIT_AUTOMAKE([no-dependencies])
AC_CONFIG_HEADERS([config.h:config.h.in])

# notices.
AC_PREREQ(2.53)
AC_REVISION($Revision: 1.6 $)

# checking for programs.
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

# When we're running gcc 4 or greater, compile with -fvisibility=hidden.
AC_TRY_COMPILE([
#if !defined(__GNUC__) || (__GNUC__ < 4)
#error not gcc4
#endif
], [], [CFLAGS="$CFLAGS -fvisibility=hidden"])

AM_PATH_PYTHON([2.2],,[:])

# configuration files.
AC_CONFIG_FILES([libmpq.pc])
AC_CONFIG_FILES([libmpq-config],[chmod +x libmpq-config])

# creating files.
AC_OUTPUT([
Makefile
libmpq/Makefile
python/Makefile
doc/Makefile
doc/man1/Makefile
doc/man3/Makefile
])
