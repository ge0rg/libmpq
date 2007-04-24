# The autoconf initilization.
AC_INIT(mpq-tools, 0.3.0, [mbroemme@plusserver.de], [mpq-tools])

# Detect the canonical host and target build environment
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([no-dependencies])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_DEFINE_UNQUOTED(OS, "${host}", [cpu-machine-OS])

# Set various version strings
LIBMPQ_MAJOR_VERSION=0
LIBMPQ_MINOR_VERSION=3
LIBMPQ_PATCHLEVEL=0
LIBMPQ_VERSION=$LIBMPQ_MAJOR_VERSION.$LIBMPQ_MINOR_VERSION.$LIBMPQ_PATCHLEVEL

AC_SUBST(LIBMPQ_MAJOR_VERSION)
AC_SUBST(LIBMPQ_MINOR_VERSION)
AC_SUBST(LIBMPQ_PATCHLEVEL)
AC_SUBST(LIBMPQ_VERSION)

# Notices
AC_PREREQ(2.53)
AC_REVISION($Revision: 1.6 $)

# Checking for programs.
AC_DISABLE_SHARED
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_CC
CCAS="$CC"
CCASFLAGS=""
AC_SUBST(CCAS)
AC_SUBST(CCASFLAGS)

dnl **********************************************************************
dnl Check for the presence of ZLIB libraries and headers
dnl **********************************************************************

dnl Check for & handle argument to --with-zlib.

AC_ARG_WITH(zlib,
AC_HELP_STRING([--with-zlib=PATH],[use libz in PATH])
AC_HELP_STRING([--without-zlib],[disable use of zlib]),
[
	if test "$withval" != "no" -a "$withval" != "yes"; then
		Z_DIR=$withval
		CPPFLAGS="${CPPFLAGS} -I$withval/include"
		LDFLAGS="${LDFLAGS} -L$withval/lib"
	fi
]
)

if test "$with_zlib" = "no"; then
	AC_MSG_WARN([*** zlib disabled - you maybe not able to extract all files from mpq archives.])
else
	AC_CHECK_HEADERS(zlib.h,
		AC_CHECK_LIB(z, inflateEnd,[
			AC_DEFINE(HAVE_LIBZ, 1, [if you have zlib library])
			if test "x${Z_DIR}" != "x"; then
				Z_CFLAGS="-I${Z_DIR}/include"
				Z_LIBS="-L${Z_DIR}/lib -lz"
			else
				Z_LIBS="-lz"
			fi
		], [AC_MSG_ERROR([*** broken zlib build.]) ])
	)
fi

AC_SUBST(Z_CFLAGS)
AC_SUBST(Z_LIBS)

# Creating files.
AC_OUTPUT([
Makefile
db/Makefile
db/diablo2/Makefile
src/Makefile
libmpq/Makefile
])
