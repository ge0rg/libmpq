# the autoconf initilization.
AC_INIT(mpq-tools, 0.4.0, [mbroemme@plusserver.de], [mpq-tools])

# detect the canonical host and target build environment.
AC_CANONICAL_SYSTEM

# initialize autoconf and automake system.
AM_INIT_AUTOMAKE([no-dependencies])
AC_CONFIG_HEADERS([config.h:config.h.in])

# create define for the package author.
AC_DEFINE([AUTHOR], ["Maik Broemme <mbroemme@plusserver.de>"], [Define to the author of this package.])

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

# configuration files.
AC_CONFIG_FILES([libmpq.pc])
AC_CONFIG_FILES([libmpq-config],[chmod +x libmpq-config])

# creating files.
AC_OUTPUT([
Makefile
src/Makefile
libmpq/Makefile
doc/Makefile
doc/man1/Makefile
doc/man3/Makefile
])

# show user the warning about the merged release.
echo ""
echo "*** NOTICE ***"
echo "'$PACKAGE-$PACKAGE_VERSION' will be the last version which includes the library"
echo "and the utility package. The next version will be shipped as two packages."
echo ""
echo "libmpq-0.4.1"
echo "mpq-tools-0.4.1"
echo ""
echo "Due to the fact that more changes are done in the library than in the"
echo "extraction utility, it is the next development step."
echo ""
