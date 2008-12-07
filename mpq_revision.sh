#!/bin/sh
set -e

DEST=mpq_revision.h
oldver=0
[ -f $DEST ] && oldver=$(awk '{print $3}' mpq_revision.h)

if [ -d .svn ]; then
	ver=$(svnversion -nc . | sed -e 's/^[^:]*://;s/[A-Za-z]//')
elif [ -d .git ]; then
	#ver=$(git-svn find-rev HEAD)
	ver=$(git-svn log --limit 1 --oneline | sed 's/^r\([0-9]*\).*/\1/')
elif [ -f $DEST ]; then
	echo "Not updating LIBMPQ_REVISION..."
	exit 0
fi || exit 1

[ "$ver" -ne "$oldver" ] && echo "#define LIBMPQ_REVISION $ver" > $DEST
cat $DEST
