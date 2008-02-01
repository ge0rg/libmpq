/*
 *  mpq-internal.h -- some default types and defines, but only required for
 *                    compilation of the library.
 *
 *  Copyright (c) 2003-2008 Maik Broemme <mbroemme@plusserver.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _MPQ_INTERNAL_H
#define _MPQ_INTERNAL_H

/* define generic mpq archive information. */
#define LIBMPQ_HEADER				0x1A51504D	/* mpq archive header ('MPQ\x1A') */
#define LIBMPQ_BUFFER_SIZE			0x500		/* mpq decryption and encryption buffer size. */

/* define the known archive versions. */
#define LIBMPQ_ARCHIVE_VERSION_ONE		0		/* version one used until world of warcraft. */
#define LIBMPQ_ARCHIVE_VERSION_TWO		1		/* version two used from world of warcraft - the burning crusade. */

/* define values used by blizzard as flags. */
#define LIBMPQ_FLAG_EXISTS			0x80000000	/* set if file exists, reset when the file was deleted. */
#define LIBMPQ_FLAG_ENCRYPTED			0x00010000	/* indicates whether file is encrypted. */
#define LIBMPQ_FLAG_COMPRESSED			0x0000FF00	/* file is compressed. */
#define LIBMPQ_FLAG_COMPRESS_PKWARE		0x00000100	/* compression made by pkware data compression library. */
#define LIBMPQ_FLAG_COMPRESS_MULTI		0x00000200	/* multiple compressions. */
#define LIBMPQ_FLAG_SINGLE			0x01000000	/* file is stored in one single sector, first seen in world of warcraft. */
#define LIBMPQ_FLAG_HASH_FREE			0xFFFFFFFF	/* hash table entry is empty and has always been empty. */

/* define true and false, because not all systems have them. */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

/* define max, because not all systems have it. */
#ifndef max
#define max(a, b) ((a > b) ? a : b)
#endif

#endif						/* _MPQ_INTERNAL_H */
