/*
 *  mpq.h -- some default types and defines.
 *
 *  Copyright (c) 2003-2007 Maik Broemme <mbroemme@plusserver.de>
 *
 *  This source was adepted from the C++ version of StormLib.h and
 *  StormPort.h included in stormlib. The C++ version belongs to
 *  the following authors,
 *
 *  Ladislav Zezula <ladik.zezula.net>
 *  Marko Friedemann <marko.friedemann@bmx-chemnitz.de>
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

#ifndef _MPQ_H
#define _MPQ_H

/* generic includes. */
#include <limits.h>

/* define return value if nothing failed. */
#define LIBMPQ_SUCCESS				0		/* return value for all functions which success. */

/* define archive errors. */
#define LIBMPQ_ARCHIVE_ERROR_OPEN		-1		/* open error on archive file. */
#define LIBMPQ_ARCHIVE_ERROR_CLOSE		-2		/* close error on archive file. */
#define LIBMPQ_ARCHIVE_ERROR_FORMAT		-3		/* archive format errror. */
#define LIBMPQ_ARCHIVE_ERROR_HASHTABLE		-4		/* hashtable in archive if broken. */
#define LIBMPQ_ARCHIVE_ERROR_BLOCKTABLE		-5		/* blocktable in archive if broken. */
#define LIBMPQ_ARCHIVE_ERROR_MALLOC		-6		/* memory allocation error for archive. */

/* define file errors. */
#define LIBMPQ_FILE_ERROR_OPEN			-1		/* open error on file. */
#define LIBMPQ_FILE_ERROR_CLOSE			-2		/* close error on file. */
#define LIBMPQ_FILE_ERROR_CORRUPT		-3		/* file is corrupt in archive. */
#define LIBMPQ_FILE_ERROR_EXIST			-4		/* file does not exist in archive. */
#define LIBMPQ_FILE_ERROR_RANGE			-5		/* filenumber is out of range. */
#define LIBMPQ_FILE_ERROR_MALLOC		-6		/* memory allocation error for file. */

/* define generic mpq archive information. */
#define LIBMPQ_MPQ_HEADER_ID			0x1A51504D	/* mpq archive header ('MPQ\x1A') */
#define LIBMPQ_MPQ_HEADER_W3M			0x6D9E4B86	/* special value used by w3m map protector. */
#define LIBMPQ_MPQ_FLAG_PROTECTED		0x00000002	/* required for protected mpq archives, like w3m maps. */
#define LIBMPQ_MPQ_HASH_DELETED			0xFFFFFFFE	/* block index for deleted hash entry. */

/* define generic values for returning archive information. */
#define LIBMPQ_ARCHIVE_SIZE			1		/* mpq archive size. */
#define LIBMPQ_ARCHIVE_HASHTABLE_SIZE		2		/* mpq archive hashtable size. */
#define LIBMPQ_ARCHIVE_BLOCKTABLE_SIZE		3		/* mpq archive blocktable size. */
#define LIBMPQ_ARCHIVE_BLOCKSIZE		4		/* mpq archive blocksize. */
#define LIBMPQ_ARCHIVE_NUMFILES			5		/* number of files in the mpq archive */
#define LIBMPQ_ARCHIVE_COMPRESSED_SIZE		6		/* compressed archive size. */
#define LIBMPQ_ARCHIVE_UNCOMPRESSED_SIZE	7		/* uncompressed archive size. */

/* define generic values for returning file information. */
#define LIBMPQ_FILE_COMPRESSED_SIZE		1		/* compressed filesize of the given file in archive. */
#define LIBMPQ_FILE_UNCOMPRESSED_SIZE		2		/* uncompressed filesize of the given file in archive. */
#define LIBMPQ_FILE_COMPRESSION_TYPE		3		/* compression type of the given file in archive.*/

#define LIBMPQ_FILE_COMPRESS_PKWARE	0x00000100	/* Compression made by PKWARE Data Compression Library */
#define LIBMPQ_FILE_COMPRESS_MULTI	0x00000200	/* Multiple compressions */
#define LIBMPQ_FILE_COMPRESSED		0x0000FF00	/* File is compressed */
#define LIBMPQ_FILE_EXISTS		0x80000000	/* Set if file exists, reset when the file was deleted */
#define LIBMPQ_FILE_ENCRYPTED		0x00010000	/* Indicates whether file is encrypted */

#define LIBMPQ_HUFF_DECOMPRESS		0		/* Defines that we want to decompress using huffman trees. */

/* define true and false, because not all systems have them. */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

/* define min, because not all systems have it. */
#ifndef min
#define min(a, b) ((a < b) ? a : b)
#endif

/* the decryption buffer. */
typedef unsigned int	mpq_buffer[0x500];

/* table for decompression functions. */
typedef int		(*DECOMPRESS)(char *, int *, char *, int);
typedef struct {
	unsigned int	mask;			/* Decompression bit */
	DECOMPRESS	decompress;		/* Decompression function */
} decompress_table;

/* mpq archive header. */
typedef struct {
	unsigned int	id;			/* the 0x1A51504D ('MPQ\x1A') signature. */
	unsigned int	offset;			/* offset of the first file (relative to mpq start). */
	unsigned int	archivesize;		/* size of mpq archive. */
	unsigned short	offsetsc;		/* 0000 for starcraft and broodwar. */
	unsigned short	blocksize;		/* size of file block is (0x200 << blocksize). */
	unsigned int	hashtablepos;		/* file position of mpq_hash. */
	unsigned int	blocktablepos;		/* file position of mpq_block, each entry has 16 bytes. */
	unsigned int	hashtablesize;		/* number of entries in hash table. */
	unsigned int	blocktablesize;		/* number of entries in the block table. */
} __attribute__ ((packed)) mpq_header;


/* hash entry, all files in the archive are searched by their hashes. */
typedef struct {
	unsigned int	name1;			/* the first two unsigned ints are the encrypted file. */
	unsigned int	name2;			/* the first two unsigned ints are the encrypted file. */
	unsigned int	locale;			/* locale information. */
	unsigned int	blockindex;		/* index to file description block. */
} mpq_hash;

/* file description block contains informations about the file. */
typedef struct {
	unsigned int	filepos;		/* block file starting position in the archive. */
	unsigned int	csize;			/* compressed file size. */
	unsigned int	fsize;			/* uncompressed file size. */
	unsigned int	flags;			/* flags. */
} mpq_block;

/* file structure used since diablo 1.00 (0x38 bytes). */
typedef struct {
	unsigned char	filename[PATH_MAX];	/* filename of the actual file in the archive. */
	int		fd;			/* file handle. */
	unsigned int	seed;			/* seed used for file decrypt. */
	unsigned int	filepos;		/* current file position. */
	unsigned int	offset;
	unsigned int	nblocks;		/* number of blocks in the file (incl. the last noncomplete one). */
	unsigned int	*blockpos;		/* position of each file block (only for compressed files). */
	int		blockposloaded;		/* true if block positions loaded. */
	unsigned int	offset2;		/* number of bytes somewhere? */
	mpq_hash	*mpq_h;			/* hash table entry. */
	mpq_block	*mpq_b;			/* file block pointer. */

	/* non file structure related members. */
	unsigned int	accessed;		/* was something from the file already read? */
} mpq_file;

/* filelist structure. */
typedef struct {
	unsigned char	**mpq_files;		/* filelist. */
} mpq_list;

/* archive structure used since diablo 1.00 by blizzard. */
typedef struct {
	unsigned char	filename[PATH_MAX];	/* archive file name. */
	int		fd;			/* file handle. */
	unsigned int	blockpos;		/* position of loaded block in the file. */
	unsigned int	blocksize;		/* size of file block. */
	unsigned char	*blockbuf;		/* buffer (cache) for file block. */
	unsigned int	bufpos;			/* position in block buffer. */
	unsigned int	mpqpos;			/* archive position in the file. */
	unsigned int	filepos;		/* current file pointer. */
	unsigned int	openfiles;		/* number of open files + 1. */
	mpq_buffer	buf;			/* mpq buffer. */
	mpq_header	*header;		/* mpq file header. */
	mpq_hash	*hashtable;		/* hash table. */
	mpq_block	*blocktable;		/* block table. */

	/* non archive structure related members. */
	mpq_list	*mpq_l;			/* handle to filelist (in most cases this is the last file in the archive). */
	unsigned int	flags;			/* see LIBMPQ_MPQ_FLAG_XXX for more details. */
	unsigned int	maxblockindex;		/* the highest block table entry. */
} mpq_archive;

/* generic information about library. */
extern char *libmpq__version();

/* generic mpq archive information. */
extern int libmpq__archive_open(mpq_archive *mpq_a, unsigned char *mpq_filename);
extern int libmpq__archive_close(mpq_archive *mpq_a);
extern int libmpq__archive_info(mpq_archive *mpq_a, unsigned int infotype);

/* generic file information. */
extern int libmpq__file_info(mpq_archive *mpq_a, unsigned int infotype, const int number);
extern char *libmpq__file_name(mpq_archive *mpq_a, const int number);
extern int libmpq__file_number(mpq_archive *mpq_a, const char *name);
extern int libmpq__file_extract(mpq_archive *mpq_a, const int number);

/* generic decompression functions. */
extern int libmpq_pkzip_decompress(char *out_buf, int *out_length, char *in_buf, int in_length);
extern int libmpq_zlib_decompress(char *out_buf, int *out_length, char *in_buf, int in_length);
extern int libmpq_huff_decompress(char *out_buf, int *out_length, char *in_buf, int in_length);
extern int libmpq_wave_decompress_stereo(char *out_buf, int *out_length, char *in_buf, int in_length);
extern int libmpq_wave_decompress_mono(char *out_buf, int *out_length, char *in_buf, int in_length);
extern int libmpq_multi_decompress(char *out_buf, int *pout_length, char *in_buf, int in_length);

static decompress_table dcmp_table[] = {
	{0x08, libmpq_pkzip_decompress},	/* decompression with pkware data compression library. */
	{0x02, libmpq_zlib_decompress},		/* decompression with the zlib library. */
	{0x01, libmpq_huff_decompress},		/* huffmann decompression. */
	{0x80, libmpq_wave_decompress_stereo},	/* wave decompression for stereo waves. */
	{0x40, libmpq_wave_decompress_mono}	/* wave decompression for mono waves. */
};

#endif						/* _MPQ_H */
