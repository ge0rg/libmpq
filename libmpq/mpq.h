/*
 *  mpq.h -- some default types and defines.
 *
 *  Copyright (c) 2003-2008 Maik Broemme <mbroemme@plusserver.de>
 *
 *  Some parts (the encryption and decryption stuff) were adapted from
 *  the C++ version of StormLib.h and StormPort.h included in stormlib.
 *  The C++ version belongs to the following authors:
 *
 *  Ladislav Zezula <ladik@zezula.net>
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

#ifdef __cplusplus
extern "C" {
#endif

/* generic includes. */
#include <limits.h>

/* define errors. */
#define LIBMPQ_ERROR_OPEN			-1		/* open error on file. */
#define LIBMPQ_ERROR_CLOSE			-2		/* close error on file. */
#define LIBMPQ_ERROR_LSEEK			-3		/* lseek error on file. */
#define LIBMPQ_ERROR_READ			-4		/* read error on file. */
#define LIBMPQ_ERROR_WRITE			-5		/* write error on file. */
#define LIBMPQ_ERROR_MALLOC			-6		/* memory allocation error. */
#define LIBMPQ_ERROR_FORMAT			-7		/* format errror. */
#define LIBMPQ_ERROR_HASHTABLE			-8		/* hash table in archive is broken. */
#define LIBMPQ_ERROR_BLOCKTABLE			-9		/* block table in archive is broken. */
#define LIBMPQ_ERROR_EXIST			-10		/* file or block does not exist in archive. */
#define LIBMPQ_ERROR_DECRYPT			-11		/* we don't know the decryption seed. */
#define LIBMPQ_ERROR_DECOMPRESS			-12		/* error on decompression. */

/* define generic values for returning archive information. */
#define LIBMPQ_ARCHIVE_SIZE			1		/* mpq archive size. */
#define LIBMPQ_ARCHIVE_COMPRESSED_SIZE		2		/* compressed archive size. */
#define LIBMPQ_ARCHIVE_UNCOMPRESSED_SIZE	3		/* uncompressed archive size. */
#define LIBMPQ_ARCHIVE_FILES			4		/* number of files in the mpq archive */
#define LIBMPQ_ARCHIVE_HASHTABLE_ENTRIES	5		/* mpq archive hashtable size. */
#define LIBMPQ_ARCHIVE_BLOCKTABLE_ENTRIES	6		/* mpq archive blocktable size. */
#define LIBMPQ_ARCHIVE_BLOCKSIZE		7		/* mpq archive block size. */
#define LIBMPQ_ARCHIVE_VERSION			8		/* mpq archive version. */

/* define generic values for returning file information. */
#define LIBMPQ_FILE_COMPRESSED_SIZE		1		/* compressed size of the given file in archive. */
#define LIBMPQ_FILE_UNCOMPRESSED_SIZE		2		/* uncompressed size of the given file in archive. */
#define LIBMPQ_FILE_ENCRYPTED_SIZE		3		/* encrypted size of the given file in archive. */
#define LIBMPQ_FILE_DECRYPTED_SIZE		4		/* decrypted size of the given file in archive. */
#define LIBMPQ_FILE_ENCRYPTED			5		/* return true if file is encrypted. */
#define LIBMPQ_FILE_COMPRESSED			6		/* return true if file is compressed using multiple compression algorithm. */
#define LIBMPQ_FILE_IMPLODED			7		/* return true if file is imploded using pkware implode algorithm. */
#define LIBMPQ_FILE_COPIED			8		/* return true if file is neither compressed nor imploded. */
#define LIBMPQ_FILE_SINGLE			9		/* return true if file is stored in single sector. */
#define LIBMPQ_FILE_OFFSET			10		/* return absolute start position of file in archive. */
#define LIBMPQ_FILE_BLOCKS			11		/* return the number of blocks for the file, if file is stored in single sector return one. */
#define LIBMPQ_FILE_BLOCKSIZE			12		/* return the block size for the file, if file is stored in single sector return uncompressed size. */

/* define generic values for returning block information. */
#define LIBMPQ_BLOCK_COMPRESSED_SIZE		1		/* compressed size of the given block in archive. */
#define LIBMPQ_BLOCK_UNCOMPRESSED_SIZE		2		/* uncompressed size of the given block in archive. */
#define LIBMPQ_BLOCK_ENCRYPTED_SIZE		3		/* encrypted size of the given block in archive. */
#define LIBMPQ_BLOCK_DECRYPTED_SIZE		4		/* decrypted size of the given block in archive. */
#define LIBMPQ_BLOCK_OFFSET			5		/* return absolute start position of block in archive. */
#define LIBMPQ_BLOCK_SEED			6		/* return the block seed used for decryption. */

/* mpq archive header. */
typedef struct {
	unsigned int	mpq_magic;		/* the 0x1A51504D ('MPQ\x1A') signature. */
	unsigned int	header_size;		/* mpq archive header size. */
	unsigned int	archive_size;		/* size of mpq archive. */
	unsigned short	version;		/* 0000 for starcraft and broodwar. */
	unsigned short	block_size;		/* size of file block is (512 * 2 ^ block size). */
	unsigned int	hash_table_offset;	/* file position of mpq_hash. */
	unsigned int	block_table_offset;	/* file position of mpq_block, each entry has 16 bytes. */
	unsigned int	hash_table_count;	/* number of entries in hash table. */
	unsigned int	block_table_count;	/* number of entries in the block table. */
} __attribute__ ((packed)) mpq_header_s;

/* hash entry, all files in the archive are searched by their hashes. */
typedef struct {
	unsigned int	hash_a;			/* the first two unsigned ints are the encrypted file. */
	unsigned int	hash_b;			/* the first two unsigned ints are the encrypted file. */
	unsigned short	locale;			/* locale information. */
	unsigned short	platform;		/* platform information and zero is default. */
	unsigned int	block_table_index;	/* index to file description block. */
} __attribute__ ((packed)) mpq_hash_s;

/* file description block contains informations about the file. */
typedef struct {
	unsigned int	offset;			/* block file starting position in the archive. */
	unsigned int	compressed_size;	/* compressed file size. */
	unsigned int	uncompressed_size;	/* uncompressed file size. */
	unsigned int	flags;			/* flags. */
} __attribute__ ((packed)) mpq_block_s;

/* file structure used since diablo 1.00 (0x38 bytes). */
typedef struct {
	unsigned int	seed;			/* seed used for file decrypt. */
	unsigned int	*compressed_offset;	/* position of each file block (only for compressed files). */
} mpq_file_s;

/* file list structure. */
typedef struct {
	char		**file_names;		/* file name for archive members. */
	unsigned int	*block_table_indices;	/* pointer which stores the mapping for file number to block entry. */
	unsigned int	*hash_table_indices;	/* pointer which stores the mapping for file number to hash entry. */
} mpq_list_s;

/* archive structure used since diablo 1.00 by blizzard. */
typedef struct {

	/* generic file information. */
	char		filename[PATH_MAX];	/* archive file name. */
	int		fd;			/* file handle. */

	/* generic size information. */
	unsigned int	block_size;		/* size of the mpq block. */

	/* archive related buffers and tables. */
	mpq_header_s	*mpq_header;		/* mpq file header. */
	mpq_hash_s	*mpq_hash;		/* hash table. */
	mpq_block_s	*mpq_block;		/* block table. */
	mpq_file_s	**mpq_file;		/* pointer to the file pointers which are opened. */

	/* non archive structure related members. */
	mpq_list_s	*mpq_list;		/* handle to file list (in most cases this is the last file in the archive). */
	unsigned int	files;			/* number of files in archive, which could be extracted. */
} mpq_archive_s;

/* generic information about library. */
extern char *libmpq__version();

/* generic mpq archive information. */
extern int libmpq__archive_open(mpq_archive_s *mpq_archive, char *mpq_filename);
extern int libmpq__archive_close(mpq_archive_s *mpq_archive);
extern int libmpq__archive_info(mpq_archive_s *mpq_archive, unsigned int info_type);

/* generic file information. */
extern int libmpq__file_open(mpq_archive_s *mpq_archive, unsigned int file_number);
extern int libmpq__file_close(mpq_archive_s *mpq_archive, unsigned int file_number);
extern int libmpq__file_info(mpq_archive_s *mpq_archive, unsigned int info_type, unsigned int file_number);
extern char *libmpq__file_name(mpq_archive_s *mpq_archive, unsigned int file_number);
extern int libmpq__file_number(mpq_archive_s *mpq_archive, char *filename);

/* generic block information. */
extern int libmpq__block_info(mpq_archive_s *mpq_archive, unsigned int info_type, unsigned int file_number, unsigned int block_number);

/* generic block decrypt function. */
extern int libmpq__block_decrypt(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int seed);

/* generic block decompress function. */
extern int libmpq__block_decompress(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size);

/* generic block explode function. */
extern int libmpq__block_explode(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size);

/* generic block copy function. */
extern int libmpq__block_copy(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size);

/* generic memory decrypt function. */
extern int libmpq__memory_decrypt(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_count);

/* generic memory decompress function. */
extern int libmpq__memory_decompress(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_size);

/* generic memory explode function. */
extern int libmpq__memory_explode(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_size);

/* generic memory copy function. */
extern int libmpq__memory_copy(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_size);

#ifdef __cplusplus
}
#endif

#endif						/* _MPQ_H */
