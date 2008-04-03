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
#include <stdint.h>

/* define errors. */
#define LIBMPQ_ERROR_OPEN			-1		/* open error on file. */
#define LIBMPQ_ERROR_CLOSE			-2		/* close error on file. */
#define LIBMPQ_ERROR_LSEEK			-3		/* lseek error on file. */
#define LIBMPQ_ERROR_READ			-4		/* read error on file. */
#define LIBMPQ_ERROR_WRITE			-5		/* write error on file. */
#define LIBMPQ_ERROR_MALLOC			-6		/* memory allocation error. */
#define LIBMPQ_ERROR_FORMAT			-7		/* format errror. */
#define LIBMPQ_ERROR_NOT_INITIALIZED		-8		/* libmpq__init() wasn't called. */
#define LIBMPQ_ERROR_EXIST			-10		/* file or block does not exist in archive. */
#define LIBMPQ_ERROR_DECRYPT			-11		/* we don't know the decryption seed. */
#define LIBMPQ_ERROR_DECOMPRESS			-12		/* error on decompression. */
#define LIBMPQ_ERROR_INFO			-13		/* requested info type was not found. */

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
	uint32_t	mpq_magic;		/* the 0x1A51504D ('MPQ\x1A') signature. */
	uint32_t	header_size;		/* mpq archive header size. */
	uint32_t	archive_size;		/* size of mpq archive. */
	uint16_t	version;		/* 0000 for starcraft and broodwar. */
	uint16_t	block_size;		/* size of file block is (512 * 2 ^ block size). */
	uint32_t	hash_table_offset;	/* file position of mpq_hash. */
	uint32_t	block_table_offset;	/* file position of mpq_block, each entry has 16 bytes. */
	uint32_t	hash_table_count;	/* number of entries in hash table. */
	uint32_t	block_table_count;	/* number of entries in the block table. */
} __attribute__ ((packed)) mpq_header_s;

/* hash entry, all files in the archive are searched by their hashes. */
typedef struct {
	uint32_t	hash_a;			/* the first two uint32_ts are the encrypted file. */
	uint32_t	hash_b;			/* the first two uint32_ts are the encrypted file. */
	uint16_t	locale;			/* locale information. */
	uint16_t	platform;		/* platform information and zero is default. */
	uint32_t	block_table_index;	/* index to file description block. */
} __attribute__ ((packed)) mpq_hash_s;

/* file description block contains informations about the file. */
typedef struct {
	uint32_t	offset;			/* block file starting position in the archive. */
	uint32_t	compressed_size;	/* compressed file size. */
	uint32_t	uncompressed_size;	/* uncompressed file size. */
	uint32_t	flags;			/* flags. */
} __attribute__ ((packed)) mpq_block_s;

/* file structure used since diablo 1.00 (0x38 bytes). */
typedef struct {
	uint32_t	seed;			/* seed used for file decrypt. */
	uint32_t	*compressed_offset;	/* position of each file block (only for compressed files). */
} mpq_file_s;

/* file list structure. */
typedef struct {
	char		**file_names;		/* file name for archive members. */
	uint32_t	*block_table_indices;	/* pointer which stores the mapping for file number to block entry. */
	uint32_t	*hash_table_indices;	/* pointer which stores the mapping for file number to hash entry. */
} mpq_list_s;

/* archive structure used since diablo 1.00 by blizzard. */
typedef struct {

	/* generic file information. */
	char		filename[PATH_MAX];	/* archive file name. */
	int32_t		fd;			/* file handle. */

	/* generic size information. */
	uint32_t	block_size;		/* size of the mpq block. */

	/* archive related buffers and tables. */
	mpq_header_s	*mpq_header;		/* mpq file header. */
	mpq_hash_s	*mpq_hash;		/* hash table. */
	mpq_block_s	*mpq_block;		/* block table. */
	mpq_file_s	**mpq_file;		/* pointer to the file pointers which are opened. */

	/* non archive structure related members. */
	mpq_list_s	*mpq_list;		/* handle to file list (in most cases this is the last file in the archive). */
	uint32_t	files;			/* number of files in archive, which could be extracted. */
} mpq_archive_s;

/* initialization and shut down */
extern int32_t libmpq__init(void);
extern int32_t libmpq__shutdown(void);

/* generic information about library. */
extern const char *libmpq__version(void);

/* generic mpq archive information. */
extern int32_t libmpq__archive_open(mpq_archive_s *mpq_archive, const char *mpq_filename);
extern int32_t libmpq__archive_close(mpq_archive_s *mpq_archive);
extern int32_t libmpq__archive_info(mpq_archive_s *mpq_archive, uint32_t info_type);

/* generic file information. */
extern int32_t libmpq__file_open(mpq_archive_s *mpq_archive, uint32_t file_number);
extern int32_t libmpq__file_close(mpq_archive_s *mpq_archive, uint32_t file_number);
extern int32_t libmpq__file_info(mpq_archive_s *mpq_archive, uint32_t info_type, uint32_t file_number);
extern const char *libmpq__file_name(mpq_archive_s *mpq_archive, uint32_t file_number);
extern int32_t libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename);

/* generic block information. */
extern int32_t libmpq__block_info(mpq_archive_s *mpq_archive, uint32_t info_type, uint32_t file_number, uint32_t block_number);

/* generic block decrypt function. */
extern int32_t libmpq__block_decrypt(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t seed);

/* generic block decompress function. */
extern int32_t libmpq__block_decompress(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size);

/* generic block explode function. */
extern int32_t libmpq__block_explode(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size);

/* generic block copy function. */
extern int32_t libmpq__block_copy(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size);

/* generic memory decrypt function. */
extern int32_t libmpq__memory_decrypt(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_count);

/* generic memory decompress function. */
extern int32_t libmpq__memory_decompress(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_size);

/* generic memory explode function. */
extern int32_t libmpq__memory_explode(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_size);

/* generic memory copy function. */
extern int32_t libmpq__memory_copy(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_size);

#ifdef __cplusplus
}
#endif

#endif						/* _MPQ_H */
