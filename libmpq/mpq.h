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
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#if defined(__GNUC__) && (__GNUC__ >= 4)
# define LIBMPQ_API __attribute__((visibility("default")))
#else
# define LIBMPQ_API
#endif

/* define errors. */
#define LIBMPQ_ERROR_OPEN			-1		/* open error on file. */
#define LIBMPQ_ERROR_CLOSE			-2		/* close error on file. */
#define LIBMPQ_ERROR_SEEK			-3		/* lseek error on file. */
#define LIBMPQ_ERROR_READ			-4		/* read error on file. */
#define LIBMPQ_ERROR_WRITE			-5		/* write error on file. */
#define LIBMPQ_ERROR_MALLOC			-6		/* memory allocation error. */
#define LIBMPQ_ERROR_FORMAT			-7		/* format errror. */
#define LIBMPQ_ERROR_NOT_INITIALIZED		-8		/* libmpq__init() wasn't called. */
#define LIBMPQ_ERROR_SIZE			-9		/* buffer size is to small. */
#define LIBMPQ_ERROR_EXIST			-10		/* file or block does not exist in archive. */
#define LIBMPQ_ERROR_DECRYPT			-11		/* we don't know the decryption seed. */
#define LIBMPQ_ERROR_UNPACK			-12		/* error on unpacking file. */

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

/* mpq extended archive header, used since world of warcraft - the burning crusade. */
typedef struct {
	uint64_t	extended_offset;	/* offset to the beginning of the extended block table, relative to the beginning of the archive. */
	uint16_t	hash_table_offset_high;	/* upper 16 bits of the hash table offset for large archives. */
	uint16_t	block_table_offset_high;/* upper 16 bits of the block table offset for large archives.*/
} __attribute__ ((packed)) mpq_header_ex_s;

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
	uint32_t	packed_size;		/* packed file size. */
	uint32_t	unpacked_size;		/* unpacked file size. */
	uint32_t	flags;			/* flags. */
} __attribute__ ((packed)) mpq_block_s;

/* extended file description block contains information about the offset beyond 2^32 (4GB). */
typedef struct {
	uint16_t	offset_high;		/* upper 16 bit of the file offset in archive. */
} __attribute__ ((packed)) mpq_block_ex_s;

/* file structure used since diablo 1.00 (0x38 bytes). */
typedef struct {
	uint32_t	seed;			/* seed used for file decrypt. */
	uint32_t	*packed_offset;		/* position of each file block (only for packed files). */
} mpq_file_s;

/* archive structure used since diablo 1.00 by blizzard. */
typedef struct {

	/* generic file information. */
	FILE		*fp;			/* file handle. */

	/* generic size information. */
	uint32_t	block_size;		/* size of the mpq block. */
	off_t		archive_offset;		/* absolute start position of archive. */

	/* archive related buffers and tables. */
	mpq_header_s	mpq_header;		/* mpq file header. */
	mpq_header_ex_s	mpq_header_ex;		/* mpq extended file header. */
	mpq_hash_s	*mpq_hash;		/* hash table. */
	mpq_block_s	*mpq_block;		/* block table. */
	mpq_block_ex_s	*mpq_block_ex;		/* extended block table. */
	mpq_file_s	**mpq_file;		/* pointer to the file pointers which are opened. */

	/* non archive structure related members. */
	uint32_t	*block_table_indices;	/* pointer which stores the mapping for file number to block entry. */
	uint32_t	files;			/* number of files in archive, which could be extracted. */
} mpq_archive_s;

/* initialization and shut down. */
extern LIBMPQ_API int32_t libmpq__init(void);
extern LIBMPQ_API int32_t libmpq__shutdown(void);

/* generic information about library. */
extern LIBMPQ_API const char *libmpq__version(void);

/* generic mpq archive information. */
extern LIBMPQ_API int32_t libmpq__archive_open(mpq_archive_s **mpq_archive, const char *mpq_filename, off_t archive_offset);
extern LIBMPQ_API int32_t libmpq__archive_close(mpq_archive_s *mpq_archive);
extern LIBMPQ_API int32_t libmpq__archive_packed_size(mpq_archive_s *mpq_archive, off_t *packed_size);
extern LIBMPQ_API int32_t libmpq__archive_unpacked_size(mpq_archive_s *mpq_archive, off_t *unpacked_size);
extern LIBMPQ_API int32_t libmpq__archive_offset(mpq_archive_s *mpq_archive, off_t *offset);
extern LIBMPQ_API int32_t libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version);
extern LIBMPQ_API int32_t libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files);

/* generic file processing functions. */
extern LIBMPQ_API int32_t libmpq__file_packed_size(mpq_archive_s *mpq_archive, uint32_t file_number, off_t *packed_size);
extern LIBMPQ_API int32_t libmpq__file_unpacked_size(mpq_archive_s *mpq_archive, uint32_t file_number, off_t *unpacked_size);
extern LIBMPQ_API int32_t libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, off_t *offset);
extern LIBMPQ_API int32_t libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks);
extern LIBMPQ_API int32_t libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *encrypted);
extern LIBMPQ_API int32_t libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *compressed);
extern LIBMPQ_API int32_t libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *imploded);
extern LIBMPQ_API int32_t libmpq__file_name(mpq_archive_s *mpq_archive, uint32_t file_number, char *filename, size_t filename_size);
extern LIBMPQ_API int32_t libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number);
extern LIBMPQ_API int32_t libmpq__file_read(mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, off_t out_size, off_t *transferred);

/* generic block processing functions. */
extern LIBMPQ_API int32_t libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__block_packed_size(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, off_t *packed_size);
extern LIBMPQ_API int32_t libmpq__block_unpacked_size(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, off_t *unpacked_size);
extern LIBMPQ_API int32_t libmpq__block_offset(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, off_t *offset);
extern LIBMPQ_API int32_t libmpq__block_seed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint32_t *seed);
extern LIBMPQ_API int32_t libmpq__block_read(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf, off_t out_size, off_t *transferred);

#ifdef __cplusplus
}
#endif

#endif						/* _MPQ_H */
