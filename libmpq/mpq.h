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
#include <sys/types.h>
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

/* internal data structure. */
typedef struct mpq_archive mpq_archive_s;

/* initialization and shut down. */
extern LIBMPQ_API int32_t libmpq__init(void);
extern LIBMPQ_API int32_t libmpq__shutdown(void);

/* generic information about library. */
extern LIBMPQ_API const char *libmpq__version(void);

/* generic mpq archive information. */
extern LIBMPQ_API mpq_archive_s* libmpq__archive_open(const char *mpq_filename, off_t archive_offset);
extern LIBMPQ_API int32_t libmpq__archive_close(mpq_archive_s *mpq_archive);
extern LIBMPQ_API off_t libmpq__archive_packed_size(mpq_archive_s *mpq_archive);
extern LIBMPQ_API off_t libmpq__archive_unpacked_size(mpq_archive_s *mpq_archive);
extern LIBMPQ_API off_t libmpq__archive_offset(mpq_archive_s *mpq_archive);
extern LIBMPQ_API int32_t libmpq__archive_version(mpq_archive_s *mpq_archive);
extern LIBMPQ_API int32_t libmpq__archive_files(mpq_archive_s *mpq_archive);

/* generic file processing functions. */
extern LIBMPQ_API off_t libmpq__file_packed_size(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API off_t libmpq__file_unpacked_size(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API off_t libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__file_name(mpq_archive_s *mpq_archive, uint32_t file_number, char *filename, size_t filename_size);
extern LIBMPQ_API int32_t libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename);
extern LIBMPQ_API off_t libmpq__file_read(mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, off_t out_size);

/* generic block processing functions. */
extern LIBMPQ_API int32_t libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API int32_t libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number);
extern LIBMPQ_API off_t libmpq__block_unpacked_size(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number);
extern LIBMPQ_API off_t libmpq__block_read(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf, off_t out_size);

#ifdef __cplusplus
}
#endif

#endif						/* _MPQ_H */
