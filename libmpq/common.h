/*
 *  common.h -- header functions used by mpq-tools.
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

#ifndef _COMMON_H
#define _COMMON_H

/* function to initialize decryption buffer. */
int32_t libmpq__decrypt_buffer_init(
	uint32_t	*buffer
);

/* function to detect decryption key. */
int32_t libmpq__decrypt_key(
	uint8_t		*in_buf,
	uint32_t	in_size,
	uint32_t	*crypt_buf
);

/* function to decrypt a block. */
int32_t libmpq__decrypt_block(
	uint8_t		*in_buf,
	uint32_t	in_size,
	uint8_t		*out_buf,
	uint32_t	out_size,
	uint32_t	seed,
	uint32_t	*crypt_buf
);

/* function to decrypt whole read buffer. */
int32_t libmpq__decrypt_memory(
	uint8_t		*in_buf,
	uint32_t	in_size,
	uint8_t		*out_buf,
	uint32_t	out_size,
	uint32_t	block_count,
	uint32_t	*crypt_buf
);

/* function to decompress or explode block from archive. */
int32_t libmpq__decompress_block(
	uint8_t		*in_buf,
	uint32_t	in_size,
	uint8_t		*out_buf,
	uint32_t	out_size,
	uint32_t	compression_type
);

/* function to decompress or explode whole read buffer. */
int32_t libmpq__decompress_memory(
	uint8_t		*in_buf,
	uint32_t	in_size,
	uint8_t		*out_buf,
	uint32_t	out_size,
	uint32_t	block_size,
	uint32_t	compression_type
);

/* function to read and decrypt hash table. */
int32_t libmpq__read_table_hash(
	mpq_archive_s	*mpq_archive,
	uint32_t	*crypt_buf
);

/* function to read and decrypt hash table. */
int32_t libmpq__read_table_block(
	mpq_archive_s	*mpq_archive,
	uint32_t	*crypt_buf
);

/* function to read listfile from mpq archive. */
int32_t libmpq__read_file_list(
	mpq_archive_s	*mpq_archive
);

uint32_t libmpq__hash_string (
	uint32_t	*buffer,
	const char	*key,
	uint32_t	offset
);

#endif						/* _COMMON_H */
