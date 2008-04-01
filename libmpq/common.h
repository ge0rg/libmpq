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
int libmpq__decrypt_buffer_init(
	unsigned int	*buffer
);

/* function to detect decryption key. */
int libmpq__decrypt_key(
	unsigned char	*in_buf,
	unsigned int	in_size,
	unsigned char	*out_buf,
	unsigned int	out_size,
	unsigned int	*crypt_buf
);

/* function to decrypt a block. */
int libmpq__decrypt_block(
	unsigned char	*in_buf,
	unsigned int	in_size,
	unsigned char	*out_buf,
	unsigned int	out_size,
	unsigned int	seed,
	unsigned int	*crypt_buf
);

/* function to decrypt whole read buffer. */
int libmpq__decrypt_memory(
	unsigned char	*in_buf,
	unsigned int	in_size,
	unsigned char	*out_buf,
	unsigned int	out_size,
	unsigned int	block_count,
	unsigned int	*crypt_buf
);

/* function to decompress or explode block from archive. */
int libmpq__decompress_block(
	unsigned char	*in_buf,
	unsigned int	in_size,
	unsigned char	*out_buf,
	unsigned int	out_size,
	unsigned int	compression_type
);

/* function to decompress or explode whole read buffer. */
int libmpq__decompress_memory(
	unsigned char	*in_buf,
	unsigned int	in_size,
	unsigned char	*out_buf,
	unsigned int	out_size,
	unsigned int	block_size,
	unsigned int	compression_type
);

/* function to read and decrypt hash table. */
int libmpq__read_table_hash(
	mpq_archive_s	*mpq_archive,
	unsigned int	*crypt_buf
);

/* function to read and decrypt hash table. */
int libmpq__read_table_block(
	mpq_archive_s	*mpq_archive,
	unsigned int	*crypt_buf
);

/* function to read listfile from mpq archive. */
int libmpq__read_file_list(
	mpq_archive_s	*mpq_archive
);

unsigned int libmpq__hash_string (
	unsigned int	*buffer,
	const char	*key,
	unsigned int offset
);

#endif						/* _COMMON_H */
