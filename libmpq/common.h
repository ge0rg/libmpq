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

/* function to decrypt a mpq block. */
int libmpq__decrypt_mpq_block(
	unsigned int	*buffer,
	unsigned int	*block,
	unsigned int	size,
	unsigned int	seed1
);

/* function to decrypt hash table of mpq archive. */
int libmpq__decrypt_table_hash(
	unsigned int	*buffer,
	unsigned int	*hash,
	unsigned char	*key,
	unsigned int	size
);

/* function to decrypt hash table of mpq archive. */
int libmpq__decrypt_table_block(
	unsigned int	*buffer,
	unsigned int	*block,
	unsigned char	*key,
	unsigned int	size
);

/* function to detect decryption key. */
int libmpq__decrypt_key(
	unsigned int	*buffer,
	unsigned int	*block,
	unsigned int	decrypted
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

/* function to read decrypted hash table. */
int libmpq__read_table_hash(
	mpq_archive_s	*mpq_archive
);

/* function to read decrypted hash table. */
int libmpq__read_table_block(
	mpq_archive_s	*mpq_archive
);

/* function to read listfile from mpq archive. */
int libmpq__read_file_list(
	mpq_archive_s	*mpq_archive
);

/* function to read variable block positions used in compressed files. */
int libmpq__read_file_offset(
	mpq_archive_s	*mpq_archive,
	unsigned int	block_count
);

#endif						/* _COMMON_H */
