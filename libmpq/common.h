/*
 *  common.h -- header functions used by mpq-tools.
 *
 *  Copyright (c) 2003-2007 Maik Broemme <mbroemme@plusserver.de>
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

/* function to decrypt a mpq block.. */
int32_t libmpq__decrypt_mpq_block(
	mpq_archive	*mpq_a,
	uint32_t	*block,
	uint32_t	length,
	uint32_t	seed1
);

/* function to decrypt hash table of mpq archive. */
int32_t libmpq__decrypt_table_hash(
	mpq_archive	*mpq_a,
	uint8_t		*pbKey
);

/* function to decrypt hash table of mpq archive. */
int32_t libmpq__decrypt_table_block(
	mpq_archive	*mpq_a,
	uint8_t		*pbKey
);

/* function to detect decryption key. */
int32_t libmpq__decrypt_key(
	mpq_archive	*mpq_a,
	uint32_t	*block,
	uint32_t	decrypted
);

/* function to initialize decryption buffer. */
int32_t libmpq__decrypt_init_buffer(
	mpq_archive	*mpq_a
);

/* function to read decrypted hash table. */
int32_t libmpq__read_table_hash(
	mpq_archive	*mpq_a
);

/* function to read decrypted hash table. */
int32_t libmpq__read_table_block(
	mpq_archive	*mpq_a
);

/* function to read decrypted block. */
int32_t libmpq__read_file_block(
	mpq_archive	*mpq_a,
	mpq_file	*mpq_f,
	uint32_t	blockpos,
	uint8_t		*buffer,
	uint32_t	blockbytes
);

/* function to read file from mpq archive. */
int32_t libmpq__read_file_mpq(
	mpq_archive	*mpq_a,
	mpq_file	*mpq_f,
	uint32_t	filepos,
	uint8_t		*buffer,
	uint32_t	toread
);

#endif						/* _COMMON_H */
