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

/* function to decrypt a mpq block. */
int libmpq__decrypt_mpq_block(
	mpq_archive	*mpq_a,
	unsigned int	*block,
	unsigned int	length,
	unsigned int	seed1
);

/* function to decrypt hash table of mpq archive. */
int libmpq__decrypt_table_hash(
	mpq_archive	*mpq_a,
	unsigned char	*pbKey
);

/* function to decrypt hash table of mpq archive. */
int libmpq__decrypt_table_block(
	mpq_archive	*mpq_a,
	unsigned char	*pbKey
);

/* function to detect decryption key. */
int libmpq__decrypt_key(
	mpq_archive	*mpq_a,
	unsigned int	*block,
	unsigned int	decrypted
);

/* function to initialize decryption buffer. */
int libmpq__decrypt_buffer_init(
	mpq_archive	*mpq_a
);

/* function to read decrypted hash table. */
int libmpq__read_table_hash(
	mpq_archive	*mpq_a
);

/* function to read decrypted hash table. */
int libmpq__read_table_block(
	mpq_archive	*mpq_a
);

/* function to read decrypted block. */
int libmpq__read_file_block(
	mpq_archive	*mpq_a,
	mpq_file	*mpq_f,
	unsigned int	blockpos,
	unsigned char	*buffer,
	unsigned int	blockbytes
);

/* function to read file from mpq archive. */
int libmpq__read_file_mpq(
	mpq_archive	*mpq_a,
	mpq_file	*mpq_f,
	unsigned int	filepos,
	unsigned char	*buffer,
	unsigned int	toread
);

#endif						/* _COMMON_H */
