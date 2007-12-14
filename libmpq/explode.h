/*
 *  explode.h -- header file for pkware data decompression library
 *               used by mpq-tools.
 *
 *  Copyright (c) 2003-2007 Maik Broemme <mbroemme@plusserver.de>
 *
 *  This source was adepted from the C++ version of pklib.h included
 *  in stormlib. The C++ version belongs to the following authors:
 *
 *  Ladislav Zezula <ladik@zezula.net>
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

#ifndef _EXPLODE_H
#define _EXPLODE_H

/* define compression constants and return values. */
#define LIBMPQ_PKZIP_CMP_BINARY			0		/* binary compression. */
#define LIBMPQ_PKZIP_CMP_ASCII			1		/* ascii compression. */
#define LIBMPQ_PKZIP_CMP_NO_ERROR		0
#define LIBMPQ_PKZIP_CMP_INV_DICTSIZE		1
#define LIBMPQ_PKZIP_CMP_INV_MODE		2
#define LIBMPQ_PKZIP_CMP_BAD_DATA		3
#define LIBMPQ_PKZIP_CMP_ABORT			4

/* compression structure. */
typedef struct {
	unsigned int	offs0000;		/* 0000 - start. */
	unsigned int	cmp_type;		/* 0004 - compression type (binary or ascii). */
	unsigned int	out_pos;		/* 0008 - position in output buffer. */
	unsigned int	dsize_bits;		/* 000C - dict size (4, 5, 6 for 0x400, 0x800, 0x1000). */
	unsigned int	dsize_mask;		/* 0010 - dict size bitmask (0x0F, 0x1F, 0x3F for 0x400, 0x800, 0x1000). */
	unsigned int	bit_buf;		/* 0014 - 16-bit buffer for processing input data. */
	unsigned int	extra_bits;		/* 0018 - number of extra (above 8) bits in bit buffer. */
	unsigned int	in_pos;			/* 001C - position in in_buf. */
	unsigned int	in_bytes;		/* 0020 - number of bytes in input buffer. */
	void		*param;			/* 0024 - custom parameter. */
	unsigned int	(*read_buf)(char *buf, unsigned int *size, void *param);	/* 0028 offset.*/
	void		(*write_buf)(char *buf, unsigned int *size, void *param);	/* 002C offset. */
	unsigned char	out_buf[0x2000];	/* 0030 - output circle buffer, starting position is 0x1000. */
	unsigned char	offs_2030[0x204];	/* 2030 - whats that? */
	unsigned char	in_buf[0x800];		/* 2234 - buffer for data to be decompressed. */
	unsigned char	pos1[0x100];		/* 2A34 - positions in buffers. */
	unsigned char	pos2[0x100];		/* 2B34 - positions in buffers. */
	unsigned char	offs_2c34[0x100];	/* 2C34 - buffer. */
	unsigned char	offs_2d34[0x100];	/* 2D34 - buffer. */
	unsigned char	offs_2e34[0x80];	/* 2EB4 - buffer. */
	unsigned char	offs_2eb4[0x100];	/* 2EB4 - buffer. */
	unsigned char	bits_asc[0x100];	/* 2FB4 - buffer. */
	unsigned char	dist_bits[0x40];	/* 30B4 - numbers of bytes to skip copied block length. */
	unsigned char	slen_bits[0x10];	/* 30F4 - numbers of bits for skip copied block length. */
	unsigned char	clen_bits[0x10];	/* 3104 - number of valid bits for copied block. */
	unsigned short	len_base[0x10];		/* 3114 - buffer. */
} __attribute__ ((packed)) pkzip_data_cmp;

/* data structure. */
typedef struct {
	unsigned char	*in_buf;		/* pointer to input data buffer. */
	unsigned int	in_pos;			/* current offset in input data buffer. */
	int		in_bytes;		/* number of bytes in the input buffer. */
	unsigned char	*out_buf;		/* pointer to output data buffer. */
	unsigned int	out_pos;		/* position in the output buffer. */
	int		max_out;		/* maximum number of bytes in the output buffer. */
} pkzip_data;

/*
 *  skips given number of bits in bit buffer, result is stored in mpq_pkzip->bit_buf
 *  and if no data in input buffer, returns zero.
 */
int libmpq__pkzip_skip_bit(
	pkzip_data_cmp	*mpq_pkzip,
	unsigned int	bits
);

/* generate decode tables for decryption. */
void libmpq__pkzip_generate_tables_decode(
	int		count,
	unsigned char	*bits,
	unsigned char	*code,
	unsigned char	*buf2
);

/* generate tables for ascii decompression. */
void libmpq__pkzip_generate_tables_ascii(
	pkzip_data_cmp	*mpq_pkzip
);

/*                      
 *  decompress the imploded data using coded literals.
 *
 *  returns: 0x000 - 0x0FF : one byte from compressed file.
 *           0x100 - 0x305 : copy previous block. (0x100 = 1 byte)
 *           0x306         : out of buffer?
 */
unsigned int libmpq__pkzip_decode_literal(
	pkzip_data_cmp	*mpq_pkzip
);

/* retrieves the number of bytes to move back. */
unsigned int libmpq__pkzip_decode_distance(
	pkzip_data_cmp	*mpq_pkzip,
	unsigned int	length
);

/*
 *  function loads data from the input buffer used by mpq_pkzip
 *  "implode" and "explode" function as user defined callback and
 *  returns number of bytes loaded.
 *
 *  char		*buf	- pointer to a buffer where to store loaded data.
 *  unsigned int	*size	- maximum number of bytes to read.
 *  void		*param	- custom pointer, parameter of implode/explode.
 */
unsigned int libmpq__pkzip_data_read_input(
	char		*buf,
	unsigned int	*size,
	void		*param
);

/*
 *  function for store output data used by mpq_pkzip "implode" and
 *  "explode" as userdefined callback.
 *
 *  char		*buf	- pointer to data to be written.
 *  unsigned int	*size	- number of bytes to write.
 *  void		*param	- custom pointer, parameter of implode/explode.
 */
void libmpq__pkzip_data_write_output(
	char		*buf,
	unsigned int	*size,
	void		*param
);

/* extract data from input stream. */
unsigned int libmpq__pkzip_expand(
	pkzip_data_cmp	*mpq_pkzip
);

/* decompress the stream using pkzip compression. */
unsigned int libmpq__do_decompress_pkzip(
	unsigned char	*work_buf,
	void		*param
);

#endif						/* _EXPLODE_H */
