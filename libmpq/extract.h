/*
 *  extract.h -- header for the extraction functions used by mpq-tools.
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

#ifndef _EXTRACT_H
#define _EXTRACT_H

/* define compression types for multilpe compressions. */
#define LIBMPQ_COMPRESSION_HUFFMANN		0x01		/* huffmann compression. (used on wave files only and introduced in starcraft) */
#define LIBMPQ_COMPRESSION_ZLIB			0x02		/* zlib compression. (introduced in warcraft 3) */
#define LIBMPQ_COMPRESSION_PKWARE		0x08		/* pkware dcl compression. (first used compression algorithm) */
#define LIBMPQ_COMPRESSION_BZIP2		0x10		/* bzip compression. (introduced in warcraft 3 - the frozen throne) */
#define LIBMPQ_COMPRESSION_WAVE_MONO		0x40		/* adpcm 4:1 compression. (introduced in starcraft) */
#define LIBMPQ_COMPRESSION_WAVE_STEREO		0x80		/* adpcm 4:1 compression. (introduced in starcraft) */

/* table for decompression functions. */
typedef int		(*DECOMPRESS)(unsigned char *, int *, unsigned char *, int);
typedef struct {
	unsigned int	mask;			/* decompression bit. */
	DECOMPRESS	decompress;		/* decompression function. */
} decompress_table_s;

/*
 *  huffmann decompression routine, the in_length parameter is not used,
 *  but needs to be specified due to compatibility reasons.
 *
 *  1500F5F0
 */
extern int libmpq__decompress_huffman(
	unsigned char	*out_buf,
	int		*out_length,
	unsigned char	*in_buf,
	int		in_length
);

/* decompression using zlib. */
extern int libmpq__decompress_zlib(
	unsigned char	*out_buf,
	int		*out_length,
	unsigned char	*in_buf,
	int		in_length
);

/* decompression using pkzip. */
extern int libmpq__decompress_pkzip(
	unsigned char	*out_buf,
	int		*out_length,
	unsigned char	*in_buf,
	int		in_length
);

/* decompression using bzip2. */
extern int libmpq__decompress_bzip2(
	unsigned char	*out_buf,
	int		*out_length,
	unsigned char	*in_buf,
	int		in_length
);

/* decompression using wave. (1 channel) */
extern int libmpq__decompress_wave_mono(
	unsigned char	*out_buf,
	int		*out_length,
	unsigned char	*in_buf,
	int		in_length
);

/* decompression using wave. (2 channels) */
extern int libmpq__decompress_wave_stereo(
	unsigned char	*out_buf,
	int		*out_length,
	unsigned char	*in_buf,
	int		in_length
);

/* decompression using multiple of the above algorithm. */
extern int libmpq__decompress_multi(
	unsigned char	*out_buf,
	int		*pout_length,
	unsigned char	*in_buf,
	int		in_length
);

/* table with decompression bits and functions. */
static decompress_table_s dcmp_table[] = {
	{0x01, libmpq__decompress_huffman},	/* decompression using huffman trees. */
	{0x02, libmpq__decompress_zlib},	/* decompression with the zlib library. */
	{0x08, libmpq__decompress_pkzip},	/* decompression with pkware data compression library. */
	{0x10, libmpq__decompress_bzip2},	/* decompression with bzip2 library. */
	{0x40, libmpq__decompress_wave_mono},	/* decompression for mono waves. */
	{0x80, libmpq__decompress_wave_stereo}	/* decompression for stereo waves. */
};

#endif						/* _EXTRACT_H */
