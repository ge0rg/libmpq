/*
 *  extract.h -- header for the extraction functions used by mpq-tools.
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

#ifndef _EXTRACT_H
#define _EXTRACT_H

/* table for decompression functions. */
typedef int32_t		(*DECOMPRESS)(uint8_t *, int32_t *, uint8_t *, int32_t);
typedef struct {
	uint32_t	mask;			/* decompression bit. */
	DECOMPRESS	decompress;		/* decompression function. */
} decompress_table;

/* decompression using pkzip. */
extern int32_t libmpq__decompress_pkzip(
	uint8_t		*out_buf,
	int32_t		*out_length,
	uint8_t		*in_buf,
	int32_t		in_length
);

/* decompression using zlib. */
extern int32_t libmpq__decompress_zlib(
	uint8_t		*out_buf,
	int32_t		*out_length,
	uint8_t		*in_buf,
	int32_t		in_length
);

/*
 *  huffmann decompression routine, the in_length parameter is not used,
 *  but needs to be specified due to compatibility reasons.
 *
 *  1500F5F0
 */
extern int32_t libmpq__decompress_huffman(
	uint8_t		*out_buf,
	int32_t		*out_length,
	uint8_t		*in_buf,
	int32_t		in_length
);

/* decompression using wave. (2 channels) */
extern int32_t libmpq__decompress_wave_stereo(
	uint8_t		*out_buf,
	int32_t		*out_length,
	uint8_t		*in_buf,
	int32_t		in_length
);

/* decompression using wave. (1 channel) */
extern int32_t libmpq__decompress_wave_mono(
	uint8_t		*out_buf,
	int32_t		*out_length,
	uint8_t		*in_buf,
	int32_t		in_length
);

/* decompression using multiple of the above algorithm. */
extern int32_t libmpq__decompress_multi(
	uint8_t		*out_buf,
	int32_t		*pout_length,
	uint8_t		*in_buf,
	int32_t		in_length
);

/* table with decompression bits and functions. */
static decompress_table dcmp_table[] = {
	{0x08, libmpq__decompress_pkzip},	/* decompression with pkware data compression library. */
	{0x02, libmpq__decompress_zlib},	/* decompression with the zlib library. */
	{0x01, libmpq__decompress_huffman},	/* huffmann decompression. */
	{0x80, libmpq__decompress_wave_stereo},	/* wave decompression for stereo waves. */
	{0x40, libmpq__decompress_wave_mono}	/* wave decompression for mono waves. */
};

#endif						/* _EXTRACT_H */
