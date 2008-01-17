/*
 *  extract.c -- global extracting function for all known file compressions
 *               in a mpq archive.
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

/* generic includes. */
#include <stdlib.h>
#include <string.h>

/* zlib includes. */
#include <zlib.h>

/* libmpq main includes. */
#include "mpq.h"

/* libmpq generic includes. */
#include "explode.h"
#include "extract.h"
#include "huffman.h"
#include "wave.h"

/* table with decompression bits and functions. */
static decompress_table_s dcmp_table[] = {
	{0x01, libmpq__decompress_huffman},	/* decompression using huffman trees. */
	{0x02, libmpq__decompress_zlib},	/* decompression with the zlib library. */
	{0x08, libmpq__decompress_pkzip},	/* decompression with pkware data compression library. */
	{0x10, libmpq__decompress_bzip2},	/* decompression with bzip2 library. */
	{0x40, libmpq__decompress_wave_mono},	/* decompression for mono waves. */
	{0x80, libmpq__decompress_wave_stereo}	/* decompression for stereo waves. */
};

/* this function decompress a stream using huffman algorithm. */
int libmpq__decompress_huffman(unsigned char *out_buf, int *out_length, unsigned char *in_buf, int in_length) {

	/* huffman tree information. */
	struct huffman_tree_s *ht         = malloc(sizeof(struct huffman_tree_s));
	struct huffman_input_stream_s *is = malloc(sizeof(struct huffman_input_stream_s));
	struct huffman_tree_item_s *hi    = malloc(sizeof(struct huffman_tree_item_s));

	/* cleanup structures. */
	memset(ht, 0, sizeof(struct huffman_tree_s));
	memset(is, 0, sizeof(struct huffman_input_stream_s));
	memset(hi, 0, sizeof(struct huffman_tree_item_s));

	/* initialize input stream. */
	is->bit_buf  = *(unsigned int *)in_buf;
	in_buf      += sizeof(int);
	is->in_buf   = (unsigned char *)in_buf;
	is->bits     = 32;

	/* initialize the huffman tree for decompression. */
	libmpq__huffman_tree_init(ht, hi, LIBMPQ_HUFF_DECOMPRESS);

	/* save the number of copied bytes. */
	*out_length = libmpq__do_decompress_huffman(ht, is, out_buf, *out_length);

	/* free allocated memory. */
	free(hi);
	free(is);
	free(ht);

	/* if no error was found, return zero. */
	return 0;
}

/* this function decompress a stream using zlib algorithm. */
int libmpq__decompress_zlib(unsigned char *out_buf, int *out_length, unsigned char *in_buf, int in_length) {

	/* stream information for zlib. */
	z_stream z;
	int result;

	/* fill the stream structure for zlib. */
	z.next_in   = (Bytef *)in_buf;
	z.avail_in  = (uInt)in_length;
	z.total_in  = in_length;
	z.next_out  = (Bytef *)out_buf;
	z.avail_out = *out_length;
	z.total_out = 0;
	z.zalloc    = NULL;
	z.zfree     = NULL;

	/* initialize the decompression structure, storm.dll uses zlib version 1.1.3. */
	if ((result = inflateInit(&z)) == 0) {

		/* call zlib to decompress the data. */
		result = inflate(&z, Z_FINISH);
		*out_length = z.total_out;
		inflateEnd(&z);
	}

	/* return zlib status. */
	return result;
}

/* this function decompress a stream using pkzip algorithm. */
int libmpq__decompress_pkzip(unsigned char *out_buf, int *out_length, unsigned char *in_buf, int in_length) {

	/* data information. */
	pkzip_data_s info;

	/* work buffer. */
	unsigned char *work_buf = malloc(sizeof(pkzip_cmp_s));

	/* fill data information structure. */
	info.in_buf   = in_buf;
	info.in_pos   = 0;
	info.in_bytes = in_length;
	info.out_buf  = out_buf;
	info.out_pos  = 0;
	info.max_out  = *out_length;

	/* do the decompression. */
	libmpq__do_decompress_pkzip(work_buf, &info);
	*out_length = info.out_pos;

	/* free allocated memory. */
	free(work_buf);

	/* if no error was found, return zero. */
	return 0;
}

/* this function decompress a stream using bzip2 library. */
int libmpq__decompress_bzip2(unsigned char *out_buf, int *out_length, unsigned char *in_buf, int in_length) {

	/* TODO: add bzip2 decompression here. */
	/* if no error was found, return zero. */
	return 0;
}

/* this function decompress a stream using wave algorithm. (1 channel) */
int libmpq__decompress_wave_mono(unsigned char *out_buf, int *out_length, unsigned char *in_buf, int in_length) {

	/* save the number of copied bytes. */
	*out_length = libmpq__do_decompress_wave(out_buf, *out_length, in_buf, in_length, 1);

	/* if no error was found, return zero. */
	return 0;
}

/* this function decompress a stream using wave algorithm. (2 channels) */
int libmpq__decompress_wave_stereo(unsigned char *out_buf, int *out_length, unsigned char *in_buf, int in_length) {

	/* save the number of copied bytes. */
	*out_length = libmpq__do_decompress_wave(out_buf, *out_length, in_buf, in_length, 2);

	/* if no error was found, return zero. */
	return 0;
}

/* this function decompress a stream using a combination of the other compression algorithm. */
int libmpq__decompress_multi(unsigned char *out_buf, int *pout_length, unsigned char *in_buf, int in_length) {

	/* temporary storage for decompressed data. */
	unsigned char *temp_buf  = NULL;

	/* where to store decompressed data. */
	unsigned char *work_buf  = NULL;

	/* for storage number of output bytes. */
	int out_length = *pout_length;

	/* counter for every use. */
	unsigned int count   = 0;
	unsigned int entries = (sizeof(dcmp_table) / sizeof(decompress_table_s));

	/* decompressions applied to the block. */
	unsigned char fDecompressions1;

	/* another copy of decompressions applied to the block. */
	unsigned char fDecompressions2;

	/* counter for the loops. */
	unsigned int i;

	/* check if the input length is the same as output, so do nothing. */
	if (in_length == out_length) {

		/* check if buffer have same data. */
		if (in_buf == out_buf) {
			return 0;
		}

		/* copy buffer to target. */
		memcpy(out_buf, in_buf, in_length);
		return 0;
	}

	/* get applied compression types and decrement data length. */
	fDecompressions1 = fDecompressions2 = *in_buf++;
	in_length--;

	/* search decompression table type and get all types of compression. */
	for (i = 0; i < entries; i++) {

		/* check if have to apply this decompression. */
		if (fDecompressions1 & dcmp_table[i].mask) {
			count++;
		}

		/* clear this flag from temporary variable. */
		fDecompressions2 &= ~dcmp_table[i].mask;
	}

	/* check if there is some method unhandled. (e.g. compressed by future versions) */
	if (fDecompressions2 != 0) {
		/* TODO: Add an error handler here. */
		/* printf("Unknown Compression\n"); */
		return 1;
	}

	/* check if there is more than only one compression, we have to allocate extra buffer. */
	if (count >= 2) {
		temp_buf = malloc(out_length);
	}

	/* apply all decompressions. */
	for (i = 0, count = 0; i < entries; i++) {

		/* check if not used this kind of compression. */
		if (fDecompressions1 & dcmp_table[i].mask) {

			/* if odd case, use target buffer for output, otherwise use allocated tempbuf. */
			work_buf   = (count++ & 1) ? temp_buf : out_buf;
			out_length = *pout_length;

			/* decompress buffer using corresponding function. */
			dcmp_table[i].decompress(work_buf, &out_length, in_buf, in_length);

			/* move output length to source length for next compression. */
			in_length = out_length;
			in_buf    = work_buf;
		}
	}

	/* check if output buffer is not the same like target buffer, so we have to copy data. */
	if (work_buf != out_buf) {
		memcpy(out_buf, in_buf, out_length);
	}

	/* save copied bytes. */
	*pout_length = out_length;

	/* delete temporary buffer, if necessary. */
	if (temp_buf != NULL) {
		free(temp_buf);
	}

	/* if no error was found, return zero. */
	return 0;
}
