/*
 *  common.c -- shared functions used by mpq-tools.
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
#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* libmpq main includes. */
#include "mpq.h"
#include "mpq-internal.h"

/* libmpq generic includes. */
#include "extract.h"

#include "common.h"

/* the global shared decryption buffer. it's set up by libmpq__decrypt_buffer_init()
 * and killed by libmpq__decrypt_buffer_deinit().
 */
static uint32_t *crypt_buf;

/* function to initialize decryption buffer. */
int32_t libmpq__decrypt_buffer_init() {
	crypt_buf = malloc(sizeof(uint32_t) * LIBMPQ_BUFFER_SIZE);

	if (!crypt_buf)
		return LIBMPQ_ERROR_MALLOC;

	/* some common variables. */
	uint32_t seed   = 0x00100001;
	uint32_t index1 = 0;
	uint32_t index2 = 0;
	uint32_t i;

	/* initialize the decryption buffer. */
	for (index1 = 0; index1 < 0x100; index1++) {
		for(index2 = index1, i = 0; i < 5; i++, index2 += 0x100) {

			/* some common variables. */
			uint32_t temp1, temp2;

			/* temporary copy. */
			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp1 = (seed & 0xFFFF) << 0x10;

			/* temporary copy. */
			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp2 = (seed & 0xFFFF);

			/* assign buffer. */
			crypt_buf[index2] = (temp1 | temp2);
		}
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

int32_t libmpq__decrypt_buffer_deinit() {
	free(crypt_buf);

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to return the hash to a given string. */
uint32_t libmpq__hash_string(const char *key, uint32_t offset) {

	/* some common variables. */
	uint32_t seed1 = 0x7FED7FED;
	uint32_t seed2 = 0xEEEEEEEE;

	/* one key character. */
	uint32_t ch;

	/* prepare seeds. */
	while (*key != 0) {
		ch    = toupper(*key++);
		seed1 = crypt_buf[offset + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}

	return seed1;
}

/* function to decrypt hash/block table of mpq archive. */
int32_t libmpq__decrypt_table(uint32_t *hash, const char *key, uint32_t size) {

	/* some common variables. */
	uint32_t seed1;
	uint32_t seed2 = 0xEEEEEEEE;

	/* one key character. */
	uint32_t ch;

	seed1 = libmpq__hash_string(key, 0x300);

	/* decrypt it. */
	while (size-- > 0) {
		seed2   += crypt_buf[0x400 + (seed1 & 0xFF)];
		ch       = *hash ^ (seed1 + seed2);
		seed1    = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2    = ch + seed2 + (seed2 << 5) + 3;
		*hash++  = ch;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to detect decryption key. */
int32_t libmpq__decrypt_key(uint8_t *in_buf, uint32_t in_size, uint32_t block_size) {

	/* some common variables. */
	uint32_t saveseed1;

	/* temp = seed1 + seed2 */
	uint32_t temp;
	uint32_t i = 0;

	/* temp = seed1 + buffer[0x400 + (seed1 & 0xFF)] */
	temp = (*(uint32_t *)in_buf ^ in_size) - 0xEEEEEEEE;

	/* try all 255 possibilities. */
	for (i = 0; i < 0x100; i++) {

		/* some common variables. */
		uint32_t seed1;
		uint32_t seed2 = 0xEEEEEEEE;
		uint32_t ch;
		uint32_t ch2;

		/* try the first uint32_t's (we exactly know the value). */
		seed1  = temp - crypt_buf[0x400 + i];
		seed2 += crypt_buf[0x400 + (seed1 & 0xFF)];
		ch     = ((uint32_t *)in_buf)[0] ^ (seed1 + seed2);

		if (ch != in_size) {
			continue;
		}

		/* add one because we are decrypting block positions. */
		saveseed1 = seed1 + 1;
		ch2       = ch;

		/*
		 *  if ok, continue and test the second value. we don't know exactly the value,
		 *  but we know that the second one has lower 16 bits set to zero (no compressed
		 *  block is larger than 0xFFFF bytes)
		 */
		seed1  = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2  = ch + seed2 + (seed2 << 5) + 3;
		seed2 += crypt_buf[0x400 + (seed1 & 0xFF)];
		ch     = ((uint32_t *)in_buf)[1] ^ (seed1 + seed2);

		/* check if we found the file seed. */
		if ((ch - ch2) <= block_size) {

			/* file seed found, so return it. */
			return saveseed1;
		}
	}

	/* if no file seed was found return with error. */
	return LIBMPQ_ERROR_DECRYPT;
}

/* function to decrypt a block. */
int32_t libmpq__decrypt_block(uint32_t *in_buf, uint32_t in_size, uint32_t seed) {

	/* some common variables. */
	uint32_t seed2 = 0xEEEEEEEE;
	uint32_t ch;
	uint32_t out_size = in_size;

	/* we're processing the data 4 bytes at a time. */
	for (; in_size >= 4; in_size -= 4) {
		seed2    += crypt_buf[0x400 + (seed & 0xFF)];
		ch        = *in_buf ^ (seed + seed2);
		seed      = ((~seed << 0x15) + 0x11111111) | (seed >> 0x0B);
		seed2     = ch + seed2 + (seed2 << 5) + 3;
		*in_buf++ = ch;
	}

	/* if no error was found, return decrypted bytes. */
	return out_size;
}

/* function to decompress or explode a block from mpq archive. */
int32_t libmpq__decompress_block(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t compression_type) {

	/* some common variables. */
	int32_t tb = 0;

	/* check if buffer is not compressed. */
	if (compression_type == LIBMPQ_FLAG_COMPRESS_NONE) {

		/* no compressed data, so copy input buffer to output buffer. */
		memcpy(out_buf, in_buf, out_size);

		/* store number of bytes copied. */
		tb = out_size;
	}

	/* check if one compression mode is used. */
	if (compression_type == LIBMPQ_FLAG_COMPRESS_PKWARE ||
	    compression_type == LIBMPQ_FLAG_COMPRESS_MULTI) {

		/* check if block is really compressed, some blocks have set the compression flag, but are not compressed. */
		if (in_size < out_size) {

			/* check if we are using pkware compression algorithm. */
			if (compression_type == LIBMPQ_FLAG_COMPRESS_PKWARE) {

				/* decompress using pkzip. */
				if ((tb = libmpq__decompress_pkzip(in_buf, in_size, out_buf, out_size)) < 0) {

					/* something on decompression failed. */
					return tb;
				}
			}

			/* check if we are using multiple compression algorithm. */
			if (compression_type == LIBMPQ_FLAG_COMPRESS_MULTI) {

				/*
				 *  check if it is a file compressed by blizzard's multiple compression, note that storm.dll
				 *  version 1.0.9 distributed with warcraft 3 passes the full path name of the opened archive
				 *  as the new last parameter.
				 */
				if ((tb = libmpq__decompress_multi(in_buf, in_size, out_buf, out_size)) < 0) {

					/* something on decompression failed. */
					return tb;
				}
			}
		} else {

			/* block has set compression flag, but is not compressed, so copy data to output buffer. */
			memcpy(out_buf, in_buf, out_size);

			/* save the number of transferred bytes. */
			tb += in_size;
		}
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}
