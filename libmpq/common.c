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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* libmpq main includes. */
#include "mpq.h"
#include "mpq-internal.h"

/* libmpq generic includes. */
#include "extract.h"

static int32_t libmpq__decrypt_table(
	uint32_t	*buffer,
	uint32_t	*hash,
	const char	*key,
	uint32_t	size
);

/* function to initialize decryption buffer. */
int32_t libmpq__decrypt_buffer_init(uint32_t *buffer) {

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
			buffer[index2] = (temp1 | temp2);
		}
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

uint32_t libmpq__hash_string (uint32_t *buffer, const char *key, uint32_t offset) {

	/* some common variables. */
	uint32_t seed1 = 0x7FED7FED;
	uint32_t seed2 = 0xEEEEEEEE;

	/* one key character. */
	uint32_t ch;

	/* prepare seeds. */
	while (*key != 0) {
		ch    = toupper(*key++);
		seed1 = buffer[offset + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}

	return seed1;
}

/* function to decrypt hash/block table of mpq archive. */
static int32_t libmpq__decrypt_table(uint32_t *buffer, uint32_t *hash, const char *key, uint32_t size) {

	/* some common variables. */
	uint32_t seed1;
	uint32_t seed2 = 0xEEEEEEEE;

	/* one key character. */
	uint32_t ch;

	seed1 = libmpq__hash_string (buffer, key, 0x300);

	/* decrypt it. */
	while (size-- > 0) {
		seed2   += buffer[0x400 + (seed1 & 0xFF)];
		ch       = *hash ^ (seed1 + seed2);
		seed1    = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2    = ch + seed2 + (seed2 << 5) + 3;
		*hash++  = ch;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to detect decryption key. */
int32_t libmpq__decrypt_key(uint8_t *in_buf, uint32_t in_size, uint32_t *crypt_buf) {

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

		/* try the first uint32_t's (we exactly know the value). */
		seed1  = temp - crypt_buf[0x400 + i];
		seed2 += crypt_buf[0x400 + (seed1 & 0xFF)];
		ch     = ((uint32_t *)in_buf)[0] ^ (seed1 + seed2);

		if (ch != in_size) {
			continue;
		}

		/* add one because we are decrypting block positions. */
		saveseed1 = seed1 + 1;

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
		if ((ch & 0xFFFF0000) == 0) {

			/* file seed found, so return it. */
			return saveseed1;
		}
	}

	/* if no file seed was found return with error. */
	return LIBMPQ_ERROR_DECRYPT;
}

/* function to decrypt a block. */
int32_t libmpq__decrypt_block(uint8_t *in_buf_raw, uint32_t in_size, uint8_t *out_buf_raw, uint32_t out_size, uint32_t seed, uint32_t *crypt_buf) {

	/* some common variables. */
	uint32_t seed2 = 0xEEEEEEEE;
	uint32_t ch;

	/* we're processing the data 4 bytes at a time. */
	uint32_t *in_buf = (uint32_t *) in_buf_raw;
	uint32_t *out_buf = (uint32_t *) out_buf_raw;

	for (; out_size >= 4; out_size -= 4) {
		seed2     += crypt_buf[0x400 + (seed & 0xFF)];
		ch         = *in_buf++ ^ (seed + seed2);
		seed       = ((~seed << 0x15) + 0x11111111) | (seed >> 0x0B);
		seed2      = ch + seed2 + (seed2 << 5) + 3;
		*out_buf++ = ch;
	}

	/* if there's any data left, just copy it over. */
	if (out_size)
		memcpy (out_buf, in_buf, out_size);

	/* if no error was found, return decrypted bytes. */
	return in_size;
}

/* function to decrypt whole read buffer. */
int32_t libmpq__decrypt_memory(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_count, uint32_t *crypt_buf) {

	/* some common variables. */
	uint32_t i;
	uint32_t seed;
	uint32_t out_offset = sizeof(uint32_t) * (block_count + 1);
	int32_t rb = 0;
	int32_t tb = 0;

	/* check if we don't know the file seed, try to find it. */
	if ((seed = libmpq__decrypt_key(in_buf, out_offset, crypt_buf)) < 0) {

		/* sorry without seed, we cannot extract file. */
		return seed;
	}

	/* decrypt the compressed offset block. */
	if ((tb = libmpq__decrypt_block(in_buf, out_offset, out_buf, out_offset, seed - 1, crypt_buf)) < 0) {

		/* something on decrypt failed. */
		return tb;
	}

	/* check if the block positions are correctly decrypted, we need to cast here, because internally libmpq used only char buffers. */
	if (((uint32_t *)out_buf)[0] != out_offset) {

		/* sorry without compressed offset table, we cannot extract file. */
		return LIBMPQ_ERROR_DECRYPT;
	}

	/* loop through all blocks and decrypt them. */
	for (i = 0; i < block_count; i++) {

		/* decrypt block. */
		if ((rb = libmpq__decrypt_block(in_buf + ((uint32_t *)out_buf)[i], ((uint32_t *)out_buf)[i + 1] - ((uint32_t *)out_buf)[i], out_buf + tb, ((uint32_t *)out_buf)[i + 1] - ((uint32_t *)out_buf)[i], seed + i, crypt_buf)) < 0) {

			/* something on decrypt failed. */
			return rb;
		}

		/* store working buffer size as offset for next block. */
		tb += rb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
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

/* function to decompress or explode whole read buffer. */
int32_t libmpq__decompress_memory(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_size, uint32_t compression_type) {

	/* some common variables. */
	int32_t tb = 0;
	int32_t rb = 0;
	uint32_t i;

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

		/* check if we are working with multiple sectors. */
		if (block_size != out_size) {

			/* loop through all blocks and decompress them. */
			for (i = 0; i < (out_size + block_size - 1) / block_size; i++) {

				/* decompress using mutliple algorithm. */
				if ((rb = libmpq__decompress_block(in_buf + ((uint32_t *)in_buf)[i], ((uint32_t *)in_buf)[i + 1] - ((uint32_t *)in_buf)[i], out_buf + block_size * i, (block_size * i + block_size > out_size) ? out_size - block_size * i : block_size, compression_type)) < 0) {

					/* something on decompression failed. */
					return rb;
				}

				/* save the number of transferred bytes. */
				tb += rb;
			}
		}

		/* check if we are working with single sector. */
		if (block_size == out_size) {

			/* decompress using mutliple algorithm. */
			if ((rb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, compression_type)) < 0) {

				/* something on decompression failed. */
				return rb;
			}

			/* save the number of transferred bytes. */
			tb += rb;
		}
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* function to read decrypted hash table. */
int32_t libmpq__read_table_hash(mpq_archive_s *mpq_archive, uint32_t *crypt_buf) {

	/* some common variables. */
	int32_t rb = 0;
	int32_t tb = 0;

	/* seek in file. */
	if ((tb = lseek(mpq_archive->fd, mpq_archive->mpq_header->hash_table_offset, SEEK_SET)) < 0) {

		/* seek in file failed. */
		return LIBMPQ_ERROR_LSEEK;
	}

	/* read the hash table into the buffer. */
	if ((rb = read(mpq_archive->fd, mpq_archive->mpq_hash, mpq_archive->mpq_header->hash_table_count * sizeof(mpq_hash_s))) < 0) {;

		/* something on read failed. */
		return LIBMPQ_ERROR_READ;
	}

	/* decrypt the hashtable. */
	libmpq__decrypt_table(crypt_buf, (uint32_t *)(mpq_archive->mpq_hash), "(hash table)", mpq_archive->mpq_header->hash_table_count * 4);

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to read decrypted hash table. */
int32_t libmpq__read_table_block(mpq_archive_s *mpq_archive, uint32_t *crypt_buf) {

	/* some common variables. */
	int32_t rb = 0;
	int32_t tb = 0;

	/* seek in file. */
	if ((tb = lseek(mpq_archive->fd, mpq_archive->mpq_header->block_table_offset, SEEK_SET)) < 0) {

		/* seek in file failed. */
		return LIBMPQ_ERROR_LSEEK;
	}

	/* read the block table into the buffer. */
	if ((rb = read(mpq_archive->fd, mpq_archive->mpq_block, mpq_archive->mpq_header->block_table_count * sizeof(mpq_block_s))) < 0) {

		/* something on read failed. */
		return LIBMPQ_ERROR_READ;
	}

	/* decrypt block table only if it is encrypted. */
	if (mpq_archive->mpq_header->header_size != mpq_archive->mpq_block->offset) {

		/* decrypt block table. */
		libmpq__decrypt_table(crypt_buf, (uint32_t *)(mpq_archive->mpq_block), "(block table)", mpq_archive->mpq_header->block_table_count * 4);
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to read listfile from mpq archive. */
int32_t libmpq__read_file_list(mpq_archive_s *mpq_archive) {

	/* TODO: include the cool filelist from last file in mpq archive here. */
	/* some common variables. */
	uint32_t count = 0;
	uint32_t i;

	/* loop through all files in mpq archive. */
	for (i = 0; i < mpq_archive->mpq_header->hash_table_count; i++) {

		/* check if hashtable is valid for this file. */
		if (mpq_archive->mpq_hash[i].block_table_index == LIBMPQ_HASH_FREE) {

			/* continue because this is an empty hash entry. */
			continue;
		}

		/* check if file exists, sizes are correct and block size is above zero. */
		if ((mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].flags & LIBMPQ_FLAG_EXISTS) == 0 ||
		     mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].offset > mpq_archive->mpq_header->archive_size ||
		     mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].compressed_size > mpq_archive->mpq_header->archive_size ||
		     mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].uncompressed_size == 0) {

			/* file does not exist, so nothing to do with that block. */
			continue;
		}

		mpq_archive->mpq_list->block_table_indices[count] = mpq_archive->mpq_hash[i].block_table_index;
		mpq_archive->mpq_list->hash_table_indices[count]  = i;

		/* increase file counter. */
		count++;
	}

	/* save the number of files. */
	mpq_archive->files = count;

	/* some common variables for heap sort. */
	uint32_t child_width = 8;
	uint32_t parent      = 0;
	uint32_t n           = mpq_archive->files;
	uint32_t m           = (n + (child_width - 2)) / child_width;
	uint32_t child;
	uint32_t w;
	uint32_t max;
	uint32_t temp_block;
	uint32_t temp_hash;
	char *temp_file;

	/* sort the array using heap sort (i use a non-recursive sort algorithm because this should be faster due to the fact of the relational arrays) */
	while (TRUE) {

		/* part 1 - heap construction. */
		if (m != 0) {

			/* last value. */
			parent     = --m;

			/* value to sift. */
			temp_block = mpq_archive->mpq_list->block_table_indices[parent];
			temp_hash  = mpq_archive->mpq_list->hash_table_indices[parent];
			temp_file  = mpq_archive->mpq_list->file_names[parent];
		} else {

			/* part 2 - real sort. */
			if (--n) {

				/* sift value from heap end. */
				temp_block                                    = mpq_archive->mpq_list->block_table_indices[n];
				temp_hash                                     = mpq_archive->mpq_list->hash_table_indices[n];
				temp_file                                     = mpq_archive->mpq_list->file_names[n];

				/* top of heap after heap in. */
				mpq_archive->mpq_list->block_table_indices[n] = mpq_archive->mpq_list->block_table_indices[0];
				mpq_archive->mpq_list->hash_table_indices[n]  = mpq_archive->mpq_list->hash_table_indices[0];
				mpq_archive->mpq_list->file_names[n]          = mpq_archive->mpq_list->file_names[0];

				/* move sorted area. */
				parent                                        = 0;
			} else {

				/* break execution, because sort finished. */
				break;
			}
		}

		/* first child - loop until end of heap. */
		while ((child = parent * child_width + 1) < n) {

			/* number of childs. */
			w = n - child < child_width ? n - child : child_width;

			/* search highest child. */
			for (max = 0, i = 1; i < w; ++i) {

				/* check if highest child found. */
				if (mpq_archive->mpq_list->block_table_indices[child + i] > mpq_archive->mpq_list->block_table_indices[child + max]) {

					/* store highest child. */
					max = i;
				}
			}

			/* increase child. */
			child += max;

			/* check if no more higher child as value to sift exist. */
			if (mpq_archive->mpq_list->block_table_indices[child] <= temp_block) {

				/* nothing more to sort, so break. */
				break;
			}

			/* move highest child above. */
			mpq_archive->mpq_list->block_table_indices[parent] = mpq_archive->mpq_list->block_table_indices[child];
			mpq_archive->mpq_list->hash_table_indices[parent]  = mpq_archive->mpq_list->hash_table_indices[child];
			mpq_archive->mpq_list->file_names[parent]          = mpq_archive->mpq_list->file_names[child];

			/* search next level. */
			parent = child;
		}

		/* store sifted value. */
		mpq_archive->mpq_list->block_table_indices[parent] = temp_block;
		mpq_archive->mpq_list->hash_table_indices[parent]  = temp_hash;
		mpq_archive->mpq_list->file_names[parent]          = temp_file;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}
