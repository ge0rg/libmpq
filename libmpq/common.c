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

/* function to decrypt a mpq block.. */
int libmpq__decrypt_mpq_block(mpq_archive_s *mpq_archive, unsigned int *block, unsigned int length, unsigned int seed1) {

	/* some common variables. */
	unsigned int seed2 = 0xEEEEEEEE;
	unsigned int ch;

	/* round to unsigned int's. */
	length >>= 2;
	while (length-- > 0) {
		seed2    += mpq_archive->mpq_buffer[0x400 + (seed1 & 0xFF)];
		ch        = *block ^ (seed1 + seed2);
		seed1     = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2     = ch + seed2 + (seed2 << 5) + 3;
		*block++  = ch;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to decrypt hash table of mpq archive. */
int libmpq__decrypt_table_hash(mpq_archive_s *mpq_archive, unsigned char *pbKey) {

	/* some common variables. */
	unsigned int seed1     = 0x7FED7FED;
	unsigned int seed2     = 0xEEEEEEEE;

	/* one key character. */
	unsigned int ch;
	unsigned int *pdwTable = (unsigned int *)(mpq_archive->mpq_hash);
	unsigned int length    = mpq_archive->mpq_header->hash_table_count * 4;

	/* prepare seeds. */
	while (*pbKey != 0) {
		ch    = toupper(*pbKey++);
		seed1 = mpq_archive->mpq_buffer[0x300 + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}

	/* decrypt it. */
	seed2 = 0xEEEEEEEE;
	while (length-- > 0) {
		seed2       += mpq_archive->mpq_buffer[0x400 + (seed1 & 0xFF)];
		ch           = *pdwTable ^ (seed1 + seed2);
		seed1        = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2        = ch + seed2 + (seed2 << 5) + 3;
		*pdwTable++  = ch;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to decrypt blocktable of mpq archive. */
int libmpq__decrypt_table_block(mpq_archive_s *mpq_archive, unsigned char *pbKey) {

	/* some common variables. */
	unsigned int seed1     = 0x7FED7FED;
	unsigned int seed2     = 0xEEEEEEEE;

	/* one key character. */
	unsigned int ch;
	unsigned int *pdwTable = (unsigned int *)(mpq_archive->mpq_block);
	unsigned int length    = mpq_archive->mpq_header->block_table_count * 4;

	/* prepare seeds. */
	while(*pbKey != 0) {
		ch    = toupper(*pbKey++);
		seed1 = mpq_archive->mpq_buffer[0x300 + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}         

	/* decrypt it. */
	seed2 = 0xEEEEEEEE;
	while(length-- > 0) {
		seed2       += mpq_archive->mpq_buffer[0x400 + (seed1 & 0xFF)];
		ch           = *pdwTable ^ (seed1 + seed2);
		seed1        = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2        = ch + seed2 + (seed2 << 5) + 3;
		*pdwTable++  = ch;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to detect decryption key. */
int libmpq__decrypt_key(mpq_archive_s *mpq_archive, unsigned int decrypted) {

	/* some common variables. */
	unsigned int saveseed1;

	/* temp = seed1 + seed2 */
	unsigned int temp  = *mpq_archive->mpq_file->compressed_offset ^ decrypted;
	unsigned int i     = 0;

	/* temp = seed1 + mpq_archive->mpq_buffer[0x400 + (seed1 & 0xFF)] */
	temp -= 0xEEEEEEEE;

	/* try all 255 possibilities. */
	for (i = 0; i < 0x100; i++) {

		/* some common variables. */
		unsigned int seed1;
		unsigned int seed2 = 0xEEEEEEEE;
		unsigned int ch;

		/* try the first unsigned int's (We exactly know the value). */
		seed1  = temp - mpq_archive->mpq_buffer[0x400 + i];
		seed2 += mpq_archive->mpq_buffer[0x400 + (seed1 & 0xFF)];
		ch     = mpq_archive->mpq_file->compressed_offset[0] ^ (seed1 + seed2);

		if (ch != decrypted) {
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
		seed2 += mpq_archive->mpq_buffer[0x400 + (seed1 & 0xFF)];
		ch     = mpq_archive->mpq_file->compressed_offset[1] ^ (seed1 + seed2);

		/* check if we found the file seed. */
		if ((ch & 0xFFFF0000) == 0) {
			return saveseed1;
		}
	}

	/* if no file seed was found return with error. */
	return LIBMPQ_FILE_ERROR_DECRYPT;
}

/* function to initialize decryption buffer. */
int libmpq__decrypt_buffer_init(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	unsigned int seed   = 0x00100001;
	unsigned int index1 = 0;
	unsigned int index2 = 0;
	unsigned int i;

	/* cleanup. */
	memset(mpq_archive->mpq_buffer, 0, sizeof(mpq_archive->mpq_buffer));

	/* initialize the decryption buffer. */
	for (index1 = 0; index1 < 0x100; index1++) {
		for(index2 = index1, i = 0; i < 5; i++, index2 += 0x100) {

			/* some common variables. */
			unsigned int temp1, temp2;

			/* temporary copy. */
			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp1 = (seed & 0xFFFF) << 0x10;

			/* temporary copy. */
			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp2 = (seed & 0xFFFF);

			/* assign buffer. */
			mpq_archive->mpq_buffer[index2] = (temp1 | temp2);
		}
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to read decrypted hash table. */
int libmpq__read_table_hash(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	int rb = 0;

	/* seek in the file. */
	lseek(mpq_archive->fd, mpq_archive->mpq_header->hash_table_offset + mpq_archive->archive_offset, SEEK_SET);

	/* read the hash table into the buffer. */
	rb = read(mpq_archive->fd, mpq_archive->mpq_hash, mpq_archive->mpq_header->hash_table_count * sizeof(mpq_hash_s));

	/* if different number of bytes read, break the loop. */
	if (rb != (mpq_archive->mpq_header->hash_table_count * sizeof(mpq_hash_s))) {

		/* something on read failed. */
		return LIBMPQ_ARCHIVE_ERROR_HASH_TABLE;
	}

	/* decrypt the hashtable. */
	libmpq__decrypt_table_hash(mpq_archive, (unsigned char *)"(hash table)");

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to read decrypted hash table. */
int libmpq__read_table_block(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	int rb = 0;

	/* seek in file. */
	lseek(mpq_archive->fd, mpq_archive->mpq_header->block_table_offset + mpq_archive->archive_offset, SEEK_SET);

	/* read the block table into the buffer. */
	rb = read(mpq_archive->fd, mpq_archive->mpq_block, mpq_archive->mpq_header->block_table_count * sizeof(mpq_block_s));

	/* if different number of bytes read, break the loop. */
	if (rb != (mpq_archive->mpq_header->block_table_count * sizeof(mpq_block_s))) {

		/* something on read failed. */
		return LIBMPQ_ARCHIVE_ERROR_BLOCK_TABLE;
	}

	/* decrypt block table only if it is encrypted. */
	if (mpq_archive->mpq_header->header_size != mpq_archive->mpq_block->offset) {

		/* decrypt block table. */
		libmpq__decrypt_table_block(mpq_archive, (unsigned char *)"(block table)");
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* function to decompress a input buffer as single sector. */
int libmpq__decompress_single(mpq_archive_s *mpq_archive, unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size) {

	/* some common variables. */
	int tb = 0;

	/* check if file is really compressed and decompress it or copy data only. */
	if (in_size < out_size) {

		/* check if the file is compressed with pkware data compression library. */
		if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_PKWARE) {

			/* decompress using pkzip. */
			if ((tb = libmpq__decompress_pkzip(out_buf, out_size, in_buf, in_size)) < 0) {

				/* something on decompression failed. */
				return tb;
			}
		}

		/*
		 *  check if it is a file compressed by blizzard's multiple compression, note that storm.dll
		 *  version 1.0.9 distributed with warcraft 3 passes the full path name of the opened archive
		 *  as the new last parameter.
		 */
		if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_MULTI) {

			/* decompress using mutliple algorithm. */
			if ((tb = libmpq__decompress_multi(out_buf, out_size, in_buf, in_size)) < 0) {

				/* something on decompression failed. */
				return tb;
			}
		}
	} else {

		/* no compressed data, so copy input buffer to output buffer. */
		memcpy(out_buf, in_buf, out_size);

		/* save the number of transferred bytes. */
		tb = out_size;
	}

	/* return the copied bytes. */
	return tb;
}

/* function to decrypt and decompress a block from mpq archive. */
int libmpq__decompress_block(mpq_archive_s *mpq_archive, unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_number) {

	/* some common variables. */
	int tb = 0;
	unsigned char *temp_buf;

	/* check if file is compressed. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) != 0) {

		/* assign input buffer to temporary buffer. */
		temp_buf = in_buf;

		/* check if block is encrypted, we have to decrypt it. */
		if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_ENCRYPTED) {

			/* decrypt block in input buffer. */
			libmpq__decrypt_mpq_block(mpq_archive, (unsigned int *)temp_buf, in_size, mpq_archive->mpq_file->seed + block_number);
		}

		/* check if block is really compressed, some blocks have set the compression flag, but are not compressed. */
		if (in_size < out_size) {

			/* check if the file is compressed with pkware data compression library. */
			if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_PKWARE) {

				/* decompress using pkzip. */
				if ((tb = libmpq__decompress_pkzip(out_buf, out_size, temp_buf, in_size)) < 0) {

					/* something on decompression failed. */
					return tb;
				}
			}

			/*
			 *  check if it is a file compressed by blizzard's multiple compression, note that storm.dll
			 *  version 1.0.9 distributed with warcraft 3 passes the full path name of the opened archive
			 *  as the new last parameter.
			 */
			if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_MULTI) {

				/* decompress using mutliple algorithm. */
				if ((tb = libmpq__decompress_multi(out_buf, out_size, temp_buf, in_size)) < 0) {

					/* something on decompression failed. */
					return tb;
				}
			}
		} else {

			/* block has set compression flag, but is not compressed, so copy data to output buffer. */
			memcpy(out_buf, in_buf, in_size);

			/* save the number of transferred bytes. */
			tb += in_size;
		}
	}

	/* check if file is not compressed. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) == 0) {

		/* no compressed data, so copy input buffer to output buffer. */
		memcpy(out_buf, in_buf, out_size);

		/* save the number of transferred bytes. */
		tb = out_size;
	}

	/* return the copied bytes. */
	return tb;
}

/* function to read listfile from mpq archive. */
int libmpq__read_file_list(mpq_archive_s *mpq_archive) {

	/* TODO: include the cool filelist from last file in mpq archive here. */
	/* some common variables. */
	unsigned int count = 0;
	unsigned int i;
	int tempsize;
	char tempfile[PATH_MAX];

	/* loop through all files in mpq archive. */
	for (i = 0; i < mpq_archive->mpq_header->hash_table_count; i++) {

		/* check if hashtable is valid for this file. */
		if (mpq_archive->mpq_hash[i].block_table_index == LIBMPQ_MPQ_HASH_FREE) {

			/* continue because this is an empty hash entry. */
			continue;
		}

		/* check if file exists, sizes are correct and block size is above zero. */
		if ((mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].flags & LIBMPQ_FILE_EXISTS) == 0 ||
		     mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].offset > mpq_archive->mpq_header->archive_size + mpq_archive->archive_offset ||
		     mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].compressed_size > mpq_archive->mpq_header->archive_size ||
		     mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].uncompressed_size == 0) {

			/* file does not exist, so nothing to do with that block. */
			continue;
		}

		/* create proper formatted filename. */
		tempsize = snprintf(tempfile, PATH_MAX, "file%06i.xxx", mpq_archive->mpq_hash[i].block_table_index + 1);

		/* allocate memory for the filelist element. */
		mpq_archive->mpq_list->file_names[count] = malloc(tempsize);

		/* check if memory allocation was successful. */
		if (mpq_archive->mpq_list->file_names[count] == NULL) {

			/* memory allocation problem. */
			return LIBMPQ_ARCHIVE_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(mpq_archive->mpq_list->file_names[count], 0, tempsize);

		/* create the filename. */
		mpq_archive->mpq_list->file_names[count]          = memcpy(mpq_archive->mpq_list->file_names[count], tempfile, tempsize);
		mpq_archive->mpq_list->block_table_indices[count] = mpq_archive->mpq_hash[i].block_table_index;
		mpq_archive->mpq_list->hash_table_indices[count]  = i;

		/* increase file counter. */
		count++;
	}

	/* save the number of files. */
	mpq_archive->files = count;

	/* some common variables for heap sort. */
	unsigned int child_width = 8;
	unsigned int parent      = 0;
	unsigned int n           = mpq_archive->files;
	unsigned int m           = (n + (child_width - 2)) / child_width;
	unsigned int child;
	unsigned int w;
	unsigned int max;
	unsigned int temp_block;
	unsigned int temp_hash;
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

/* this function reads variable block positions used in compressed files. */
int libmpq__read_file_offset(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	int rb = 0;

	/* seek to block position. */
	lseek(mpq_archive->fd, mpq_archive->mpq_file->mpq_block->offset, SEEK_SET);

	/* read block positions from begin of file. */
	rb = read(mpq_archive->fd, mpq_archive->mpq_file->compressed_offset, (mpq_archive->mpq_file->mpq_block->uncompressed_size / mpq_archive->block_size + 2) * sizeof(unsigned int));

	/* check if the archive is protected some way, sometimes the file appears not to be encrypted, but it is. */
	if (mpq_archive->mpq_file->compressed_offset[0] != rb) {
		mpq_archive->mpq_file->mpq_block->flags |= LIBMPQ_FILE_ENCRYPTED;
	}

	/* decrypt loaded block positions if necessary. */
	if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_ENCRYPTED) {

		/* check if we don't know the file seed, try to find it. */
		if ((mpq_archive->mpq_file->seed = libmpq__decrypt_key(mpq_archive, rb)) < 0) {

			/* sorry without seed, we cannot extract file. */
			return LIBMPQ_FILE_ERROR_DECRYPT;
		}

		/* decrypt block positions. */
		libmpq__decrypt_mpq_block(mpq_archive, mpq_archive->mpq_file->compressed_offset, rb, mpq_archive->mpq_file->seed - 1);

		/* check if the block positions are correctly decrypted, sometimes it will result invalid block positions on some files. */
		if (mpq_archive->mpq_file->compressed_offset[0] != rb) {

			/* try once again to detect fileseed and decrypt the blocks. */
			lseek(mpq_archive->fd, mpq_archive->mpq_file->mpq_block->offset, SEEK_SET);

			/* read again. */
			rb = read(mpq_archive->fd, mpq_archive->mpq_file->compressed_offset, (mpq_archive->mpq_file->mpq_block->uncompressed_size / mpq_archive->block_size + 2) * sizeof(unsigned int));
			mpq_archive->mpq_file->seed = libmpq__decrypt_key(mpq_archive, rb);

			/* decrypt mpq block. */
			libmpq__decrypt_mpq_block(mpq_archive, mpq_archive->mpq_file->compressed_offset, rb, mpq_archive->mpq_file->seed - 1);

			/* check if the block positions are correctly decrypted. */
			if (mpq_archive->mpq_file->compressed_offset[0] != rb) {

				/* sorry without seed, we cannot extract file. */
				return LIBMPQ_FILE_ERROR_DECRYPT;
			}
		}
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}
