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
	return 0;
}

/* function to decrypt hash table of mpq archive. */
int libmpq__decrypt_table_hash(mpq_archive_s *mpq_archive, unsigned char *pbKey) {

	/* some common variables. */
	unsigned int seed1     = 0x7FED7FED;
	unsigned int seed2     = 0xEEEEEEEE;

	/* one key character. */
	unsigned int ch;
	unsigned int *pdwTable = (unsigned int *)(mpq_archive->mpq_hash);
	unsigned int length    = mpq_archive->mpq_header->hash_table_size * 4;

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
	return 0;
}

/* function to decrypt blocktable of mpq archive. */
int libmpq__decrypt_table_block(mpq_archive_s *mpq_archive, unsigned char *pbKey) {

	/* some common variables. */
	unsigned int seed1     = 0x7FED7FED;
	unsigned int seed2     = 0xEEEEEEEE;

	/* one key character. */
	unsigned int ch;
	unsigned int *pdwTable = (unsigned int *)(mpq_archive->mpq_block);
	unsigned int length    = mpq_archive->mpq_header->block_table_size * 4;

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
	return 0;
}

/* function to detect decryption key. */
int libmpq__decrypt_key(mpq_archive_s *mpq_archive, unsigned int *block, unsigned int decrypted) {

	/* some common variables. */
	unsigned int saveseed1;

	/* temp = seed1 + seed2 */
	unsigned int temp  = *block ^ decrypted;
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
		ch     = block[0] ^ (seed1 + seed2);

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
		ch     = block[1] ^ (seed1 + seed2);

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
	return 0;
}

/* function to read decrypted hash table. */
int libmpq__read_table_hash(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	int rb = 0;

	/* allocate memory, note that the blocktable should be as large as the hashtable. (for later file additions) */
	mpq_archive->mpq_hash = malloc(sizeof(mpq_hash_s) * mpq_archive->mpq_header->hash_table_size);

	/* check if memory allocation was successful. */
	if (!mpq_archive->mpq_hash) {
		return -1;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_hash, 0, sizeof(mpq_hash_s) * mpq_archive->mpq_header->hash_table_size);

	/* seek in the file. */
	lseek(mpq_archive->fd, mpq_archive->mpq_header->hash_table_offset + mpq_archive->archive_offset, SEEK_SET);

	/* read the hash table into the buffer. */
	rb = read(mpq_archive->fd, mpq_archive->mpq_hash, mpq_archive->mpq_header->hash_table_size * sizeof(mpq_hash_s));

	/* if different number of bytes read, break the loop. */
	if (rb != (mpq_archive->mpq_header->hash_table_size * sizeof(mpq_hash_s))) {
		return -1;
	}

	/* decrypt the hashtable. */
	libmpq__decrypt_table_hash(mpq_archive, (unsigned char *)"(hash table)");

	/* if no error was found, return zero. */
	return 0;
}

/* function to read decrypted hash table. */
int libmpq__read_table_block(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	int rb = 0;

	/* allocate memory, note that the blocktable should be as large as the hashtable. (for later file additions) */
	mpq_archive->mpq_block = malloc(sizeof(mpq_block_s) * mpq_archive->mpq_header->block_table_size);
	mpq_archive->block_buffer = malloc(mpq_archive->block_size);

	/* check if memory allocation was successful. */
	if (!mpq_archive->mpq_block || !mpq_archive->block_buffer) {
		return -1;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_block, 0, sizeof(mpq_block_s) * mpq_archive->mpq_header->block_table_size);
	memset(mpq_archive->block_buffer, 0, mpq_archive->block_size);

	/* seek in file. */
	lseek(mpq_archive->fd, mpq_archive->mpq_header->block_table_offset + mpq_archive->archive_offset, SEEK_SET);

	/* read the block table into the buffer. */
	rb = read(mpq_archive->fd, mpq_archive->mpq_block, mpq_archive->mpq_header->block_table_size * sizeof(mpq_block_s));

	/* if different number of bytes read, break the loop. */
	if (rb != (mpq_archive->mpq_header->block_table_size * sizeof(mpq_block_s))) {
		return -1;
	}

	/* decrypt block table only if it is encrypted. */
	if (mpq_archive->mpq_header->header_size != mpq_archive->mpq_block->offset) {

		/* decrypt block table. */
		libmpq__decrypt_table_block(mpq_archive, (unsigned char *)"(block table)");
	}

	/* if no error was found, return zero. */
	return 0;
}

/* function to read decrypted block. */
int libmpq__read_file_block(mpq_archive_s *mpq_archive, mpq_file_s *mpq_file, unsigned int block_offset, unsigned char *buffer, unsigned int blockbytes) {

	/* reading position from the file. */
	unsigned int readpos;

	/* block number. (needed for decrypt) */
	unsigned int blocknum;

	/* number of blocks to load. */
	unsigned int nblocks;

	/* block counter. */
	unsigned int i;

	/* buffer for reading compressed data from the file. */
	unsigned char *tempbuf   = NULL;

	/* number of bytes to read. */
	unsigned int toread      = 0;

	/* total number of bytes read. */
	unsigned int bytesread   = 0;

	/* number of data bytes remaining up to the end of the file. */
	unsigned int bytesremain = 0;

	/* check parameters, block position and block size must be blockaligned, block size nonzero. */
	if ((block_offset & (mpq_archive->block_size - 1)) || blockbytes == 0) {
		return 0;
	}

	/* check the end of file. */
	if ((block_offset + blockbytes) > mpq_file->mpq_block->uncompressed_size) {
		blockbytes = mpq_file->mpq_block->uncompressed_size - block_offset;
	}

	/* set blocknumber and number of blocks. */
	bytesremain = mpq_file->mpq_block->uncompressed_size - block_offset;
	blocknum    = block_offset / mpq_archive->block_size;
	nblocks     = blockbytes / mpq_archive->block_size;

	/* check if some bytes are still open and add a block. */
	if (blockbytes % mpq_archive->block_size) {
		nblocks++;
	}

	/* get file position and number of bytes to read. */
	readpos = block_offset;
	toread  = blockbytes;

	/* check if file is compressed. */
	if (mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {
		readpos = mpq_file->file_block_offset[blocknum];
		toread  = mpq_file->file_block_offset[blocknum + nblocks] - readpos;
	}

	/* set new read position. */
	readpos += mpq_file->mpq_block->offset;

	/* set pointer to buffer, this is necessary if file is not compressed (such files are used in warcraft 3 - the frozen throne setup.mpq archive). */
	tempbuf = buffer;

	/* get work buffer for store read data. */
	if (mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {
		if ((tempbuf = malloc(toread)) == NULL) {

			/* hmmm... we should add a better error handling here :) */
			return 0;
		}
	}

	/* 15018F87 - read all requested blocks. */
	bytesread = read(mpq_archive->fd, tempbuf, toread);

	/* index of block start in work buffer. */
	unsigned int blockstart = 0;
	unsigned int blocksize  = min(blockbytes, mpq_archive->block_size);

	/* current block index. */
	unsigned int index      = blocknum;

	/* clear read byte counter. */
	bytesread               = 0;

	/* walk through all blocks. */
	for (i = 0; i < nblocks; i++, index++) {

		/* some common variables. */
		int outlength = mpq_archive->block_size;

		/* cut remaining bytes. */
		if (bytesremain < outlength) {
			outlength = bytesremain;
		}

		/* get current block length. */
		if (mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {
			blocksize = mpq_file->file_block_offset[index + 1] - mpq_file->file_block_offset[index];
		}

		/* check if block is encrypted, we have to decrypt it. */
		if (mpq_file->mpq_block->flags & LIBMPQ_FILE_ENCRYPTED) {
			if (mpq_file->seed == 0) {
				return 0;
			}
			libmpq__decrypt_mpq_block(mpq_archive, (unsigned int *)&tempbuf[blockstart], blocksize, mpq_file->seed + index);
		}

		/*
		 *  check if the block is really compressed, recompress it, note that some block may not be compressed,
		 *  it can only be determined by comparing uncompressed and compressed size.
		 */
		if (blocksize < blockbytes) {

			/* check if the file is compressed with pkware data compression library. */
			if (mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_PKWARE) {
				libmpq__decompress_pkzip(buffer, &outlength, &tempbuf[blockstart], blocksize);
			}

			/*
			 *  check if it is a file compressed by blizzard's multiple compression, note that storm.dll
			 *  version 1.0.9 distributed with warcraft 3 passes the full path name of the opened archive
			 *  as the new last parameter.
			 */
			if (mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_MULTI) {
				libmpq__decompress_multi(buffer, &outlength, &tempbuf[blockstart], blocksize);
			}

			/* fill values. */
			bytesread += outlength;
			buffer    += outlength;
		} else {

			/* check if we need to copy something. */
			if (buffer != tempbuf) {

				/* copy into buffer. */
				memcpy(buffer, tempbuf, blocksize);
			}

			/* fill values. */
			bytesread += blocksize;
			buffer    += blocksize;
		}

		/* fill values. */
		blockstart  += blocksize;
		bytesremain -= outlength;
	}

	/* delete input buffer, if necessary. */
	if (mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {
		free(tempbuf);
	}

	/* return the copied bytes. */
	return bytesread;
}

/* function to read file from mpq archive. */
int libmpq__read_file_mpq(mpq_archive_s *mpq_archive, mpq_file_s *mpq_file, unsigned char *buffer, unsigned int toread) {

	/* position in the file aligned to the whole blocks. */
	unsigned int block_offset;
	unsigned int buffer_offset;

	/* number of bytes read from the file. */
	unsigned int bytesread = 0;
	unsigned int loaded    = 0;

	/* check if file position is greater or equal to file size. */
	if (mpq_file->offset >= mpq_file->mpq_block->uncompressed_size) {
		return 0;
	}

	/* check if to few bytes in the file remaining, cut them. */
	if ((mpq_file->mpq_block->uncompressed_size - mpq_file->offset) < toread) {
		toread = (mpq_file->mpq_block->uncompressed_size - mpq_file->offset);
	}

	/* block position in the file. */
	block_offset = mpq_file->offset & ~(mpq_archive->block_size - 1);

	/* load the first block, if incomplete, it may be loaded in the cache buffer and we have to check if this block is loaded, if not, load it. */
	if ((mpq_file->offset % mpq_archive->block_size) != 0) {

		/* number of bytes remaining in the buffer. */
		unsigned int tocopy;
		unsigned int loaded = mpq_archive->block_size;

		/* check if data are loaded in the cache. */
		if (block_offset < mpq_archive->block_size - 1 || block_offset != mpq_archive->block_offset) {   

			/* load one mpq block into archive buffer. */
			loaded = libmpq__read_file_block(mpq_archive, mpq_file, block_offset, mpq_archive->block_buffer, mpq_archive->block_size);
			if (loaded == 0) {
				return 0;
			}

			/* save lastly accessed file and block position for later use. */
			mpq_archive->block_offset = block_offset;
			buffer_offset   = mpq_file->offset % mpq_archive->block_size;
		}

		/* check remaining bytes for copying. */
		tocopy = loaded - buffer_offset;
		if (tocopy > toread) {
			tocopy = toread;
		}

		/* copy data from block buffer into target buffer. */
		memcpy(buffer, mpq_archive->block_buffer + buffer_offset, tocopy);

		/* update pointers. */
		toread        -= tocopy;
		bytesread     += tocopy;
		buffer        += tocopy;
		block_offset  += mpq_archive->block_size;
		buffer_offset += tocopy;

		/* check if we finish read, so return. */
		if (toread == 0) {
			return bytesread;
		}
	}

	/* load the whole ("middle") blocks only if there are more or equal one block. */
	if (toread > mpq_archive->block_size) {

		/* some common variables. */
		unsigned int blockbytes = toread & ~(mpq_archive->block_size - 1);

		/* read the mpq block from file. */
		loaded = libmpq__read_file_block(mpq_archive, mpq_file, block_offset, buffer, blockbytes);
		if (loaded == 0) {
			return 0;
		}

		/* update pointers. */
		toread    -= loaded;
		bytesread += loaded;
		buffer    += loaded;
		block_offset  += loaded;

		/* check if we finish read, so return. */
		if (toread == 0) {
			return bytesread;
		}
	}

	/* load the terminating block. */
	if (toread > 0) {

		/* some common variables. */
		unsigned int tocopy = mpq_archive->block_size;

		/* check if data are loaded in the cache. */
		if (block_offset < mpq_archive->block_size - 1 || block_offset != mpq_archive->block_offset) {

			/* load one mpq block into archive buffer. */
			tocopy = libmpq__read_file_block(mpq_archive, mpq_file, block_offset, mpq_archive->block_buffer, mpq_archive->block_size);
			if (tocopy == 0) {
				return 0;
			}

			/* save lastly accessed file and block position for later use. */
			mpq_archive->block_offset = block_offset;
		}

		/* check number of bytes read. */
		if (tocopy > toread) {
			tocopy = toread;
		}

		/* copy data from block buffer into target buffer. */
		memcpy(buffer, mpq_archive->block_buffer, tocopy);

		/* update pointers. */
		bytesread     += tocopy;
		buffer_offset  = tocopy;
	}

	/* return the copied bytes. */
	return bytesread;
}

/* function to read listfile from mpq archive. */
int libmpq__read_file_list(mpq_archive_s *mpq_archive) {

	/* TODO: include the cool filelist from last file in mpq archive here. */
	/* some common variables. */
	unsigned int count = 0;
	unsigned int i;
	int tempsize;
	char tempfile[PATH_MAX];
	char **file_names;
	unsigned int *block_table_indices;
	unsigned int *hash_table_indices;

	/* allocate memory for the mpq file list. */
	if ((mpq_archive->mpq_list = malloc(sizeof(mpq_list_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_list, 0, sizeof(mpq_list_s));

	/* allocate memory for the file names. */
	file_names = malloc(mpq_archive->mpq_header->block_table_size * sizeof(char *));
	block_table_indices = malloc(mpq_archive->mpq_header->block_table_size * sizeof(unsigned int));
	hash_table_indices = malloc(mpq_archive->mpq_header->block_table_size * sizeof(unsigned int));

	/* check if memory allocation was successful. */
	if (!file_names || !block_table_indices || !hash_table_indices) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(file_names, 0, mpq_archive->mpq_header->block_table_size * sizeof(char *));
	memset(block_table_indices, 0, mpq_archive->mpq_header->block_table_size * sizeof(unsigned int));
	memset(hash_table_indices, 0, mpq_archive->mpq_header->block_table_size * sizeof(unsigned int));

	/* loop through all files in mpq archive. */
	for (i = 0; i < mpq_archive->mpq_header->hash_table_size; i++) {

		/* check if hashtable is valid for this file. */
		if (mpq_archive->mpq_hash[i].block_table_index == LIBMPQ_MPQ_HASH_FREE) {

			/* continue because this is an empty hash entry. */
			continue;
		}

		/* check if blocksize is zero. */
		if (mpq_archive->mpq_block[mpq_archive->mpq_hash[i].block_table_index].uncompressed_size == 0) {

			/* nothing to do with that block. */
			continue;
		}

		/* create proper formatted filename. */
		tempsize = snprintf(tempfile, PATH_MAX, "file%06i.xxx", mpq_archive->mpq_hash[i].block_table_index + 1);

		/* allocate memory for the filelist element. */
		file_names[mpq_archive->mpq_hash[i].block_table_index] = malloc(tempsize);

		/* check if memory allocation was successful. */
		if (!file_names[mpq_archive->mpq_hash[i].block_table_index]) {

			/* memory allocation problem. */
			return LIBMPQ_ARCHIVE_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(file_names[mpq_archive->mpq_hash[i].block_table_index], 0, tempsize);

		/* create the filename. */
		file_names[mpq_archive->mpq_hash[i].block_table_index] = memcpy(file_names[mpq_archive->mpq_hash[i].block_table_index], tempfile, tempsize);
		block_table_indices[mpq_archive->mpq_hash[i].block_table_index] = mpq_archive->mpq_hash[i].block_table_index;
		hash_table_indices[mpq_archive->mpq_hash[i].block_table_index] = i;

		/* increase file counter. */
		count++;
	}

	/* save the number of files. */
	mpq_archive->num_files = count;

	/* allocate memory for the file names. */
	mpq_archive->mpq_list->file_names = malloc(count * sizeof(char *));
	mpq_archive->mpq_list->block_table_indices = malloc(count * sizeof(unsigned int));
	mpq_archive->mpq_list->hash_table_indices = malloc(count * sizeof(unsigned int));

	/* check if memory allocation was successful. */
	if (!mpq_archive->mpq_list->file_names || !mpq_archive->mpq_list->block_table_indices || !mpq_archive->mpq_list->hash_table_indices) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_list->file_names, 0, count * sizeof(char *));
	memset(mpq_archive->mpq_list->block_table_indices, 0, count * sizeof(unsigned int));
	memset(mpq_archive->mpq_list->hash_table_indices, 0, count * sizeof(unsigned int));

	/* reset the counter and use it again. */
	count = 0;

	/* loop through all files a second time and rebuild indexes for unused blocks (first seen in warcraft 3 - the frozen throne). */
	for (i = 0; i < mpq_archive->mpq_header->block_table_size; i++) {

		if (file_names[i] != NULL) {

			/* allocate memory for the filelist element. */
			mpq_archive->mpq_list->file_names[count] = malloc(strlen(file_names[i]));

			/* check if memory allocation was successful. */
			if (!mpq_archive->mpq_list->file_names[count]) {

				/* memory allocation problem. */
				return LIBMPQ_ARCHIVE_ERROR_MALLOC;
			}

			/* cleanup. */
			memset(mpq_archive->mpq_list->file_names[count], 0, strlen(file_names[i]));

			/* create the filename. */
			mpq_archive->mpq_list->file_names[count] = memcpy(mpq_archive->mpq_list->file_names[count], file_names[i], strlen(file_names[i]));
			mpq_archive->mpq_list->block_table_indices[count] = block_table_indices[i];
			mpq_archive->mpq_list->hash_table_indices[count] = hash_table_indices[i];

			/* increase file counter. */
			count++;
		}
	}

	/* free the filelist. */
	for (i = 0; i < mpq_archive->mpq_header->block_table_size; i++) {

		/* free the filelist element. */
		free(file_names[i]);
	}

	/* free the filelist pointer. */
	free(file_names);
	free(block_table_indices);
	free(hash_table_indices);

	/* if no error was found, return zero. */
	return 0;
}
