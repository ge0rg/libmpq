/*
 *  common.c -- shared functions used by mpq-tools.
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
int libmpq__decrypt_mpq_block(mpq_archive *mpq_a, unsigned int *block, unsigned int length, unsigned int seed1) {

	/* some common variables. */
	unsigned int seed2 = 0xEEEEEEEE;
	unsigned int ch;

	/* round to unsigned int's. */
	length >>= 2;
	while (length-- > 0) {
		seed2    += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch        = *block ^ (seed1 + seed2);
		seed1     = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2     = ch + seed2 + (seed2 << 5) + 3;
		*block++  = ch;
	}

	/* if no error was found, return zero. */
	return 0;
}

/* function to decrypt hash table of mpq archive. */
int libmpq__decrypt_table_hash(mpq_archive *mpq_a, unsigned char *pbKey) {

	/* some common variables. */
	unsigned int seed1     = 0x7FED7FED;
	unsigned int seed2     = 0xEEEEEEEE;

	/* one key character. */
	unsigned int ch;
	unsigned int *pdwTable = (unsigned int *)(mpq_a->hashtable);
	unsigned int length    = mpq_a->header->hashtablesize * 4;

	/* prepare seeds. */
	while (*pbKey != 0) {
		ch    = toupper(*pbKey++);
		seed1 = mpq_a->buf[0x300 + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}

	/* decrypt it. */
	seed2 = 0xEEEEEEEE;
	while (length-- > 0) {
		seed2       += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch           = *pdwTable ^ (seed1 + seed2);
		seed1        = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2        = ch + seed2 + (seed2 << 5) + 3;
		*pdwTable++  = ch;
	}

	/* if no error was found, return zero. */
	return 0;
}

/* function to decrypt blocktable of mpq archive. */
int libmpq__decrypt_table_block(mpq_archive *mpq_a, unsigned char *pbKey) {

	/* some common variables. */
	unsigned int seed1     = 0x7FED7FED;
	unsigned int seed2     = 0xEEEEEEEE;

	/* one key character. */
	unsigned int ch;
	unsigned int *pdwTable = (unsigned int *)(mpq_a->blocktable);
	unsigned int length    = mpq_a->header->blocktablesize * 4;

	/* prepare seeds. */
	while(*pbKey != 0) {
		ch    = toupper(*pbKey++);
		seed1 = mpq_a->buf[0x300 + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}         

	/* decrypt it. */
	seed2 = 0xEEEEEEEE;
	while(length-- > 0) {
		seed2       += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch           = *pdwTable ^ (seed1 + seed2);
		seed1        = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2        = ch + seed2 + (seed2 << 5) + 3;
		*pdwTable++  = ch;
	}

	/* if no error was found, return zero. */
	return 0;
}

/* function to detect decryption key. */
int libmpq__decrypt_key(mpq_archive *mpq_a, unsigned int *block, unsigned int decrypted) {

	/* some common variables. */
	unsigned int saveseed1;

	/* temp = seed1 + seed2 */
	unsigned int temp  = *block ^ decrypted;
	unsigned int i     = 0;

	/* temp = seed1 + mpq_a->buf[0x400 + (seed1 & 0xFF)] */
	temp          -= 0xEEEEEEEE;

	/* try all 255 possibilities. */
	for (i = 0; i < 0x100; i++) {

		/* some common variables. */
		unsigned int seed1;
		unsigned int seed2 = 0xEEEEEEEE;
		unsigned int ch;

		/* try the first unsigned int's (We exactly know the value). */
		seed1  = temp - mpq_a->buf[0x400 + i];
		seed2 += mpq_a->buf[0x400 + (seed1 & 0xFF)];
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
		seed2 += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch     = block[1] ^ (seed1 + seed2);

		/* check if we found the fileseed. */
		if ((ch & 0xFFFF0000) == 0) {
			return saveseed1;
		}
	}

	/* if no error was found, return zero. */
	return 0;
}

/* function to initialize decryption buffer. */
int libmpq__decrypt_buffer_init(mpq_archive *mpq_a) {

	/* some common variables. */
	unsigned int seed   = 0x00100001;
	unsigned int index1 = 0;
	unsigned int index2 = 0;
	unsigned int i;

	/* cleanup. */
	memset(mpq_a->buf, 0, sizeof(mpq_a->buf));

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
			mpq_a->buf[index2] = (temp1 | temp2);
		}
	}

	/* if no error was found, return zero. */
	return 0;
}

/* function to read decrypted hash table. */
int libmpq__read_table_hash(mpq_archive *mpq_a) {

	/* some common variables. */
	unsigned int bytes = 0;
	int rb     = 0;

	/* allocate memory, note that the blocktable should be as large as the hashtable. (for later file additions) */
	mpq_a->hashtable = malloc(sizeof(mpq_hash) * mpq_a->header->hashtablesize);

	/* check if memory allocation was successful. */
	if (!mpq_a->hashtable) {
		return -1;
	}

	/* read the hash table into the buffer. */
	bytes = mpq_a->header->hashtablesize * sizeof(mpq_hash);
	lseek(mpq_a->fd, mpq_a->header->hashtablepos, SEEK_SET);
	rb = read(mpq_a->fd, mpq_a->hashtable, bytes);
	if (rb != bytes) {
		return -1;
	}

	/* create hashtable structure. */
	mpq_hash *mpq_h_end = mpq_a->hashtable + mpq_a->header->hashtablesize;
	mpq_hash *mpq_h     = NULL;

	/* decrypt the hashtable. */
	libmpq__decrypt_table_hash(mpq_a, (unsigned char *)"(hash table)");

	/* check if hashtable is correctly decrypted. */
	for (mpq_h = mpq_a->hashtable; mpq_h < mpq_h_end; mpq_h++) {
		if (mpq_h->locale != 0xFFFFFFFF && (mpq_h->locale & 0xFFFF0000) != 0) {
			return -1;
		}

		/* remember the highest blocktable entry. */
		if (mpq_h->blockindex < LIBMPQ_MPQ_HASH_DELETED && mpq_h->blockindex > 0) {
			mpq_a->maxblockindex = mpq_h->blockindex;
		}
	}

	/* if no error was found, return zero. */
	return 0;
}

/* function to read decrypted hash table. */
int libmpq__read_table_block(mpq_archive *mpq_a) {

	/* some common variables. */
	unsigned int bytes = 0;
	int rb     = 0;

	/* allocate memory, note that the blocktable should be as large as the hashtable. (for later file additions) */
	mpq_a->blocktable = malloc(sizeof(mpq_block) * mpq_a->header->hashtablesize);
	mpq_a->blockbuf   = malloc(mpq_a->blocksize);

	/* check if memory allocation was successful. */
	if (!mpq_a->blocktable || !mpq_a->blockbuf) {
		return -1;
	}

	/* read the blocktable into the buffer. */
	bytes = mpq_a->header->blocktablesize * sizeof(mpq_block);
	memset(mpq_a->blocktable, 0, mpq_a->header->blocktablesize * sizeof(mpq_block));
	lseek(mpq_a->fd, mpq_a->header->blocktablepos, SEEK_SET);
	rb = read(mpq_a->fd, mpq_a->blocktable, bytes);
	if (rb != bytes) {
		return -1;
	}

	/*
	 *  decrypt blocktable, some mpq archives don't have encrypted blocktable,
	 *  e.g. cracked diablo version. we have to check if block table is already
	 *  decrypted.
	 */
	mpq_block *mpq_b_end     = mpq_a->blocktable + mpq_a->maxblockindex + 1;
	mpq_block *mpq_b         = NULL;
	unsigned int archivesize     = mpq_a->header->archivesize + mpq_a->mpqpos;

	/* check if we should decrypt the blocktable. */
	if (mpq_a->header->offset != mpq_a->blocktable->filepos) {
		libmpq__decrypt_table_block(mpq_a, (unsigned char *)"(block table)");
	}

	/* check if blocktable is correctly decrypted. */
	for (mpq_b = mpq_a->blocktable; mpq_b < mpq_b_end; mpq_b++) {
		if (mpq_b->filepos > archivesize || mpq_b->csize > archivesize) {
			if ((mpq_a->flags & LIBMPQ_MPQ_FLAG_PROTECTED) == 0) {
				return -1;
			}
		}
		mpq_b->filepos += mpq_a->mpqpos;
	}

	/* if no error was found, return zero. */
	return 0;
}

/* function to read decrypted block. */
int libmpq__read_file_block(mpq_archive *mpq_a, mpq_file *mpq_f, unsigned int blockpos, unsigned char *buffer, unsigned int blockbytes) {

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
	unsigned int toread    = 0;

	/* total number of bytes read. */
	unsigned int bytesread = 0;

	/* check parameters, block position and block size must be blockaligned, block size nonzero. */
	if ((blockpos & (mpq_a->blocksize - 1)) || blockbytes == 0) {
		return 0;
	}

	/* check the end of file. */
	if ((blockpos + blockbytes) > mpq_f->mpq_b->fsize) {
		blockbytes = mpq_f->mpq_b->fsize - blockpos;
	}

	/* set blocknumber and number of blocks. */
	blocknum = blockpos   / mpq_a->blocksize;
	nblocks  = blockbytes / mpq_a->blocksize;

	/* check if some bytes are still open and add a block. */
	if (blockbytes % mpq_a->blocksize) {
		nblocks++;
	}

	/* check if file has variable block positions, we have to load them. */
	if ((mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) && mpq_f->blockposloaded == FALSE) {

		/* some common variables. */
		unsigned int nread;

		/* check if file position match block position in archive. */
		if (mpq_f->mpq_b->filepos != mpq_a->filepos) {
			lseek(mpq_a->fd, mpq_f->mpq_b->filepos, SEEK_SET);
		}

		/* read block positions from begin of file. */
		nread = (mpq_f->nblocks + 1) * sizeof(int);
		nread = read(mpq_a->fd, mpq_f->blockpos, nread);

		/* check if the archive is protected some way, sometimes the file appears not to be encrypted, but it is. */
		if (mpq_f->blockpos[0] != nread) {
			mpq_f->mpq_b->flags |= LIBMPQ_FILE_ENCRYPTED;
		}

		/* decrypt loaded block positions if necessary. */
		if (mpq_f->mpq_b->flags & LIBMPQ_FILE_ENCRYPTED) {

			/* check if we don't know the file seed, try to find it. */
			if (mpq_f->seed == 0) {
				mpq_f->seed = libmpq__decrypt_key(mpq_a, mpq_f->blockpos, nread);
			}

			/* check if we don't know the file seed, sorry but we cannot extract the file. */
			if (mpq_f->seed == 0) {
				return 0;
			}

			/* decrypt block positions. */
			libmpq__decrypt_mpq_block(mpq_a, mpq_f->blockpos, nread, mpq_f->seed - 1);

			/* check if the block positions are correctly decrypted, sometimes it will result invalid block positions on some files. */
			if (mpq_f->blockpos[0] != nread) {

				/* try once again to detect fileseed and decrypt the blocks. */
				lseek(mpq_a->fd, mpq_f->mpq_b->filepos, SEEK_SET);

				/* read again. */
				nread       = read(mpq_a->fd, mpq_f->blockpos, (mpq_f->nblocks + 1) * sizeof(int));
				mpq_f->seed = libmpq__decrypt_key(mpq_a, mpq_f->blockpos, nread);

				/* decrypt mpq block. */
				libmpq__decrypt_mpq_block(mpq_a, mpq_f->blockpos, nread, mpq_f->seed - 1);

				/* check if the block positions are correctly decrypted. */
				if (mpq_f->blockpos[0] != nread) {
					return 0;
				}
			}
		}

		/* update mpq_f's variables. */
		mpq_f->blockposloaded = TRUE;
		mpq_a->filepos        = mpq_f->mpq_b->filepos + nread;
	}

	/* get file position and number of bytes to read. */
	readpos = blockpos;
	toread  = blockbytes;

	/* check if file is compressed. */
	if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) {
		readpos = mpq_f->blockpos[blocknum];
		toread  = mpq_f->blockpos[blocknum + nblocks] - readpos;
	}

	/* set new read position. */
	readpos += mpq_f->mpq_b->filepos;

	/* get work buffer for store read data. */
	if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) {
		if ((tempbuf = malloc(toread)) == NULL) {

			/* hmmm... we should add a better error handling here :) */
			return 0;
		}
	}

	/* set file pointer, if necessary. */
	if (mpq_a->filepos != readpos) {
		mpq_a->filepos = lseek(mpq_a->fd, readpos, SEEK_SET);
	}

	/* 15018F87 - read all requested blocks. */
	bytesread      = read(mpq_a->fd, tempbuf, toread);
	mpq_a->filepos = readpos + bytesread;

	/* index of block start in work buffer. */
	unsigned int blockstart = 0;
	unsigned int blocksize  = min(blockbytes, mpq_a->blocksize);

	/* current block index. */
	unsigned int index      = blocknum;

	/* clear read byte counter. */
	bytesread           = 0;

	/* walk through all blocks. */
	for (i = 0; i < nblocks; i++, index++) {

		/* some common variables. */
		int outlength = mpq_a->blocksize;

		/* get current block length. */
		if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) {
			blocksize = mpq_f->blockpos[index + 1] - mpq_f->blockpos[index];
		}

		/* check if block is encrypted, we have to decrypt it. */
		if (mpq_f->mpq_b->flags & LIBMPQ_FILE_ENCRYPTED) {
			if (mpq_f->seed == 0) {
				return 0;
			}
			libmpq__decrypt_mpq_block(mpq_a, (unsigned int *)&tempbuf[blockstart], blocksize, mpq_f->seed + index);
		}

		/*
		 *  check if the block is really compressed, recompress it, note that some block may not be compressed,
		 *  it can only be determined by comparing uncompressed and compressed size.
		 */
		if (blocksize < blockbytes) {

			/* check if the file is compressed with pkware data compression library. */
			if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESS_PKWARE) {
				libmpq__decompress_pkzip(buffer, &outlength, &tempbuf[blockstart], blocksize);
			}

			/*
			 *  check if it is a file compressed by blizzard's multiple compression, note that storm.dll
			 *  version 1.0.9 distributed with warcraft 3 passes the full path name of the opened archive
			 *  as the new last parameter.
			 */
			if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESS_MULTI) {
				libmpq__decompress_multi(buffer, &outlength, &tempbuf[blockstart], blocksize);
			}

			/* fill values. */
			bytesread += outlength;
			buffer    += outlength;
		} else {

			/* copy into buffer. */
			memcpy(buffer, tempbuf, blocksize);

			/* fill values. */
			bytesread += blocksize;
			buffer    += blocksize;
		}

		/* fill values. */
		blockstart += blocksize;
	}

	/* delete input buffer, if necessary. */
	if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) {
		free(tempbuf);
	}

	/* return the copied bytes. */
	return bytesread;
}

/* function to read file from mpq archive. */
int libmpq__read_file_mpq(mpq_archive *mpq_a, mpq_file *mpq_f, unsigned int filepos, unsigned char *buffer, unsigned int toread) {

	/* position in the file aligned to the whole blocks. */
	unsigned int blockpos;

	/* number of bytes read from the file. */
	unsigned int bytesread = 0;
	unsigned int loaded    = 0;

	/* check if file position is greater or equal to file size. */
	if (filepos >= mpq_f->mpq_b->fsize) {
		return 0;
	}

	/* check if to few bytes in the file remaining, cut them. */
	if ((mpq_f->mpq_b->fsize - filepos) < toread) {
		toread = (mpq_f->mpq_b->fsize - filepos);
	}

	/* block position in the file. */
	blockpos = filepos & ~(mpq_a->blocksize - 1);

	/* load the first block, if incomplete, it may be loaded in the cache buffer and we have to check if this block is loaded, if not, load it. */
	if ((filepos % mpq_a->blocksize) != 0) {

		/* number of bytes remaining in the buffer. */
		unsigned int tocopy;
		unsigned int loaded = mpq_a->blocksize;

		/* check if data are loaded in the cache. */
		if (mpq_f->accessed == FALSE || blockpos != mpq_a->blockpos) {   

			/* load one mpq block into archive buffer. */
			loaded = libmpq__read_file_block(mpq_a, mpq_f, blockpos, mpq_a->blockbuf, mpq_a->blocksize);
			if (loaded == 0) {
				return 0;
			}

			/* save lastly accessed file and block position for later use. */
			mpq_f->accessed = TRUE;
			mpq_a->blockpos = blockpos;
			mpq_a->bufpos   = filepos % mpq_a->blocksize;
		}

		/* check remaining bytes for copying. */
		tocopy = loaded - mpq_a->bufpos;
		if (tocopy > toread) {
			tocopy = toread;
		}

		/* copy data from block buffer into target buffer. */
		memcpy(buffer, mpq_a->blockbuf + mpq_a->bufpos, tocopy);

		/* update pointers. */
		toread        -= tocopy;
		bytesread     += tocopy;
		buffer        += tocopy;
		blockpos      += mpq_a->blocksize;
		mpq_a->bufpos += tocopy;

		/* check if we finish read, so return. */
		if (toread == 0) {
			return bytesread;
		}
	}

	/* load the whole ("middle") blocks only if there are more or equal one block. */
	if (toread > mpq_a->blocksize) {

		/* some common variables. */
		unsigned int blockbytes = toread & ~(mpq_a->blocksize - 1);

		/* read the mpq block from file. */
		loaded = libmpq__read_file_block(mpq_a, mpq_f, blockpos, buffer, blockbytes);
		if (loaded == 0) {
			return 0;
		}

		/* update pointers. */
		toread    -= loaded;
		bytesread += loaded;
		buffer    += loaded;
		blockpos  += loaded;

		/* check if we finish read, so return. */
		if (toread == 0) {
			return bytesread;
		}
	}

	/* load the terminating block. */
	if (toread > 0) {

		/* some common variables. */
		unsigned int tocopy = mpq_a->blocksize;

		/* check if data are loaded in the cache. */
		if (mpq_f->accessed == FALSE || blockpos != mpq_a->blockpos) {

			/* load one mpq block into archive buffer. */
			tocopy = libmpq__read_file_block(mpq_a, mpq_f, blockpos, mpq_a->blockbuf, mpq_a->blocksize);
			if (tocopy == 0) {
				return 0;
			}

			/* save lastly accessed file and block position for later use. */
			mpq_f->accessed = TRUE;
			mpq_a->blockpos = blockpos;
		}
		mpq_a->bufpos  = 0;

		/* check number of bytes read. */
		if (tocopy > toread) {
			tocopy = toread;
		}

		/* copy data from block buffer into target buffer. */
		memcpy(buffer, mpq_a->blockbuf, tocopy);

		/* update pointers. */
		bytesread     += tocopy;
		mpq_a->bufpos  = tocopy;
	}

	/* return the copied bytes. */
	return bytesread;
}
