/*
 *  common.c -- shared functions used by mpq-tools.
 *
 *  Copyright (C) 2003 Maik Broemme <mbroemme@plusserver.de>
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
 *
 *  $Id: common.c,v 1.12 2004/02/12 00:42:54 mbroemme Exp $
 */

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libmpq/mpq.h"

/*
 *  This function decrypts a MPQ block.
 */
int libmpq_decrypt_block(mpq_archive *mpq_a, unsigned int *block, unsigned int length, unsigned int seed1) {
	unsigned int seed2 = 0xEEEEEEEE;
	unsigned int ch;

	/* Round to unsigned int's */
	length >>= 2;
	while (length-- > 0) {
		seed2    += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch        = *block ^ (seed1 + seed2);
		seed1     = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2     = ch + seed2 + (seed2 << 5) + 3;
		*block++  = ch;
	}
	return LIBMPQ_SUCCESS;
}

/*
 *  This function decrypts the hashtable for the
 *  file informations.
 */
int libmpq_decrypt_hashtable(mpq_archive *mpq_a, unsigned char *pbKey) {
	unsigned int seed1 = 0x7FED7FED;
	unsigned int seed2 = 0xEEEEEEEE;
	unsigned int ch;			/* One key character */
	unsigned int *pdwTable = (unsigned int *)(mpq_a->hashtable);
	unsigned int length = mpq_a->header->hashtablesize * 4;

	/* Prepare seeds */
	while (*pbKey != 0) {
		ch = toupper(*pbKey++);
		seed1 = mpq_a->buf[0x300 + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}

	/* Decrypt it */
	seed2 = 0xEEEEEEEE;
	while (length-- > 0) {
		seed2 += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch     = *pdwTable ^ (seed1 + seed2);
		seed1  = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2  = ch + seed2 + (seed2 << 5) + 3;
		*pdwTable++ = ch;
	}
	return LIBMPQ_SUCCESS;
}

/*
 *  This function decrypts the blocktable.
 */
int libmpq_decrypt_blocktable(mpq_archive *mpq_a, unsigned char *pbKey) {
	unsigned int seed1 = 0x7FED7FED;
	unsigned int seed2 = 0xEEEEEEEE;
	unsigned int ch;			/* One key character */
	unsigned int *pdwTable = (unsigned int *)(mpq_a->blocktable);
	unsigned int length = mpq_a->header->blocktablesize * 4;

	/* Prepare seeds */
	while(*pbKey != 0) {
		ch = toupper(*pbKey++);
		seed1 = mpq_a->buf[0x300 + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}         

	/* Decrypt it */
	seed2 = 0xEEEEEEEE;
	while(length-- > 0) {
		seed2 += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch     = *pdwTable ^ (seed1 + seed2);
		seed1  = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2  = ch + seed2 + (seed2 << 5) + 3;
		*pdwTable++ = ch;
	}
	return LIBMPQ_SUCCESS;
}

/*
 *  This functions tries to get file decryption key. The trick comes from block
 *  positions which are stored at the begin of each compressed file. We know the
 *  file size, that means we know number of blocks that means we know the first
 *  int value in block position. And if we know encrypted and decrypted value,
 *  we can find the decryption key.
 */
int libmpq_detect_fileseed(mpq_archive *mpq_a, unsigned int *block, unsigned int decrypted) {
	unsigned int saveseed1;
	unsigned int temp = *block ^ decrypted;		/* temp = seed1 + seed2 */
	int i = 0;
	temp -= 0xEEEEEEEE;				/* temp = seed1 + mpq_a->buf[0x400 + (seed1 & 0xFF)] */

	for (i = 0; i < 0x100; i++) {			/* Try all 255 possibilities */
		unsigned int seed1;
		unsigned int seed2 = 0xEEEEEEEE;
		unsigned int ch;

		/* Try the first unsigned int's (We exactly know the value) */
		seed1  = temp - mpq_a->buf[0x400 + i];
		seed2 += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch     = block[0] ^ (seed1 + seed2);

		if (ch != decrypted) {
			continue;
		}

		/* Add 1 because we are decrypting block positions */
		saveseed1 = seed1 + 1;

		/*
		 *  If OK, continue and test the second value. We don't know exactly the value,
		 *  but we know that the second one has lower 16 bits set to zero
		 *  (no compressed block is larger than 0xFFFF bytes)
		 */
		seed1  = ((~seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B);
		seed2  = ch + seed2 + (seed2 << 5) + 3;
		seed2 += mpq_a->buf[0x400 + (seed1 & 0xFF)];
		ch     = block[1] ^ (seed1 + seed2);
		if ((ch & 0xFFFF0000) == 0) {
			return saveseed1;
		}
	}
	return LIBMPQ_SUCCESS;
}

/*
 *  This function initialize the decryption buffer
 */
int libmpq_init_buffer(mpq_archive *mpq_a) {
	unsigned int seed   = 0x00100001;
	unsigned int index1 = 0;
	unsigned int index2 = 0;
	int i;

	memset(mpq_a->buf, 0, sizeof(mpq_a->buf));

	/* Initialize the decryption buffer. */
	for (index1 = 0; index1 < 0x100; index1++) {
		for(index2 = index1, i = 0; i < 5; i++, index2 += 0x100) {
			unsigned int temp1, temp2;
			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp1 = (seed & 0xFFFF) << 0x10;

			seed  = (seed * 125 + 3) % 0x2AAAAB;
			temp2 = (seed & 0xFFFF);

			mpq_a->buf[index2] = (temp1 | temp2);
		}
	}
	return LIBMPQ_SUCCESS;
}

/*
 *  This functions fills the mpq_hash structure with the
 *  hashtable found in the MPQ file. The hashtable will
 *  be decrypted for later use.
 */
int libmpq_read_hashtable(mpq_archive *mpq_a) {
	unsigned int bytes = 0;
	int rb = 0;

	/*
	 *  Allocate memory. Note that the block table should be as large as the
	 *  hash table. (for later file additions)
	 */
	mpq_a->hashtable = malloc(sizeof(mpq_hash) * mpq_a->header->hashtablesize);

	if (!mpq_a->hashtable) {
		return -1;
	}

	/* Read the hash table into the buffer */
	bytes = mpq_a->header->hashtablesize * sizeof(mpq_hash);
	lseek(mpq_a->fd, mpq_a->header->hashtablepos, SEEK_SET);
	rb = read(mpq_a->fd, mpq_a->hashtable, bytes);
	if (rb != bytes) {
		return -1;
	}

	/* Decrypt hash table and check if it is correctly decrypted */
	mpq_hash *mpq_h_end = mpq_a->hashtable + mpq_a->header->hashtablesize;
	mpq_hash *mpq_h     = NULL;

	libmpq_decrypt_hashtable(mpq_a, "(hash table)");

	/* Check hash table if is correctly decrypted */
	for (mpq_h = mpq_a->hashtable; mpq_h < mpq_h_end; mpq_h++) {
		if (mpq_h->locale != 0xFFFFFFFF && (mpq_h->locale & 0xFFFF0000) != 0) {
			return -1;
		}

		/* Remember the highest block table entry */
		if (mpq_h->blockindex < LIBMPQ_MPQ_HASH_DELETED && mpq_h->blockindex > 0) {
			mpq_a->maxblockindex = mpq_h->blockindex;
		}
	}

	return LIBMPQ_SUCCESS;
}

/*
 *  This functions fills the mpq_block structure with the
 *  blocktable found in the MPQ file. The blocktable will
 *  be decrypted for later use.
 *
 *  NOTICE: Some MPQs have decrypted block table, e.g.
 *          cracked Diablo versions.
 */
int libmpq_read_blocktable(mpq_archive *mpq_a) {
	unsigned int bytes = 0;
	int rb = 0;

	/*
	 *  Allocate memory. Note that the block table should be as large as the
	 *  hash table. (for later file additions)
	 */
	mpq_a->blocktable = malloc(sizeof(mpq_block) * mpq_a->header->hashtablesize);
	mpq_a->blockbuf   = malloc(mpq_a->blocksize);

	if (!mpq_a->blocktable || !mpq_a->blockbuf) {
		return -1;
	}

	/* Read the block table into the buffer */
	bytes = mpq_a->header->blocktablesize * sizeof(mpq_block);
	memset(mpq_a->blocktable, 0, mpq_a->header->blocktablesize * sizeof(mpq_block));
	lseek(mpq_a->fd, mpq_a->header->blocktablepos, SEEK_SET);
	rb = read(mpq_a->fd, mpq_a->blocktable, bytes);
	if (rb != bytes) {
		return -1;
	}

	/*
	 *  Decrypt block table. Some MPQs don't have encrypted block table,
	 *  e.g. cracked Diablo version. We have to check if block table is
	 *  already decrypted
	 */
	mpq_block *mpq_b_end     = mpq_a->blocktable + mpq_a->maxblockindex + 1;
	mpq_block *mpq_b         = NULL;
	unsigned int archivesize = mpq_a->header->archivesize + mpq_a->mpqpos;

	if (mpq_a->header->offset != mpq_a->blocktable->filepos) {
		libmpq_decrypt_blocktable(mpq_a, "(block table)");
	}
	for (mpq_b = mpq_a->blocktable; mpq_b < mpq_b_end; mpq_b++) {
		if (mpq_b->filepos > archivesize || mpq_b->csize > archivesize) {
			if ((mpq_a->flags & LIBMPQ_MPQ_FLAG_PROTECTED) == 0) {
				return -1;
			}
		}
		mpq_b->filepos += mpq_a->mpqpos;
	}

	return LIBMPQ_SUCCESS;
}

int libmpq_file_read_block(mpq_archive *mpq_a, mpq_file *mpq_f, unsigned int blockpos, char *buffer, unsigned int blockbytes) {
	unsigned char *tempbuf = NULL;			/* Buffer for reading compressed data from the file */
	unsigned int readpos;				/* Reading position from the file */
	unsigned int toread = 0;			/* Number of bytes to read */
	unsigned int blocknum;				/* Block number (needed for decrypt) */
	unsigned int bytesread = 0;			/* Total number of bytes read */
	unsigned int nblocks;				/* Number of blocks to load */
	unsigned int i;

	/* Test parameters. Block position and block size must be block-aligned, block size nonzero */
	if ((blockpos & (mpq_a->blocksize - 1)) || blockbytes == 0) {
		return 0;
	}

	/* Check the end of file */
	if ((blockpos + blockbytes) > mpq_f->mpq_b->fsize) {
		blockbytes = mpq_f->mpq_b->fsize - blockpos;
	}
	blocknum = blockpos   / mpq_a->blocksize;
	nblocks  = blockbytes / mpq_a->blocksize;
	if (blockbytes % mpq_a->blocksize) {
		nblocks++;
	}

	/* If file has variable block positions, we have to load them */
	if ((mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) && mpq_f->blockposloaded == FALSE) {
		unsigned int nread;

		if (mpq_f->mpq_b->filepos != mpq_a->filepos) {
			lseek(mpq_a->fd, mpq_f->mpq_b->filepos, SEEK_SET);
		}

		/* Read block positions from begin of file. */
		nread = (mpq_f->nblocks + 1) * sizeof(int);
		nread = read(mpq_a->fd, mpq_f->blockpos, nread);

		/*
		 *  If the archive is protected some way, perform additional check
		 *  Sometimes, the file appears not to be encrypted, but it is.
		 */
		if (mpq_f->blockpos[0] != nread) {
			mpq_f->mpq_b->flags |= LIBMPQ_FILE_ENCRYPTED;
		}

		/* Decrypt loaded block positions if necessary */
		if (mpq_f->mpq_b->flags & LIBMPQ_FILE_ENCRYPTED) {

			/* If we don't know the file seed, try to find it. */
			if (mpq_f->seed == 0) {
				mpq_f->seed = libmpq_detect_fileseed(mpq_a, mpq_f->blockpos, nread);
			}

			/* If we don't know the file seed, sorry but we cannot extract the file. */
			if (mpq_f->seed == 0) {
				return 0;
			}

			/* Decrypt block positions */
			libmpq_decrypt_block(mpq_a, mpq_f->blockpos, nread, mpq_f->seed - 1);

			/*
			 *  Check if the block positions are correctly decrypted
			 *  I don't know why, but sometimes it will result invalid
			 *  block positions on some files.
			 */
			if (mpq_f->blockpos[0] != nread) {

				/* Try once again to detect file seed and decrypt the blocks */
				lseek(mpq_a->fd, mpq_f->mpq_b->filepos, SEEK_SET);
				nread = read(mpq_a->fd, mpq_f->blockpos, (mpq_f->nblocks + 1) * sizeof(int));
				mpq_f->seed = libmpq_detect_fileseed(mpq_a, mpq_f->blockpos, nread);
				libmpq_decrypt_block(mpq_a, mpq_f->blockpos, nread, mpq_f->seed - 1);

				/* Check if the block positions are correctly decrypted. */
				if (mpq_f->blockpos[0] != nread) {
					return 0;
				}
			}
		}

		/* Update mpq_f's variables */
		mpq_f->blockposloaded = TRUE;
		mpq_a->filepos        = mpq_f->mpq_b->filepos + nread;
	}

	/* Get file position and number of bytes to read */
	readpos = blockpos;
	toread  = blockbytes;

	if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) {
		readpos = mpq_f->blockpos[blocknum];
		toread  = mpq_f->blockpos[blocknum + nblocks] - readpos;
	}
	readpos += mpq_f->mpq_b->filepos;

	/* Get work buffer for store read data */
	if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) {
		if ((tempbuf = malloc(toread)) == NULL) {
			/* Hmmm... We should add a better error handling here :) */
			return 0;
		}
	}

	/* Set file pointer, if necessary. */
	if (mpq_a->filepos != readpos) {
		mpq_a->filepos = lseek(mpq_a->fd, readpos, SEEK_SET);
	}

	/* 15018F87 - Read all requested blocks. */
	bytesread = read(mpq_a->fd, tempbuf, toread);
	mpq_a->filepos = readpos + bytesread;

	/* Block processing part. */
	unsigned int blockstart = 0;			/* Index of block start in work buffer. */
	unsigned int blocksize  = min(blockbytes, mpq_a->blocksize);
	unsigned int index      = blocknum;		/* Current block index. */
	bytesread = 0;					/* Clear read byte counter */

	/* Walk through all blocks. */
	for (i = 0; i < nblocks; i++, index++) {
		int outlength = mpq_a->blocksize;

		/* Get current block length */
		if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) {
			blocksize = mpq_f->blockpos[index + 1] - mpq_f->blockpos[index];
		}

		/* If block is encrypted, we have to decrypt it. */
		if (mpq_f->mpq_b->flags & LIBMPQ_FILE_ENCRYPTED) {
			if (mpq_f->seed == 0) {
				return 0;
			}
			libmpq_decrypt_block(mpq_a, (unsigned int *)&tempbuf[blockstart], blocksize, mpq_f->seed + index);
		}

		/*
		 *  If the block is really compressed, recompress it.
		 *  WARNING: Some block may not be compressed, it can
		 *  only be determined by comparing uncompressed and
		 *  compressed size!
		 */
		if (blocksize < blockbytes) {

			/* Is the file compressed with PKWARE Data Compression Library? */
			if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESS_PKWARE) {
				libmpq_pkzip_decompress(buffer, &outlength, &tempbuf[blockstart], blocksize);
			}

			/*
			 *  Is it a file compressed by Blizzard's multiple compression ?
			 *  Note that Storm.dll v 1.0.9 distributed with Warcraft III
			 *  passes the full path name of the opened archive as the new
			 *  last parameter.
			 */
			if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESS_MULTI) {
				libmpq_multi_decompress(buffer, &outlength, &tempbuf[blockstart], blocksize);
			}

			bytesread += outlength;
			buffer    += outlength;
		} else {
			memcpy(buffer, tempbuf, blocksize);
			bytesread += blocksize;
			buffer    += blocksize;
		}
		blockstart += blocksize;
	}

	/* Delete input buffer, if necessary. */
	if (mpq_f->mpq_b->flags & LIBMPQ_FILE_COMPRESSED) {
		free(tempbuf);
	}
	return bytesread;
}

int libmpq_file_read_file(mpq_archive *mpq_a, mpq_file *mpq_f, unsigned int filepos, char *buffer, unsigned int toread) {
	unsigned int bytesread = 0;			/* Number of bytes read from the file */
	unsigned int blockpos;				/* Position in the file aligned to the whole blocks */
	unsigned int loaded = 0;

	/* File position is greater or equal to file size? */
	if (filepos >= mpq_f->mpq_b->fsize) {
		return 0;
	}

	/* If to few bytes in the file remaining, cut them */
	if ((mpq_f->mpq_b->fsize - filepos) < toread) {
		toread = (mpq_f->mpq_b->fsize - filepos);
	}

	/* Block position in the file */
	blockpos = filepos & ~(mpq_a->blocksize - 1);

	/*
	 *  Load the first block, if noncomplete. It may be loaded in the cache buffer.
	 *  We have to check if this block is loaded. If not, load it.
	 */
	if ((filepos % mpq_a->blocksize) != 0) {
		/* Number of bytes remaining in the buffer */
		unsigned int tocopy;
		unsigned int loaded = mpq_a->blocksize;

		/* Check if data are loaded in the cache */
		if (mpq_f->accessed == FALSE || blockpos != mpq_a->blockpos) {   

			/* Load one MPQ block into archive buffer */
			loaded = libmpq_file_read_block(mpq_a, mpq_f, blockpos, mpq_a->blockbuf, mpq_a->blocksize);
			if (loaded == 0) {
				return 0;
			}

			/* Save lastly accessed file and block position for later use */
			mpq_f->accessed = TRUE;
			mpq_a->blockpos = blockpos;
			mpq_a->bufpos   = filepos % mpq_a->blocksize;
		}
		tocopy = loaded - mpq_a->bufpos;
		if (tocopy > toread) {
			tocopy = toread;
		}

		/* Copy data from block buffer into target buffer */
		memcpy(buffer, mpq_a->blockbuf + mpq_a->bufpos, tocopy);

		/* Update pointers */
		toread        -= tocopy;
		bytesread     += tocopy;
		buffer        += tocopy;
		blockpos      += mpq_a->blocksize;
		mpq_a->bufpos += tocopy;

		/* If all, return. */
		if (toread == 0) {
			return bytesread;
		}
	}

	/* Load the whole ("middle") blocks only if there are more or equal one block */
	if (toread > mpq_a->blocksize) {
		unsigned int blockbytes = toread & ~(mpq_a->blocksize - 1);
		loaded = libmpq_file_read_block(mpq_a, mpq_f, blockpos, buffer, blockbytes);
		if (loaded == 0) {
			return 0;
		}

		/* Update pointers */
		toread    -= loaded;
		bytesread += loaded;
		buffer    += loaded;
		blockpos  += loaded;

		/* If all, return. */
		if (toread == 0) {
			return bytesread;
		}
	}

	/* Load the terminating block */
	if (toread > 0) {
		unsigned int tocopy = mpq_a->blocksize;

		/* Check if data are loaded in the cache */
		if (mpq_f->accessed == FALSE || blockpos != mpq_a->blockpos) {

			/* Load one MPQ block into archive buffer */
			tocopy = libmpq_file_read_block(mpq_a, mpq_f, blockpos, mpq_a->blockbuf, mpq_a->blocksize);
			if (tocopy == 0) {
				return 0;
			}

			/* Save lastly accessed file and block position for later use */
			mpq_f->accessed = TRUE;
			mpq_a->blockpos = blockpos;
		}
		mpq_a->bufpos  = 0;

		/* Check number of bytes read */
		if (tocopy > toread) {
			tocopy = toread;
		}

		memcpy(buffer, mpq_a->blockbuf, tocopy);
		bytesread     += tocopy;
		mpq_a->bufpos  = tocopy;
	}

	/* Return what we've read */
	return bytesread;
}
