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

/* function to read a file as single sector. */
int libmpq__read_file_single(mpq_archive_s *mpq_archive) {

	/* total number of bytes read. */
	int rb = 0;
	int tb = 0;

	/* seek in file. */
	lseek(mpq_archive->fd, mpq_archive->mpq_file->mpq_block->offset, SEEK_SET);

	/* check if file is really compressed and decompress it or copy data only. */
	if (mpq_archive->mpq_file->mpq_block->compressed_size < mpq_archive->mpq_file->mpq_block->uncompressed_size) {

		/* read the compressed file data. */
		if ((rb = read(mpq_archive->fd, mpq_archive->mpq_file->in_buf, mpq_archive->mpq_file->mpq_block->compressed_size)) < 0) {

			/* something on read from archive failed. */
			return LIBMPQ_FILE_ERROR_READ;
		}

		/* check if the file is compressed with pkware data compression library. */
		if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_PKWARE) {

			/* decompress using pkzip. */
			if ((tb = libmpq__decompress_pkzip(mpq_archive->mpq_file->out_buf, mpq_archive->mpq_file->mpq_block->uncompressed_size, mpq_archive->mpq_file->in_buf, mpq_archive->mpq_file->mpq_block->compressed_size)) < 0) {

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
			if ((tb = libmpq__decompress_multi(mpq_archive->mpq_file->out_buf, mpq_archive->mpq_file->mpq_block->uncompressed_size, mpq_archive->mpq_file->in_buf, mpq_archive->mpq_file->mpq_block->compressed_size)) < 0) {

				/* something on decompression failed. */
				return tb;
			}
		}
	} else {

		/* read the uncompressed data. */
		if ((rb = read(mpq_archive->fd, mpq_archive->mpq_file->out_buf, mpq_archive->mpq_file->mpq_block->compressed_size)) < 0) {

			/* something on read from archive failed. */
			return LIBMPQ_FILE_ERROR_READ;
		}

		/* save the number of transferred bytes. */
		tb = rb;
	}

	/* return the copied bytes. */
	return tb;
}

/* function to read decrypted block. */
int libmpq__read_file_block(mpq_archive_s *mpq_archive, unsigned int block_offset, unsigned char *buffer, unsigned int blockbytes) {

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
	if ((block_offset + blockbytes) > mpq_archive->mpq_file->mpq_block->uncompressed_size) {
		blockbytes = mpq_archive->mpq_file->mpq_block->uncompressed_size - block_offset;
	}

	/* set blocknumber and number of blocks. */
	bytesremain = mpq_archive->mpq_file->mpq_block->uncompressed_size - block_offset;
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
	if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {
		readpos = mpq_archive->mpq_file->compressed_offset[blocknum];
		toread  = mpq_archive->mpq_file->compressed_offset[blocknum + nblocks] - readpos;
	}

	/* set new read position. */
	readpos += mpq_archive->mpq_file->mpq_block->offset;

	/* set pointer to buffer, this is necessary if file is not compressed (such files are used in warcraft 3 - the frozen throne setup.mpq archive). */
	tempbuf = buffer;

	/* get work buffer for store read data. */
	if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {
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
		if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {
			blocksize = mpq_archive->mpq_file->compressed_offset[index + 1] - mpq_archive->mpq_file->compressed_offset[index];
		}

		/* check if block is encrypted, we have to decrypt it. */
		if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_ENCRYPTED) {
			if (mpq_archive->mpq_file->seed == 0) {
				return 0;
			}
			libmpq__decrypt_mpq_block(mpq_archive, (unsigned int *)&tempbuf[blockstart], blocksize, mpq_archive->mpq_file->seed + index);
		}

		/*
		 *  check if the block is really compressed, recompress it, note that some block may not be compressed,
		 *  it can only be determined by comparing uncompressed and compressed size.
		 */
		if (blocksize < blockbytes) {

			/* check if the file is compressed with pkware data compression library. */
			if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_PKWARE) {

				/* decompress using pkzip. */
				outlength = libmpq__decompress_pkzip(buffer, outlength, &tempbuf[blockstart], blocksize);
			}

			/*
			 *  check if it is a file compressed by blizzard's multiple compression, note that storm.dll
			 *  version 1.0.9 distributed with warcraft 3 passes the full path name of the opened archive
			 *  as the new last parameter.
			 */
			if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESS_MULTI) {

				/* decompress using mutliple algorithm. */
				outlength = libmpq__decompress_multi(buffer, outlength, &tempbuf[blockstart], blocksize);
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
	if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {
		free(tempbuf);
	}

	/* return the copied bytes. */
	return bytesread;
}

/* function to read file from mpq archive. */
int libmpq__read_file_mpq(mpq_archive_s *mpq_archive, unsigned char *buffer, unsigned int toread) {

	/* position in the file aligned to the whole blocks. */
	unsigned int block_offset;
	unsigned int buffer_offset;

	/* number of bytes read from the file. */
	unsigned int bytesread = 0;
	unsigned int loaded    = 0;

	/* check if file position is greater or equal to file size. */
	if (mpq_archive->mpq_file->uncompressed_offset >= mpq_archive->mpq_file->mpq_block->uncompressed_size) {
		return 0;
	}

	/* check if to few bytes in the file remaining, cut them. */
	if ((mpq_archive->mpq_file->mpq_block->uncompressed_size - mpq_archive->mpq_file->uncompressed_offset) < toread) {
		toread = (mpq_archive->mpq_file->mpq_block->uncompressed_size - mpq_archive->mpq_file->uncompressed_offset);
	}

	/* block position in the file. */
	block_offset = mpq_archive->mpq_file->uncompressed_offset & ~(mpq_archive->block_size - 1);

	/* load the first block, if incomplete, it may be loaded in the cache buffer and we have to check if this block is loaded, if not, load it. */
	if ((mpq_archive->mpq_file->uncompressed_offset % mpq_archive->block_size) != 0) {

		/* number of bytes remaining in the buffer. */
		unsigned int tocopy;
		unsigned int loaded = mpq_archive->block_size;

		/* check if data are loaded in the cache. */
		if (block_offset < mpq_archive->block_size - 1 || block_offset != mpq_archive->block_offset) {   

			/* load one mpq block into archive buffer. */
			loaded = libmpq__read_file_block(mpq_archive, block_offset, mpq_archive->mpq_file->block_buffer, mpq_archive->block_size);
			if (loaded == 0) {
				return 0;
			}

			/* save lastly accessed file and block position for later use. */
			mpq_archive->block_offset = block_offset;
			buffer_offset   = mpq_archive->mpq_file->uncompressed_offset % mpq_archive->block_size;
		}

		/* check remaining bytes for copying. */
		tocopy = loaded - buffer_offset;
		if (tocopy > toread) {
			tocopy = toread;
		}

		/* copy data from block buffer into target buffer. */
		memcpy(buffer, mpq_archive->mpq_file->block_buffer + buffer_offset, tocopy);

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
		loaded = libmpq__read_file_block(mpq_archive, block_offset, buffer, blockbytes);
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
			tocopy = libmpq__read_file_block(mpq_archive, block_offset, mpq_archive->mpq_file->block_buffer, mpq_archive->block_size);
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
		memcpy(buffer, mpq_archive->mpq_file->block_buffer, tocopy);

		/* update pointers. */
		bytesread     += tocopy;
		buffer_offset  = tocopy;
	}

	/* return the copied bytes. */
	return bytesread;
}

/* function to read variable block positions used in compressed files. */
int libmpq__read_file_offset(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	int rb = 0;

	/* check if block is compressed and no single sector. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) != 0 &&
	    (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_SINGLE) == 0) {

		/* seek to block position. */
		lseek(mpq_archive->fd, mpq_archive->mpq_file->mpq_block->offset, SEEK_SET);

		/* read block positions from begin of file. */
		rb = read(mpq_archive->fd, mpq_archive->mpq_file->compressed_offset, (mpq_archive->mpq_file->blocks + 1) * sizeof(unsigned int));

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
				rb = read(mpq_archive->fd, mpq_archive->mpq_file->compressed_offset, (mpq_archive->mpq_file->blocks + 1) * sizeof(unsigned int));
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
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
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
