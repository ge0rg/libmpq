/*
 *  mpq.c -- functions for developers using libmpq.
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* libmpq main includes. */
#include "mpq.h"

/* libmpq generic includes. */
#include "common.h"

/* mpq-tools configuration includes. */
#include "config.h"

/* this function returns the library version information. */
unsigned char *libmpq__version() {

	/* return version information. */
	return (unsigned char *)VERSION;
}

/* this function reads a file and verify if it is a valid mpq archive, then it reads and decrypts the hash table. */
int libmpq__archive_open(mpq_archive_s *mpq_archive, const char *mpq_filename) {

	/* some common variables. */
	int fd          = 0;
	unsigned int rb = 0;
	unsigned int i;
	struct stat fileinfo;
	char tempfile[PATH_MAX];
	int tempsize;

	/* allocate memory for the mpq archive. */
	if ((mpq_archive->mpq_list = malloc(sizeof(mpq_list_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_list, 0, sizeof(mpq_list_s));

	/* allocate memory for the mpq header. */
	if ((mpq_archive->mpq_header = malloc(sizeof(mpq_header_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_header, 0, sizeof(mpq_header_s));

	/* try to open the file. */
	fd = open(mpq_filename, O_RDONLY);

	/* check if file exists and is readable */
	if (fd == -1) {

		/* file could not be opened. */
		return LIBMPQ_ARCHIVE_ERROR_OPEN;
	}

	/* fill the structures with informations */
	strncpy((char *)mpq_archive->filename, mpq_filename, strlen(mpq_filename));

	/* initialize the decryption buffer. */
	libmpq__decrypt_buffer_init(mpq_archive);

	/* assign some default values. */
	mpq_archive->fd                    = fd;
	mpq_archive->mpq_header->mpq_magic = 0;
	mpq_archive->maxblockindex         = 0;

	/* loop through file and search for mpq signature. */
	while (TRUE) {

		/* reset header values. */
		mpq_archive->mpq_header->mpq_magic = 0;

		/* seek in file. */
		lseek(mpq_archive->fd, mpq_archive->mpqpos, SEEK_SET);

		/* read header from file. */
		rb = read(mpq_archive->fd, mpq_archive->mpq_header, sizeof(mpq_header_s));

		/* if different number of bytes read, break the loop. */
		if (rb != sizeof(mpq_header_s)) {

			/* reset values, to make close archive function happy. */
			mpq_archive->mpq_header->block_table_length = 0;

			/* no valid mpq archive. */
			return LIBMPQ_ARCHIVE_ERROR_FORMAT;
		}

		/* check if we found a valid mpq header. */
		if (mpq_archive->mpq_header->mpq_magic == LIBMPQ_MPQ_HEADER_ID) {

			/* check if we process old mpq archive version. */
			if (mpq_archive->mpq_header->version == LIBMPQ_ARCHIVE_VERSION_ONE) {

				/* break the loop, because header was found. */
				break;
			}

			/* check if we process new mpq archive version. */
			if (mpq_archive->mpq_header->version == LIBMPQ_ARCHIVE_VERSION_TWO) {

				/* TODO: add support for mpq version two. */
				/* support for version two will be added soon. */
				return LIBMPQ_ARCHIVE_ERROR_FORMAT;
			}
		}

		/* move to the next possible offset. */
		mpq_archive->mpqpos += 0x200;
	}

	/* get the right positions of the hash table and the block table. */
	mpq_archive->blocksize = (0x200 << mpq_archive->mpq_header->sector_size_shift);
	fstat(mpq_archive->fd, &fileinfo);

	/* try to read and decrypt the hashtable. */
	if (libmpq__read_table_hash(mpq_archive) != 0) {

		/* the hashtable seems corrupt. */
		return LIBMPQ_ARCHIVE_ERROR_HASHTABLE;
	}

	/* try to read and decrypt the blocktable. */
	if (libmpq__read_table_block(mpq_archive) != 0) {

		/* the blocktable seems corrupt. */
		return LIBMPQ_ARCHIVE_ERROR_BLOCKTABLE;
	}

	/* TODO: include the cool filelist from last file in mpq archive here. */
	/* allocate memory for the file list. */
	mpq_archive->mpq_list->mpq_files = malloc(mpq_archive->mpq_header->block_table_length * sizeof(char *));

	/* check if memory allocation was successful. */
	if (!mpq_archive->mpq_list->mpq_files) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_list->mpq_files, 0, mpq_archive->mpq_header->block_table_length * sizeof(char *));

	/* loop through all files in mpq archive. */
	for (i = 0; i < mpq_archive->mpq_header->block_table_length; i++) {

		/* create proper formatted filename. */
		tempsize = snprintf(tempfile, PATH_MAX, "file%06i.xxx", i + 1);

		/* allocate memory for the filelist element. */
		mpq_archive->mpq_list->mpq_files[i] = malloc(tempsize);

		/* check if memory allocation was successful. */
		if (!mpq_archive->mpq_list->mpq_files[i]) {

			/* memory allocation problem. */
			return LIBMPQ_ARCHIVE_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(mpq_archive->mpq_list->mpq_files[i], 0, tempsize);

		/* create the filename. */
		mpq_archive->mpq_list->mpq_files[i] = memcpy(mpq_archive->mpq_list->mpq_files[i], tempfile, tempsize);
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function closes the file descriptor, frees the decryption buffer and the filelist. */
int libmpq__archive_close(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	unsigned int i;

	/* check if filelist was created. */
	if (mpq_archive->mpq_list->mpq_files != NULL) {

		/* free the filelist. */
		for (i = 0; i < mpq_archive->mpq_header->block_table_length; i++) {

			/* free the filelist element. */
			free(mpq_archive->mpq_list->mpq_files[i]);
		}

		/* free the filelist pointer. */
		free(mpq_archive->mpq_list->mpq_files);
	}

	/* cleanup. */
	memset(mpq_archive->buf, 0, sizeof(mpq_archive->buf));

	/* free the allocated memory. */
	free(mpq_archive->mpq_header);
	free(mpq_archive->mpq_list);

	/* check if file descriptor is valid. */
	if ((close(mpq_archive->fd)) == -1) {

		/* file was not opened. */
		return LIBMPQ_ARCHIVE_ERROR_CLOSE;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function returns some information for the requested type of a mpq archive. */
int libmpq__archive_info(mpq_archive_s *mpq_archive, unsigned int infotype) {

	/* some common variables. */
	unsigned int filecount = 0;
	unsigned int fsize     = 0;
	unsigned int csize     = 0;
	mpq_block_s *mpq_b_end = mpq_archive->mpq_block + mpq_archive->mpq_header->block_table_length;
	mpq_block_s *mpq_b     = NULL;

	/* check which information type should be returned. */
	switch (infotype) {
		case LIBMPQ_ARCHIVE_SIZE:

			/* return the archive size. */
			return mpq_archive->mpq_header->archive_size;
		case LIBMPQ_ARCHIVE_HASHTABLE_SIZE:

			/* return the hashtable size. */
			return mpq_archive->mpq_header->hash_table_length;
		case LIBMPQ_ARCHIVE_BLOCKTABLE_SIZE:

			/* return the blocktable size. */
			return mpq_archive->mpq_header->block_table_length;
		case LIBMPQ_ARCHIVE_BLOCKSIZE:

			/* return the blocksize. */
			return mpq_archive->blocksize;
		case LIBMPQ_ARCHIVE_NUMFILES:

			/* loop through all files in archive and count them. */
			for (mpq_b = mpq_archive->mpq_block; mpq_b < mpq_b_end; mpq_b++) {
				filecount++;
			}

			/* return the number of files in the mpq archive. */
			return filecount;
		case LIBMPQ_ARCHIVE_COMPRESSED_SIZE:

			/* loop through all files in archive and count compressed size. */
			for (mpq_b = mpq_archive->mpq_block; mpq_b < mpq_b_end; mpq_b++) {
				csize += mpq_b->archived_size;
			}

			/* return the compressed size of all files in the mpq archive. */
			return csize;
		case LIBMPQ_ARCHIVE_UNCOMPRESSED_SIZE:

			/* loop through all files in archive and count uncompressed size. */
			for (mpq_b = mpq_archive->mpq_block; mpq_b < mpq_b_end; mpq_b++) {
				fsize += mpq_b->size;
			}

			/* return the uncompressed size of all files in the mpq archive. */
			return fsize;
		default:

			/* if no error was found, return zero. */
			return LIBMPQ_SUCCESS;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function returns some useful file information. */
int libmpq__file_info(mpq_archive_s *mpq_archive, unsigned int infotype, const unsigned int number) {

	/* some common variables. */
	mpq_block_s *mpq_block = NULL;
	mpq_hash_s *mpq_hash   = NULL;
	int blockindex         = -1;
	unsigned int i;

	/* check if given number is not out of range. */
	if (number < 1 || number > mpq_archive->mpq_header->block_table_length) {

		/* file number is out of range. */
		return LIBMPQ_FILE_ERROR_RANGE;
	}

	/* search for correct hashtable. */
	for (i = 0; i < mpq_archive->mpq_header->hash_table_length; i++) {
		if ((number - 1) == (mpq_archive->mpq_hash[i]).block_table_index) {

			/* correct hashtable found. */
			blockindex = (mpq_archive->mpq_hash[i]).block_table_index;
			mpq_hash = &(mpq_archive->mpq_hash[i]);

			/* break execution. */
			break;
		}
	}

	/* check if file was found. */
	if (blockindex == -1 || blockindex > mpq_archive->mpq_header->block_table_length) {

		/* file was not found in mpq archive. :( */
		return LIBMPQ_FILE_ERROR_EXIST;
	}

	/* check if sizes are correct. */
	mpq_block = mpq_archive->mpq_block + blockindex;
	if (mpq_block->offset > (mpq_archive->mpq_header->archive_size + mpq_archive->mpqpos) || mpq_block->archived_size > mpq_archive->mpq_header->archive_size) {

		/* file is corrupt in mpq archive. */
		return LIBMPQ_FILE_ERROR_CORRUPT;
	}

	/* check if file exists. */
	if ((mpq_block->flags & LIBMPQ_FILE_EXISTS) == 0) {

		/* file does not exist in mpq archive. */
		return LIBMPQ_FILE_ERROR_EXIST;
	}

	/* check which information type should be returned. */
	switch (infotype) {
		case LIBMPQ_FILE_COMPRESSED_SIZE:

			/* return the compressed size of the file in the mpq archive. */
			return mpq_block->archived_size;
		case LIBMPQ_FILE_UNCOMPRESSED_SIZE:

			/* return the uncompressed size of the file in the mpq archive. */
			return mpq_block->size;
		case LIBMPQ_FILE_COMPRESSION_TYPE:

			/* check if compression type is pkware. */
			if (mpq_block->flags & LIBMPQ_FILE_COMPRESS_PKWARE) {

				/* return the compression type pkware. */
				return LIBMPQ_FILE_COMPRESS_PKWARE;
			}

			/* check if compression type is multi. */
			if (mpq_block->flags & LIBMPQ_FILE_COMPRESS_MULTI) {

				/* return the compression type multi. */
				return LIBMPQ_FILE_COMPRESS_MULTI;
			}
		default:

			/* if no error was found, return zero. */
			return LIBMPQ_SUCCESS;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function returns filename by the given number. */
char *libmpq__file_name(mpq_archive_s *mpq_archive, const unsigned int number) {

	/* check if we are in the range of available files. */
	if (number < 1 || number > mpq_archive->mpq_header->block_table_length) {

		/* file not found by number, so return NULL. */
		return NULL;
	}

	/* return the filename. */
	return mpq_archive->mpq_list->mpq_files[number - 1];
}

/* this function returns filenumber by the given name. */
int libmpq__file_number(mpq_archive_s *mpq_archive, const char *name) {

	/* some common variables. */
	unsigned int i;

	/* loop through all filenames in mpq archive. */
	for (i = 0; mpq_archive->mpq_list->mpq_files[i]; i++) {

		/* check if given filename was found in list. */
		if (strncmp(mpq_archive->mpq_list->mpq_files[i], name, strlen(name)) == 0) {

			/* if file found return the number */
			return i + 1;
		}
	}

	/* if no matching entry found, so return error. */
	return LIBMPQ_FILE_ERROR_EXIST;
}

/* this function extracts a file from a mpq archive by the given number. */
int libmpq__file_extract(mpq_archive_s *mpq_archive, const unsigned int number) {

	/* some common variables. */
	mpq_file_s *mpq_file   = NULL;
	mpq_block_s *mpq_block = NULL;
	mpq_hash_s *mpq_hash   = NULL;
	int blockindex         = -1;
	int fd                 = 0;
	int transferred        = 1;
	int i;
	unsigned char buffer[0x1000];

	/* check if we are in the range of available files. */
	if (number < 1 || number > mpq_archive->mpq_header->block_table_length) {

		/* file not found by number, so return with error. */
		return LIBMPQ_FILE_ERROR_RANGE;
	}

	/* open file in write mode. */
	fd = open(mpq_archive->mpq_list->mpq_files[number - 1], O_RDWR|O_CREAT|O_TRUNC, 0644);

	/* check if file could be written. */
	if (fd == -1) {

		/* file could not be created, so return with error. */
		return LIBMPQ_FILE_ERROR_OPEN;
	}

	/* search for correct hashtable. */
	for (i = 0; i < mpq_archive->mpq_header->hash_table_length; i++) {
		if ((number - 1) == (mpq_archive->mpq_hash[i]).block_table_index) {

			/* correct hashtable found. */
			blockindex = (mpq_archive->mpq_hash[i]).block_table_index;
			mpq_hash = &(mpq_archive->mpq_hash[i]);

			/* break execution. */
			break;
		}
	}

	/* check if file was found. */
	if (blockindex == -1 || blockindex > mpq_archive->mpq_header->block_table_length) {

		/* file was not found in mpq archive. :( */
		return LIBMPQ_FILE_ERROR_EXIST;
	}

	/* check if sizes are correct. */
	mpq_block = mpq_archive->mpq_block + blockindex;
	if (mpq_block->offset > (mpq_archive->mpq_header->archive_size + mpq_archive->mpqpos) || mpq_block->archived_size > mpq_archive->mpq_header->archive_size) {

		/* file is corrupt in mpq archive. */
		return LIBMPQ_FILE_ERROR_CORRUPT;
	}

	/* check if file exists. */
	if ((mpq_block->flags & LIBMPQ_FILE_EXISTS) == 0) {

		/* file does not exist in mpq archive. */
		return LIBMPQ_FILE_ERROR_EXIST;
	}

	/* allocate memory for file structure */
	mpq_file = malloc(sizeof(mpq_file_s));
	if (!mpq_file) {

		/* memory allocation problem. */
		return LIBMPQ_FILE_ERROR_MALLOC;
	}

	/* initialize file structure. */
	memset(mpq_file, 0, sizeof(mpq_file_s));
	mpq_file->fd             = fd;
	mpq_file->mpq_block      = mpq_block;
	mpq_file->nblocks        = (mpq_file->mpq_block->size + mpq_archive->blocksize - 1) / mpq_archive->blocksize;
	mpq_file->mpq_hash       = mpq_hash;
	mpq_file->accessed       = FALSE;
	mpq_file->blockposloaded = FALSE;
	snprintf((char *)mpq_file->filename, PATH_MAX, (const char *)mpq_archive->mpq_list->mpq_files[number - 1]);

	/* allocate buffers for decompression. */
	if (mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) {

		/* allocate buffer for block positions. */
		if ((mpq_file->blockpos = malloc(sizeof(int) * mpq_file->nblocks + 1)) == NULL) {

			/* memory allocation problem. */
			return LIBMPQ_FILE_ERROR_MALLOC;
		}
	}

	/* loop until whole file content is written. */
	while (transferred > 0) {

		/* read file until its end. */
		transferred = libmpq__read_file_mpq(mpq_archive, mpq_file, mpq_file->filepos, buffer, sizeof(buffer));

		/* check if we reached end of file. */
		if (transferred == 0) {

			/* break execution. */
			break;
		} else {

			/* file was already processed in this loop. */
			mpq_file->accessed  = TRUE;
			mpq_file->filepos  += transferred;
		}

		/* write file to disk. */
		transferred = write(mpq_file->fd, buffer, transferred);

		/* check if write operations was successful. */
		if (transferred == 0) {

			/* break execution. */
			break;
		}
	}

	/* check if file descriptor is valid. */
	if ((close(fd)) == -1) {

		/* file was not opened. */
		return LIBMPQ_FILE_ERROR_CLOSE;
	}

	/* freeing the file structure. */
	free(mpq_file);

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}
