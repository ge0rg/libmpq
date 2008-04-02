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
#include "mpq-internal.h"

/* libmpq generic includes. */
#include "common.h"

/* mpq-tools configuration includes. */
#include "config.h"

#define CHECK_IS_INITIALIZED() \
	if (init_count <= 0) return LIBMPQ_ERROR_NOT_INITIALIZED

/* stores how many times libmpq__init() was called.
 * for each of those calls, libmpq__shutdown() needs to be called.
 */
static int32_t init_count;

/* the global shared decryption buffer. it's set up by libmpq__init()
 * and killed by libmpq__shutdown().
 */
static uint32_t *crypt_buf;

/* initializes libmpq. returns < 0 on failure, 0 on success. */
int32_t libmpq__init() {

	if (init_count == 0) {
		crypt_buf = malloc(sizeof(uint32_t) * LIBMPQ_BUFFER_SIZE);

		if (!crypt_buf)
			return LIBMPQ_ERROR_MALLOC;

		if (libmpq__decrypt_buffer_init(crypt_buf) < 0) {
			free(crypt_buf);
			crypt_buf = NULL;

			return LIBMPQ_ERROR_DECRYPT;
		}
	}

	init_count++;

	return LIBMPQ_SUCCESS;
}

/* shuts down libmpq. */
int32_t libmpq__shutdown() {
	CHECK_IS_INITIALIZED();

	init_count--;

	if (!init_count) {
		free(crypt_buf);
		crypt_buf = NULL;
	}

	return LIBMPQ_SUCCESS;
}

/* this function returns the library version information. */
const char *libmpq__version() {

	/* return version information. */
	return VERSION;
}

/* this function read a file and verify if it is a valid mpq archive, then it read and decrypt the hash table. */
int32_t libmpq__archive_open(mpq_archive_s *mpq_archive, const char *mpq_filename) {

	/* some common variables. */
	uint32_t rb             = 0;
	uint32_t archive_offset = 0;
	uint32_t i              = 0;
	int32_t result          = 0;

	CHECK_IS_INITIALIZED();

	/* check if file exists and is readable */
	if ((mpq_archive->fd = open(mpq_filename, O_RDONLY)) < 0) {

		/* file could not be opened. */
		return LIBMPQ_ERROR_OPEN;
	}

	/* allocate memory for the mpq header and file list. */
	if ((mpq_archive->mpq_header = calloc(1, sizeof(mpq_header_s))) == NULL) {

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* fill the structures with informations. */
	strncpy(mpq_archive->filename, mpq_filename, strlen(mpq_filename));

	/* assign some default values. */
	mpq_archive->mpq_header->mpq_magic = 0;
	mpq_archive->files                 = 0;

	/* loop through file and search for mpq signature. */
	while (TRUE) {

		/* reset header values. */
		mpq_archive->mpq_header->mpq_magic = 0;

		/* seek in file. */
		if (lseek(mpq_archive->fd, archive_offset, SEEK_SET) < 0) {

			/* free the allocated memory for mpq header. */
			free(mpq_archive->mpq_header);

			/* check if file descriptor is valid. */
			if ((close(mpq_archive->fd)) < 0) {

				/* file was not opened. */
				return LIBMPQ_ERROR_CLOSE;
			}

			/* seek in file failed. */
			return LIBMPQ_ERROR_LSEEK;
		}

		/* read header from file. */
		if ((rb = read(mpq_archive->fd, mpq_archive->mpq_header, sizeof(mpq_header_s))) != sizeof(mpq_header_s)) {

			/* free the allocated memory for mpq header. */
			free(mpq_archive->mpq_header);

			/* check if file descriptor is valid. */
			if ((close(mpq_archive->fd)) < 0) {

				/* file was not opened. */
				return LIBMPQ_ERROR_CLOSE;
			}

			/* no valid mpq archive. */
			return LIBMPQ_ERROR_FORMAT;
		}

		/* check if we found a valid mpq header. */
		if (mpq_archive->mpq_header->mpq_magic == LIBMPQ_HEADER) {

			/* check if we process old mpq archive version. */
			if (mpq_archive->mpq_header->version == LIBMPQ_ARCHIVE_VERSION_ONE) {

				/* check if the archive is protected. */
				if (mpq_archive->mpq_header->header_size != sizeof(mpq_header_s)) {

					/* correct header size. */
					mpq_archive->mpq_header->header_size = sizeof(mpq_header_s);
				}

				/* break the loop, because header was found. */
				break;
			}

			/* check if we process new mpq archive version. */
			if (mpq_archive->mpq_header->version == LIBMPQ_ARCHIVE_VERSION_TWO) {

				/* free the allocated memory for mpq header. */
				free(mpq_archive->mpq_header);

				/* check if file descriptor is valid. */
				if ((close(mpq_archive->fd)) < 0) {

					/* file was not opened. */
					return LIBMPQ_ERROR_CLOSE;
				}

				/* TODO: add support for mpq version two. */
				/* support for version two will be added soon. */
				return LIBMPQ_ERROR_FORMAT;
			}
		}

		/* move to the next possible offset. */
		archive_offset += 512;
	}

	/* store block size for later use. */
	mpq_archive->block_size = 512 << mpq_archive->mpq_header->block_size;

	/* add archive offset to size, hash and block table offset. */
	mpq_archive->mpq_header->archive_size       += archive_offset;
	mpq_archive->mpq_header->hash_table_offset  += archive_offset;
	mpq_archive->mpq_header->block_table_offset += archive_offset;

	/* allocate memory for the block table and hash table. */
	if ((mpq_archive->mpq_block = calloc(mpq_archive->mpq_header->block_table_count, sizeof(mpq_block_s))) == NULL ||
	    (mpq_archive->mpq_hash  = calloc(mpq_archive->mpq_header->hash_table_count,  sizeof(mpq_hash_s))) == NULL) {

		/* free the allocated memory for mpq header. */
		free(mpq_archive->mpq_header);

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* try to read and decrypt the hash table. */
	if ((result = libmpq__read_table_hash(mpq_archive, crypt_buf)) != 0) {

		/* free header and tables. */
		free(mpq_archive->mpq_hash);
		free(mpq_archive->mpq_block);
		free(mpq_archive->mpq_header);

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* the hash table seems corrupt. */
		return result;
	}

	/* try to read and decrypt the block table. */
	if ((result = libmpq__read_table_block(mpq_archive, crypt_buf)) != 0) {

		/* free header and tables. */
		free(mpq_archive->mpq_hash);
		free(mpq_archive->mpq_block);
		free(mpq_archive->mpq_header);

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* the block table seems corrupt. */
		return result;
	}

	/* loop through all files in mpq archive and add archive offset to file offset. */
	for (i = 0; i < mpq_archive->mpq_header->block_table_count; i++) {

		/* add archive offset to file offset. */
		mpq_archive->mpq_block[i].offset += archive_offset;
	}

	/* allocate memory for the mpq header and file list. */
	if ((mpq_archive->mpq_list = calloc(1, sizeof(mpq_list_s))) == NULL) {

		/* free header and tables. */
		free(mpq_archive->mpq_hash);
		free(mpq_archive->mpq_block);
		free(mpq_archive->mpq_header);

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* allocate memory, some mpq archives have block table greater than hash table, avoid buffer overruns. */
	if ((mpq_archive->mpq_file                      = calloc(mpq_archive->mpq_header->hash_table_count,                                                  sizeof(mpq_file_s))) == NULL ||
	    (mpq_archive->mpq_list->file_names          = calloc(max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count), sizeof(char *))) == NULL ||
	    (mpq_archive->mpq_list->block_table_indices = calloc(max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count), sizeof(uint32_t))) == NULL ||
	    (mpq_archive->mpq_list->hash_table_indices  = calloc(max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count), sizeof(uint32_t))) == NULL) {

		/* free header, tables and list. */
		free(mpq_archive->mpq_list);
		free(mpq_archive->mpq_hash);
		free(mpq_archive->mpq_block);
		free(mpq_archive->mpq_header);

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* try to read list file. */
	if ((result = libmpq__read_file_list(mpq_archive)) != 0) {

		/* check if there is some real data in the file list. */
		if (mpq_archive->mpq_list->file_names != NULL) {

			/* free the filelist. */
			for (i = 0; i < max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count); i++) {

				/* free the filelist element. */
				free(mpq_archive->mpq_list->file_names[i]);
			}
		}

		/* free header, tables and list. */
		free(mpq_archive->mpq_list->hash_table_indices);
		free(mpq_archive->mpq_list->block_table_indices);
		free(mpq_archive->mpq_list);
		free(mpq_archive->mpq_file);
		free(mpq_archive->mpq_hash);
		free(mpq_archive->mpq_block);
		free(mpq_archive->mpq_header);

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* the list file seems corrupt. */
		return result;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function close the file descriptor, free the decryption buffer and the file list. */
int32_t libmpq__archive_close(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	uint32_t i;

	CHECK_IS_INITIALIZED();

	/* check if there is some real data in the file list. */
	if (mpq_archive->mpq_list->file_names != NULL) {

		/* free the filelist. */
		for (i = 0; i < max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count); i++) {

			/* free the filelist element. */
			free(mpq_archive->mpq_list->file_names[i]);
		}
	}

	/* free header, tables and list. */
	free(mpq_archive->mpq_list->hash_table_indices);
	free(mpq_archive->mpq_list->block_table_indices);
	free(mpq_archive->mpq_list);
	free(mpq_archive->mpq_file);
	free(mpq_archive->mpq_hash);
	free(mpq_archive->mpq_block);
	free(mpq_archive->mpq_header);

	/* check if file descriptor is valid. */
	if ((close(mpq_archive->fd)) < 0) {

		/* file was not opened. */
		return LIBMPQ_ERROR_CLOSE;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return some information for the requested type of a mpq archive. */
int32_t libmpq__archive_info(mpq_archive_s *mpq_archive, uint32_t info_type) {

	/* some common variables. */
	uint32_t uncompressed_size = 0;
	uint32_t compressed_size   = 0;
	uint32_t i;

	CHECK_IS_INITIALIZED();

	/* check which information type should be returned. */
	switch (info_type) {
		case LIBMPQ_ARCHIVE_SIZE:

			/* return the archive size. */
			return mpq_archive->mpq_header->archive_size;
		case LIBMPQ_ARCHIVE_COMPRESSED_SIZE:

			/* loop through all files in archive and count compressed size. */
			for (i = 0; i < mpq_archive->files; i++) {
				compressed_size += mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[i]].compressed_size;
			}

			/* return the compressed size of all files in the mpq archive. */
			return compressed_size;
		case LIBMPQ_ARCHIVE_UNCOMPRESSED_SIZE:

			/* loop through all files in archive and count compressed size. */
			for (i = 0; i < mpq_archive->files; i++) {
				uncompressed_size += mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[i]].uncompressed_size;
			}

			/* return the uncompressed size of all files in the mpq archive. */
			return uncompressed_size;
		case LIBMPQ_ARCHIVE_FILES:

			/* return the number of files in archive. */
			return mpq_archive->files;
		case LIBMPQ_ARCHIVE_HASHTABLE_ENTRIES:

			/* return the number of hash table entries. */
			return mpq_archive->mpq_header->hash_table_count;
		case LIBMPQ_ARCHIVE_BLOCKTABLE_ENTRIES:

			/* return the number of block table entries. */
			return mpq_archive->mpq_header->block_table_count;
		case LIBMPQ_ARCHIVE_BLOCKSIZE:

			/* return the block size. */
			return mpq_archive->block_size;
		case LIBMPQ_ARCHIVE_VERSION:

			/* return the archive version. */
			return mpq_archive->mpq_header->version + 1;
		default:

			/* if info type was not found, return error. */
			return LIBMPQ_ERROR_INFO;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function open a file in the given archive and caches the block offset information. */
int32_t libmpq__file_open(mpq_archive_s *mpq_archive, uint32_t file_number) {

	/* some common variables. */
	uint32_t i;
	uint32_t compressed_size;
	int32_t rb = 0;
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	compressed_size = sizeof(uint32_t) * (((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size) + 1);

	/* allocate memory for the file. */
	if ((mpq_archive->mpq_file[file_number - 1] = calloc(1, sizeof(mpq_file_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* allocate memory for the compressed block offset table. */
	if ((mpq_archive->mpq_file[file_number - 1]->compressed_offset = calloc(1, compressed_size)) == NULL) {

		/* free file pointer. */
		free(mpq_archive->mpq_file[file_number - 1]);

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* check if we need to load the compressed block offset table, we will maintain this table for uncompressed files too. */
	if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_COMPRESSED) != 0 &&
	    (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

		/* seek to block position. */
		if (lseek(mpq_archive->fd, mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].offset, SEEK_SET) < 0) {

			/* free compressed block offset table and file pointer. */
			free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
			free(mpq_archive->mpq_file[file_number - 1]);

			/* seek in file failed. */
			return LIBMPQ_ERROR_LSEEK;
		}

		/* read block positions from begin of file. */
		if ((rb = read(mpq_archive->fd, mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size)) < 0) {

			/* free compressed block offset table and file pointer. */
			free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
			free(mpq_archive->mpq_file[file_number - 1]);

			/* something on read from archive failed. */
			return LIBMPQ_ERROR_READ;
		}

		/* check if the archive is protected some way, sometimes the file appears not to be encrypted, but it is. */
		if (mpq_archive->mpq_file[file_number - 1]->compressed_offset[0] != rb) {

			/* file is encrypted. */
			mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags |= LIBMPQ_FLAG_ENCRYPTED;
		}

		/* check if compressed offset block is encrypted, we have to decrypt it. */
		if (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_ENCRYPTED) {

			/* check if we don't know the file seed, try to find it. */
			if ((mpq_archive->mpq_file[file_number - 1]->seed = libmpq__decrypt_key((uint8_t *)mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, crypt_buf)) < 0) {

				/* free compressed block offset table, file pointer and mpq buffer. */
				free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				free(mpq_archive->mpq_file[file_number - 1]);

				/* sorry without seed, we cannot extract file. */
				return LIBMPQ_ERROR_DECRYPT;
			}

			/* decrypt block in input buffer. */
			if ((tb = libmpq__decrypt_block((uint8_t *)mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, (uint8_t *)mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, mpq_archive->mpq_file[file_number - 1]->seed - 1, crypt_buf)) < 0 ) {

				/* free compressed block offset table, file pointer and mpq buffer. */
				free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				free(mpq_archive->mpq_file[file_number - 1]);

				/* something on decrypt failed. */
				return LIBMPQ_ERROR_DECRYPT;
			}

			/* check if the block positions are correctly decrypted. */
			if (mpq_archive->mpq_file[file_number - 1]->compressed_offset[0] != compressed_size) {

				/* free compressed block offset table, file pointer. */
				free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				free(mpq_archive->mpq_file[file_number - 1]);

				/* sorry without seed, we cannot extract file. */
				return LIBMPQ_ERROR_DECRYPT;
			}
		}
	} else {

		/* loop through all blocks and create compressed block offset table based on block size. */
		for (i = 0; i < ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size + 1); i++) {

			/* check if we process the last block. */
			if (i == ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size)) {

				/* store size of last block. */
				mpq_archive->mpq_file[file_number - 1]->compressed_offset[i] = mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size;
			} else {

				/* store default block size. */
				mpq_archive->mpq_file[file_number - 1]->compressed_offset[i] = i * mpq_archive->block_size;
			}
		}
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function free the file pointer to the opened file in archive. */
int32_t libmpq__file_close(mpq_archive_s *mpq_archive, uint32_t file_number) {

	CHECK_IS_INITIALIZED();

	/* free compressed block offset table and file pointer. */
	free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
	free(mpq_archive->mpq_file[file_number - 1]);

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return some useful file information. */
int32_t libmpq__file_info(mpq_archive_s *mpq_archive, uint32_t info_type, uint32_t file_number) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 1 || file_number > mpq_archive->files) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check which information type should be returned. */
	switch (info_type) {
		case LIBMPQ_FILE_COMPRESSED_SIZE:

			/* return the compressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
		case LIBMPQ_FILE_UNCOMPRESSED_SIZE:

			/* return the uncompressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size;
		case LIBMPQ_FILE_ENCRYPTED_SIZE:

			/* return the compressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
		case LIBMPQ_FILE_DECRYPTED_SIZE:

			/* return the compressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
		case LIBMPQ_FILE_ENCRYPTED:

			/* return true if file is encrypted, false otherwise. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_ENCRYPTED) != 0 ? TRUE : FALSE;
		case LIBMPQ_FILE_COMPRESSED:

			/* return true if file is compressed, false otherwise. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_COMPRESS_MULTI) != 0 ? TRUE : FALSE;
		case LIBMPQ_FILE_IMPLODED:

			/* return true if file is imploded, false otherwise. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_COMPRESS_PKWARE) != 0 ? TRUE : FALSE;
		case LIBMPQ_FILE_COPIED:

			/* return true if file is neither compressed nor imploded. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_COMPRESS_MULTI) == 0 &&
			    (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_COMPRESS_PKWARE) == 0) {

				/* return true, because file is neither compressed nor imploded. */
				return TRUE;
			} else {

				/* return false, because file is compressed or imploded. */
				return FALSE;
			}
		case LIBMPQ_FILE_SINGLE:

			/* return true if file is stored in single sector, otherwise false. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? TRUE : FALSE;
		case LIBMPQ_FILE_OFFSET:

			/* return the absolute file start position in archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].offset;
		case LIBMPQ_FILE_BLOCKS:

			/* return the number of blocks for file, on single sector files return one. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? 1 : (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size;
		case LIBMPQ_FILE_BLOCKSIZE:

			/* return the blocksize for the file, if file is stored in single sector returns uncompressed size. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size : mpq_archive->block_size;
		default:

			/* if info type was not found, return error. */
			return LIBMPQ_ERROR_INFO;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return filename by the given number. */
const char *libmpq__file_name(mpq_archive_s *mpq_archive, uint32_t file_number) {

	if (init_count <= 0)
		return NULL;

	/* check if we are in the range of available files. */
	if (file_number < 1 || file_number > mpq_archive->files) {

		/* file not found by number, so return NULL. */
		return NULL;
	}

	/* return the filename. */
	return mpq_archive->mpq_list->file_names[file_number - 1];
}

/* this function return filenumber by the given name. */
int32_t libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename) {

	/* some common variables. */
	uint32_t i, hash1, hash2, hash3, ht_count;

	CHECK_IS_INITIALIZED();

	/* loop through all filenames in mpq archive. */
	for (i = 0; mpq_archive->mpq_list->file_names[i]; i++) {

		/* check if given filename was found in list. */
		if (strncmp(mpq_archive->mpq_list->file_names[i], filename, strlen(filename)) == 0) {

			/* if file found return the number */
			return i + 1;
		}
	}

	/* if the list of file names doesn't include this one, we'll have
	 * to figure out the file number the "hard" way.
	 */
	hash1 = libmpq__hash_string (crypt_buf, filename, 0x0);
	hash2 = libmpq__hash_string (crypt_buf, filename, 0x100);
	hash3 = libmpq__hash_string (crypt_buf, filename, 0x200);

	ht_count = mpq_archive->mpq_header->hash_table_count;

	/* loop through all files in mpq archive.
	 * hash1 gives us a clue about the starting position of this
	 * search.
	 */
	for (i = hash1 & (ht_count - 1); i < ht_count; i++) {

		/* check if hashtable is valid for this file. */
		if (mpq_archive->mpq_hash[i].block_table_index == LIBMPQ_HASH_FREE) {

			/* continue because this is an empty hash entry. */
			continue;
		}

		/* if the other two hashes match, we found our file number. */
		if (mpq_archive->mpq_hash[i].hash_a == hash2 &&
		    mpq_archive->mpq_hash[i].hash_b == hash3)
			return mpq_archive->mpq_hash[i].block_table_index + 1;
	}

	/* if no matching entry found, so return error. */
	return LIBMPQ_ERROR_EXIST;
}

/* this function return some useful block information. */
int32_t libmpq__block_info(mpq_archive_s *mpq_archive, uint32_t info_type, uint32_t file_number, uint32_t block_number) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 1 || file_number > mpq_archive->files) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if given block number is not out of range. */
	if (block_number < 1 || block_number > ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? 1 : (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size)) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check which information type should be returned. */
	switch (info_type) {
		case LIBMPQ_BLOCK_COMPRESSED_SIZE:

			/* check if block is stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0) {

				/* return the compressed size of the block in the mpq archive. */
				return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
			}

			/* check if block is not stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

				/* return the compressed size of the block in the mpq archive. */
				return mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number] - mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number - 1];
			}
		case LIBMPQ_BLOCK_UNCOMPRESSED_SIZE:

			/* check if block is stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0) {

				/* return the uncompressed size of the block in the mpq archive. */
				return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size;
			}

			/* check if block is not stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

				/* check if we not process the last block. */
				if (block_number < (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size) {

					/* return the block size as uncompressed size. */
					return mpq_archive->block_size;
				} else {

					/* return the uncompressed size of the last block in the mpq archive. */
					return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size - mpq_archive->block_size * (block_number - 1);
				}
			}
		case LIBMPQ_BLOCK_ENCRYPTED_SIZE:

			/* check if block is stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0) {

				/* return the compressed size of the block in the mpq archive. */
				return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
			}

			/* check if block is not stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

				/* return the compressed size of the block in the mpq archive. */
				return mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number] - mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number - 1];
			}
		case LIBMPQ_BLOCK_DECRYPTED_SIZE:

			/* check if block is stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0) {

				/* return the compressed size of the block in the mpq archive. */
				return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
			}

			/* check if block is not stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

				/* return the compressed size of the block in the mpq archive. */
				return mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number] - mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number - 1];
			}
		case LIBMPQ_BLOCK_OFFSET:

			/* check if block is stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0) {

				/* return the uncompressed size of the block in the mpq archive. */
				return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].offset;
			}

			/* check if block is not stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

				/* return the absolute block start position in archive. */
				return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].offset + mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number - 1];
			}
		case LIBMPQ_BLOCK_SEED:

			/* check if block is stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0) {

				/* return zero as seed. */
				return 0;
			}

			/* check if block is not stored as single sector. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

				/* return the seed of the block for decryption. */
				return mpq_archive->mpq_file[file_number - 1]->seed + block_number - 1;
			}
		default:

			/* if info type was not found, return error. */
			return LIBMPQ_ERROR_INFO;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function decrypt the given block in input buffer to output buffer. */
int32_t libmpq__block_decrypt(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t seed) {

	/* some common variables. */
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	/* decrypt the mpq block. */
	if ((tb = libmpq__decrypt_block(in_buf, in_size, out_buf, out_size, seed, crypt_buf)) < 0) {

		/* something on decrypt failed. */
		return LIBMPQ_ERROR_DECRYPT;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function decompress the given block in input buffer to output buffer. */
int32_t libmpq__block_decompress(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size) {

	/* some common variables. */
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	/* call real decompress function. */
	if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_MULTI)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function explode the given block in input buffer to output buffer. */
int32_t libmpq__block_explode(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size) {

	/* some common variables. */
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	/* call real decompress function. */
	if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_PKWARE)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function copy the given block in input buffer to output buffer. */
int32_t libmpq__block_copy(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size) {

	/* some common variables. */
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	/* call real decompress function. */
	if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_NONE)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function decrypt the given input buffer to output buffer. */
int32_t libmpq__memory_decrypt(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_count) {

	/* some common variables. */
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	/* call real decrypt function. */
	if ((tb = libmpq__decrypt_memory(in_buf, in_size, out_buf, out_size, block_count, crypt_buf)) < 0) {

		/* sorry without seed, we cannot extract file. */
		return LIBMPQ_ERROR_DECRYPT;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function decompress the given input buffer to output buffer. */
int32_t libmpq__memory_decompress(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_size) {

	/* some common variables. */
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	/* call real decompress function. */
	if ((tb = libmpq__decompress_memory(in_buf, in_size, out_buf, out_size, block_size, LIBMPQ_FLAG_COMPRESS_MULTI)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function explode the given input buffer to output buffer. */
int32_t libmpq__memory_explode(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_size) {

	/* some common variables. */
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	/* call real decompress function. */
	if ((tb = libmpq__decompress_memory(in_buf, in_size, out_buf, out_size, block_size, LIBMPQ_FLAG_COMPRESS_PKWARE)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function copy the given input buffer to output buffer. */
int32_t libmpq__memory_copy(uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size, uint32_t block_size) {

	/* some common variables. */
	int32_t tb = 0;

	CHECK_IS_INITIALIZED();

	/* call real decompress function. */
	if ((tb = libmpq__decompress_memory(in_buf, in_size, out_buf, out_size, block_size, LIBMPQ_FLAG_COMPRESS_NONE)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}
