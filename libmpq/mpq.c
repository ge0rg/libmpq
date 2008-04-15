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
int32_t libmpq__init(void) {

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
int32_t libmpq__shutdown(void) {
	CHECK_IS_INITIALIZED();

	init_count--;

	if (!init_count) {
		free(crypt_buf);
		crypt_buf = NULL;
	}

	return LIBMPQ_SUCCESS;
}

/* this function returns the library version information. */
const char *libmpq__version(void) {

	/* return version information. */
	return VERSION;
}

/* this function read a file and verify if it is a valid mpq archive, then it read and decrypt the hash table. */
int32_t libmpq__archive_open(mpq_archive_s **mpq_archive, const char *mpq_filename, uint32_t archive_offset) {

	/* some common variables. */
	uint32_t rb             = 0;
	uint32_t i              = 0;
	uint32_t count          = 0;
	int32_t result          = 0;
	uint32_t header_search	= FALSE;

	CHECK_IS_INITIALIZED();

	if (archive_offset == (uint32_t) -1) {
		archive_offset = 0;
		header_search = TRUE;
	}

	if ((*mpq_archive = calloc(1, sizeof(mpq_archive_s))) == NULL) {

		/* archive struct could not be allocated */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* check if file exists and is readable */
	if (((*mpq_archive)->fp = fopen(mpq_filename, "rb")) == NULL) {

		/* clean up */
		free(*mpq_archive);

		/* file could not be opened. */
		return LIBMPQ_ERROR_OPEN;
	}

	/* allocate memory for the mpq header and file list. */
	if (((*mpq_archive)->mpq_header = calloc(1, sizeof(mpq_header_s))) == NULL) {

		fclose((*mpq_archive)->fp);
		free(*mpq_archive);

		/* header struct could not be allocated */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* assign some default values. */
	(*mpq_archive)->mpq_header->mpq_magic = 0;
	(*mpq_archive)->files                 = 0;

	/* loop through file and search for mpq signature. */
	while (TRUE) {

		/* reset header values. */
		(*mpq_archive)->mpq_header->mpq_magic = 0;

		/* seek in file. */
		if (fseek((*mpq_archive)->fp, archive_offset, SEEK_SET) < 0) {

			/* clean up */
			fclose((*mpq_archive)->fp);
			free((*mpq_archive)->mpq_header);
			free(*mpq_archive);

			/* seek in file failed. */
			return LIBMPQ_ERROR_SEEK;
		}

		/* read header from file. */
		if ((rb = fread((*mpq_archive)->mpq_header, 1, sizeof(mpq_header_s), (*mpq_archive)->fp)) != sizeof(mpq_header_s)) {

			/* clean up */
			fclose((*mpq_archive)->fp);
			free((*mpq_archive)->mpq_header);
			free(*mpq_archive);

			/* no valid mpq archive. */
			return LIBMPQ_ERROR_FORMAT;
		}

		/* check if we found a valid mpq header. */
		if ((*mpq_archive)->mpq_header->mpq_magic == LIBMPQ_HEADER) {

			/* check if we process old mpq archive version. */
			if ((*mpq_archive)->mpq_header->version == LIBMPQ_ARCHIVE_VERSION_ONE) {

				/* check if the archive is protected. */
				if ((*mpq_archive)->mpq_header->header_size != sizeof(mpq_header_s)) {

					/* correct header size. */
					(*mpq_archive)->mpq_header->header_size = sizeof(mpq_header_s);
				}

				/* break the loop, because header was found. */
				break;
			}

			/* check if we process new mpq archive version. */
			if ((*mpq_archive)->mpq_header->version == LIBMPQ_ARCHIVE_VERSION_TWO) {

				/* clean up */
				fclose((*mpq_archive)->fp);
				free((*mpq_archive)->mpq_header);
				free(*mpq_archive);

				/* TODO: add support for mpq version two. */
				/* support for version two will be added soon. */
				return LIBMPQ_ERROR_FORMAT;
			}
		}

		/* move to the next possible offset. */
		if (!header_search) {
			/* clean up */
			fclose((*mpq_archive)->fp);
			free((*mpq_archive)->mpq_header);
			free(*mpq_archive);

			/* no valid mpq archive. */
			return LIBMPQ_ERROR_FORMAT;
		}
		archive_offset += 512;
	}

	/* store block size for later use. */
	(*mpq_archive)->block_size = 512 << (*mpq_archive)->mpq_header->block_size;

	/* store archive offset for later use. */
	(*mpq_archive)->archive_offset = archive_offset;

	/* allocate memory for the block table and hash table. */
	if (((*mpq_archive)->mpq_block = calloc((*mpq_archive)->mpq_header->block_table_count, sizeof(mpq_block_s))) == NULL ||
	    ((*mpq_archive)->mpq_hash  = calloc((*mpq_archive)->mpq_header->hash_table_count,  sizeof(mpq_hash_s))) == NULL) {

		/* clean up */
		fclose((*mpq_archive)->fp);
		free((*mpq_archive)->mpq_header);
		free(*mpq_archive);

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* try to read and decrypt the hash table. */
	if ((result = libmpq__read_table_hash(*mpq_archive, crypt_buf)) != 0) {

		/* clean up */
		fclose((*mpq_archive)->fp);

		free((*mpq_archive)->mpq_hash);
		free((*mpq_archive)->mpq_block);
		free((*mpq_archive)->mpq_header);
		free(*mpq_archive);

		/* the hash table seems corrupt. */
		return result;
	}

	/* try to read and decrypt the block table. */
	if ((result = libmpq__read_table_block((*mpq_archive), crypt_buf)) != 0) {

		/* clean up */
		fclose((*mpq_archive)->fp);

		free((*mpq_archive)->mpq_hash);
		free((*mpq_archive)->mpq_block);
		free((*mpq_archive)->mpq_header);
		free(*mpq_archive);

		/* the block table seems corrupt. */
		return result;
	}

	/* allocate memory for the mpq header and file list. */
	if (((*mpq_archive)->mpq_list = calloc(1, sizeof(mpq_list_s))) == NULL) {

		/* clean up */
		fclose((*mpq_archive)->fp);

		free((*mpq_archive)->mpq_hash);
		free((*mpq_archive)->mpq_block);
		free((*mpq_archive)->mpq_header);
		free(*mpq_archive);

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* allocate memory, some mpq archives have block table greater than hash table, avoid buffer overruns. */
	if (((*mpq_archive)->mpq_file                      = calloc((*mpq_archive)->mpq_header->hash_table_count,  sizeof(mpq_file_s))) == NULL ||
	    ((*mpq_archive)->mpq_list->block_table_indices = calloc((*mpq_archive)->mpq_header->block_table_count, sizeof(uint32_t))) == NULL) {

		/* clean up */
		fclose((*mpq_archive)->fp);

		free((*mpq_archive)->mpq_list);
		free((*mpq_archive)->mpq_hash);
		free((*mpq_archive)->mpq_block);
		free((*mpq_archive)->mpq_header);
		free(*mpq_archive);

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* loop through all files in mpq archive and check if they are valid. */
	for (i = 0; i < (*mpq_archive)->mpq_header->block_table_count; i++) {

		/* check if file exists, sizes and offsets are correct. */
		if (((*mpq_archive)->mpq_block[i].flags & LIBMPQ_FLAG_EXISTS) == 0 ||
		     (*mpq_archive)->mpq_block[i].offset > (*mpq_archive)->mpq_header->archive_size ||
		     (*mpq_archive)->mpq_block[i].compressed_size > (*mpq_archive)->mpq_header->archive_size ||
		     (*mpq_archive)->mpq_block[i].uncompressed_size == 0) {

			/* file does not exist, so nothing to do with that block. */
			continue;
		}

		/* create final indices tables. */
		(*mpq_archive)->mpq_list->block_table_indices[count] = i;

		/* increase file counter. */
		count++;
	}

	/* save the number of files. */
	(*mpq_archive)->files = count;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function close the file descriptor, free the decryption buffer and the file list. */
int32_t libmpq__archive_close(mpq_archive_s *mpq_archive) {

	CHECK_IS_INITIALIZED();

	/* try to close the file */
	if ((fclose(mpq_archive->fp)) < 0) {
		/* don't free anything here, so the caller can try calling us
		 * again.
		 */
		return LIBMPQ_ERROR_CLOSE;
	}

	/* free header, tables and list. */
	free(mpq_archive->mpq_list->block_table_indices);
	free(mpq_archive->mpq_list);
	free(mpq_archive->mpq_file);
	free(mpq_archive->mpq_hash);
	free(mpq_archive->mpq_block);
	free(mpq_archive->mpq_header);
	free(mpq_archive);

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
			return mpq_archive->mpq_header->archive_size + mpq_archive->archive_offset;
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

	/* check if file is not stored in a single sector. */
	if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

		/* get compressed size based on block size and block count. */
		compressed_size = sizeof(uint32_t) * (((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size) + 1);
	} else {

		/* file is stored in single sector and we need only two entries for the compressed block offset table. */
		compressed_size = sizeof(uint32_t) * 2;
	}

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
		if (fseek(mpq_archive->fp, mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].offset + mpq_archive->archive_offset, SEEK_SET) < 0) {

			/* free compressed block offset table and file pointer. */
			free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
			free(mpq_archive->mpq_file[file_number - 1]);

			/* seek in file failed. */
			return LIBMPQ_ERROR_SEEK;
		}

		/* read block positions from begin of file. */
		if ((rb = fread(mpq_archive->mpq_file[file_number - 1]->compressed_offset, 1, compressed_size, mpq_archive->fp)) < 0) {

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
			if ((mpq_archive->mpq_file[file_number - 1]->seed = libmpq__decrypt_key((uint8_t *)mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, mpq_archive->block_size, crypt_buf)) < 0) {

				/* free compressed block offset table, file pointer and mpq buffer. */
				free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				free(mpq_archive->mpq_file[file_number - 1]);

				/* sorry without seed, we cannot extract file. */
				return LIBMPQ_ERROR_DECRYPT;
			}

			/* decrypt block in input buffer. */
			if ((tb = libmpq__decrypt_block(mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, mpq_archive->mpq_file[file_number - 1]->seed - 1, crypt_buf)) < 0 ) {

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

		/* check if file is not stored in a single sector. */
		if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

			/* loop thr ugh all blocks and create compressed block offset table based on block size. */
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
		} else {

			/* store offsets. */
			mpq_archive->mpq_file[file_number - 1]->compressed_offset[0] = 0;
			mpq_archive->mpq_file[file_number - 1]->compressed_offset[1] = mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
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
		case LIBMPQ_FILE_PACKED_SIZE:

			/* return the compressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
		case LIBMPQ_FILE_UNPACKED_SIZE:

			/* return the uncompressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size;
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
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].offset + mpq_archive->archive_offset;
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
int32_t libmpq__file_name(mpq_archive_s *mpq_archive, uint32_t file_number, char *filename, size_t filename_size) {

	CHECK_IS_INITIALIZED();

	/* check if we are in the range of available files. */
	if (file_number < 1 || file_number > mpq_archive->files) {
		/* file not in valid range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* file was found but no internal listfile exist. */
	snprintf(filename, filename_size, "file%06i.xxx", file_number);

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return filenumber by the given name. */
int32_t libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename) {

	/* some common variables. */
	uint32_t i, hash1, hash2, hash3, ht_count;

	CHECK_IS_INITIALIZED();

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

/* this function read the given file from archive into a buffer. */
int32_t libmpq__file_read(mpq_archive_s *mpq_archive, uint8_t *out_buf, uint32_t out_size, uint32_t file_number) {

	/* some common variables. */
	int32_t tb = 0;
	int32_t rb = 0;
	uint32_t file_offset;
	uint32_t blocks;
	uint32_t unpacked_size;
	uint32_t i;

	CHECK_IS_INITIALIZED();

	/* check if file and block exist in archive. */
	if ((file_offset = libmpq__file_info(mpq_archive, LIBMPQ_FILE_OFFSET, file_number)) < 0) {

		/* file or block does not exist. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if target buffer is to small. */
	if ((libmpq__file_info(mpq_archive, LIBMPQ_FILE_UNPACKED_SIZE, file_number)) < 0 ||
	    (libmpq__file_info(mpq_archive, LIBMPQ_FILE_UNPACKED_SIZE, file_number)) > out_size) {

		/* output buffer size is to small or block size is unknown. */
		return LIBMPQ_ERROR_SIZE;
	}

	/* seek in file. */
	if (fseek(mpq_archive->fp, file_offset, SEEK_SET) < 0) {

		/* something with seek in file failed. */
		return LIBMPQ_ERROR_SEEK;
	}

	/* get block count for file. */
	blocks = libmpq__file_info(mpq_archive, LIBMPQ_FILE_BLOCKS, file_number);

	/* loop through all blocks. */
	for (i = 1; i <= blocks; i++) {

		/* get unpacked block size. */
		unpacked_size = libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_UNPACKED_SIZE, file_number, i);

		/* read block. */
		if ((rb = libmpq__block_read(mpq_archive, out_buf + tb, unpacked_size, file_number, i)) < 0) {

			/* something on reading block failed. */
			return rb;
		}

		/* save the number of transferred bytes. */
		tb += rb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
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
		case LIBMPQ_BLOCK_PACKED_SIZE:

			/* return the compressed size of the block in the mpq archive. */
			return mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number] - mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number - 1];
		case LIBMPQ_BLOCK_UNPACKED_SIZE:

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
		case LIBMPQ_BLOCK_OFFSET:

			/* return the absolute block start position in archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].offset + mpq_archive->archive_offset + mpq_archive->mpq_file[file_number - 1]->compressed_offset[block_number - 1];
		case LIBMPQ_BLOCK_SEED:

			/* return the seed of the block for decryption. */
			return mpq_archive->mpq_file[file_number - 1]->seed + block_number - 1;
		default:

			/* if info type was not found, return error. */
			return LIBMPQ_ERROR_INFO;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function read the given block from archive into a buffer. */
int32_t libmpq__block_read(mpq_archive_s *mpq_archive, uint8_t *out_buf, uint32_t out_size, uint32_t file_number, uint32_t block_number) {

	/* some common variables. */
	int32_t tb = 0;
	uint32_t block_offset;
	uint32_t seed;
	uint8_t *in_buf;
	uint32_t in_size;

	CHECK_IS_INITIALIZED();

	/* check if file and block exist in archive. */
	if ((block_offset = libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_OFFSET, file_number, block_number)) < 0) {

		/* file or block does not exist. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if target buffer is to small. */
	if ((libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_UNPACKED_SIZE, file_number, block_number)) < 0 ||
	    (libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_UNPACKED_SIZE, file_number, block_number)) > out_size) {

		/* output buffer size is to small or block size is unknown. */
		return LIBMPQ_ERROR_SIZE;
	}

	/* seek in file. */
	if (fseek(mpq_archive->fp, block_offset, SEEK_SET) < 0) {

		/* something with seek in file failed. */
		return LIBMPQ_ERROR_SEEK;
	}

	/* get buffer sizes. */
	in_size = libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_PACKED_SIZE, file_number, block_number);

	/* allocate memory for the read buffer. */
	if ((in_buf = calloc(1, in_size)) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* read block from file. */
	if (fread(in_buf, 1, in_size, mpq_archive->fp) < 0) {

		/* free buffers. */
		free(in_buf);

		/* something on reading block failed. */
		return LIBMPQ_ERROR_READ;
	}

	/* check if file is encrypted. */
	if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_ENCRYPTED, file_number) == 1) {

		/* get decryption key. */
		seed = libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_SEED, file_number, block_number);

		/* decrypt block. */
		if ((tb = libmpq__decrypt_block((uint32_t *)in_buf, in_size, seed, crypt_buf)) < 0) {

			/* free buffers. */
			free(in_buf);

			/* something on decrypting block failed. */
			return LIBMPQ_ERROR_DECRYPT;
		}
	}

	/* check if file is compressed. */
	if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_COMPRESSED, file_number) == 1) {

		/* decompress block. */
		if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_MULTI)) < 0) {

			/* free temporary buffer. */
			free(in_buf);

			/* something on decompressing block failed. */
			return LIBMPQ_ERROR_DECOMPRESS;
		}
	}

	/* check if file is imploded. */
	if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_IMPLODED, file_number) == 1) {

		/* explode block. */
		if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_PKWARE)) < 0) {

			/* free temporary buffer. */
			free(in_buf);

			/* something on decompressing block failed. */
			return LIBMPQ_ERROR_DECOMPRESS;
		}
	}

	/* check if file is neither compressed nor imploded. */
	if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_COPIED, file_number) == 1) {

		/* copy block. */
		if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_NONE)) < 0) {

			/* free temporary buffer. */
			free(in_buf);

			/* something on decompressing block failed. */
			return LIBMPQ_ERROR_DECOMPRESS;
		}
	}

	/* free read buffer. */
	free(in_buf);

	/* if no error was found, return transferred bytes. */
	return tb;
}
