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

/* mpq-tools configuration includes. */
#include "config.h"

/* libmpq main includes. */
#include "mpq.h"
#include "mpq-internal.h"

/* libmpq generic includes. */
#include "common.h"

/* generic includes. */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK_IS_INITIALIZED() \
	if (init_count <= 0) return LIBMPQ_ERROR_NOT_INITIALIZED

/* stores how many times libmpq__init() was called.
 * for each of those calls, libmpq__shutdown() needs to be called.
 */
static int32_t init_count;

/* initializes libmpq. returns < 0 on failure, 0 on success. */
int32_t libmpq__init(void) {
	init_count++;

	if (init_count == 1) {
		return libmpq__decrypt_buffer_init();
	}

	return LIBMPQ_SUCCESS;
}

/* shuts down libmpq. */
int32_t libmpq__shutdown(void) {
	CHECK_IS_INITIALIZED();

	init_count--;

	if (!init_count) {
		return libmpq__decrypt_buffer_deinit();
	}

	return LIBMPQ_SUCCESS;
}

/* this function returns the library version information. */
const char *libmpq__version(void) {

	/* return version information. */
	return VERSION;
}

/* this function read a file and verify if it is a valid mpq archive, then it read and decrypt the hash table. */
int32_t libmpq__archive_open(mpq_archive_s **mpq_archive, const char *mpq_filename, off_t archive_offset) {

	/* some common variables. */
	uint32_t rb             = 0;
	uint32_t i              = 0;
	uint32_t count          = 0;
	int32_t result          = 0;
	uint32_t header_search	= FALSE;

	CHECK_IS_INITIALIZED();

	if (archive_offset == (off_t) -1) {
		archive_offset = 0;
		header_search = TRUE;
	}

	if ((*mpq_archive = calloc(1, sizeof(mpq_archive_s))) == NULL) {

		/* archive struct could not be allocated */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* check if file exists and is readable */
	if (((*mpq_archive)->fp = fopen(mpq_filename, "rb")) == NULL) {

		/* file could not be opened. */
		result = LIBMPQ_ERROR_OPEN;
		goto error;
	}

	/* assign some default values. */
	(*mpq_archive)->mpq_header.mpq_magic = 0;
	(*mpq_archive)->files                = 0;

	/* loop through file and search for mpq signature. */
	while (TRUE) {

		/* reset header values. */
		(*mpq_archive)->mpq_header.mpq_magic = 0;

		/* seek in file. */
		if (fseeko((*mpq_archive)->fp, archive_offset, SEEK_SET) < 0) {

			/* seek in file failed. */
			result = LIBMPQ_ERROR_SEEK;
			goto error;
		}

		/* read header from file. */
		if ((rb = fread(&(*mpq_archive)->mpq_header, 1, sizeof(mpq_header_s), (*mpq_archive)->fp)) != sizeof(mpq_header_s)) {

			/* no valid mpq archive. */
			result = LIBMPQ_ERROR_FORMAT;
			goto error;
		}

		/* check if we found a valid mpq header. */
		if ((*mpq_archive)->mpq_header.mpq_magic == LIBMPQ_HEADER) {

			/* check if we process old mpq archive version. */
			if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_ONE) {

				/* check if the archive is protected. */
				if ((*mpq_archive)->mpq_header.header_size != sizeof(mpq_header_s)) {

					/* correct header size. */
					(*mpq_archive)->mpq_header.header_size = sizeof(mpq_header_s);
				}
			}

			/* check if we process new mpq archive version. */
			if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {

				/* check if the archive is protected. */
				if ((*mpq_archive)->mpq_header.header_size != sizeof(mpq_header_s) + sizeof(mpq_header_ex_s)) {

					/* correct header size. */
					(*mpq_archive)->mpq_header.header_size = sizeof(mpq_header_s) + sizeof(mpq_header_ex_s);
				}
			}

			/* break the loop, because header was found. */
			break;
		}

		/* move to the next possible offset. */
		if (!header_search) {

			/* no valid mpq archive. */
			result = LIBMPQ_ERROR_FORMAT;
			goto error;
		}
		archive_offset += 512;
	}

	/* store block size for later use. */
	(*mpq_archive)->block_size = 512 << (*mpq_archive)->mpq_header.block_size;

	/* store archive offset and size for later use. */
	(*mpq_archive)->archive_offset = archive_offset;

	/* check if we process new mpq archive version. */
	if ((*mpq_archive)->mpq_header.version == LIBMPQ_ARCHIVE_VERSION_TWO) {

		/* seek in file. */
		if (fseeko((*mpq_archive)->fp, sizeof(mpq_header_s) + archive_offset, SEEK_SET) < 0) {

			/* seek in file failed. */
			result = LIBMPQ_ERROR_SEEK;
			goto error;
		}

		/* read header from file. */
		if ((rb = fread(&(*mpq_archive)->mpq_header_ex, 1, sizeof(mpq_header_ex_s), (*mpq_archive)->fp)) != sizeof(mpq_header_ex_s)) {

			/* no valid mpq archive. */
			result = LIBMPQ_ERROR_FORMAT;
			goto error;
		}
	}

	/* allocate memory for the block table, hash table, file and block table to file mapping. */
	if (((*mpq_archive)->mpq_block           = calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_s))) == NULL ||
	    ((*mpq_archive)->mpq_block_ex        = calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_block_ex_s))) == NULL ||
	    ((*mpq_archive)->mpq_hash            = calloc((*mpq_archive)->mpq_header.hash_table_count,  sizeof(mpq_hash_s))) == NULL ||
	    ((*mpq_archive)->mpq_file            = calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(mpq_file_s))) == NULL ||
	    ((*mpq_archive)->block_table_indices = calloc((*mpq_archive)->mpq_header.block_table_count, sizeof(uint32_t))) == NULL) {

		/* memory allocation problem. */
		result = LIBMPQ_ERROR_MALLOC;
		goto error;
	}

	/* seek in file. */
	if (fseeko((*mpq_archive)->fp, (*mpq_archive)->mpq_header.hash_table_offset + (((long long)((*mpq_archive)->mpq_header_ex.hash_table_offset_high)) << 32) + (*mpq_archive)->archive_offset, SEEK_SET) < 0) {

		/* seek in file failed. */
		result = LIBMPQ_ERROR_SEEK;
		goto error;
	}

	/* read the hash table into the buffer. */
	if ((rb = fread((*mpq_archive)->mpq_hash, 1, (*mpq_archive)->mpq_header.hash_table_count * sizeof(mpq_hash_s), (*mpq_archive)->fp)) < 0) {

		/* something on read failed. */
		result = LIBMPQ_ERROR_READ;
		goto error;
	}

	/* decrypt the hashtable. */
	libmpq__decrypt_table((uint32_t *)((*mpq_archive)->mpq_hash), "(hash table)", (*mpq_archive)->mpq_header.hash_table_count * 4);

	/* seek in file. */
	if (fseeko((*mpq_archive)->fp, (*mpq_archive)->mpq_header.block_table_offset + (((long long)((*mpq_archive)->mpq_header_ex.block_table_offset_high)) << 32) + (*mpq_archive)->archive_offset, SEEK_SET) < 0) {

		/* seek in file failed. */
		result = LIBMPQ_ERROR_SEEK;
		goto error;
	}

	/* read the block table into the buffer. */
	if ((rb = fread((*mpq_archive)->mpq_block, 1, (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_s), (*mpq_archive)->fp)) < 0) {

		/* something on read failed. */
		result = LIBMPQ_ERROR_READ;
		goto error;
	}

	/* decrypt block table. */
	libmpq__decrypt_table((uint32_t *)((*mpq_archive)->mpq_block), "(block table)", (*mpq_archive)->mpq_header.block_table_count * 4);

	/* check if extended block table is present, regardless of version 2 it is only present in archives > 4GB. */
	if ((*mpq_archive)->mpq_header_ex.extended_offset > 0) {

		/* seek in file. */
		if (fseeko((*mpq_archive)->fp, (*mpq_archive)->mpq_header_ex.extended_offset + archive_offset, SEEK_SET) < 0) {

			/* seek in file failed. */
			result = LIBMPQ_ERROR_SEEK;
			goto error;
		}

		/* read header from file. */
		if ((rb = fread((*mpq_archive)->mpq_block_ex, 1, (*mpq_archive)->mpq_header.block_table_count * sizeof(mpq_block_ex_s), (*mpq_archive)->fp)) < 0) {

			/* no valid mpq archive. */
			result = LIBMPQ_ERROR_FORMAT;
			goto error;
		}
	}

	/* loop through all files in mpq archive and check if they are valid. */
	for (i = 0; i < (*mpq_archive)->mpq_header.block_table_count; i++) {

		/* check if file exists, sizes and offsets are correct. */
		if (((*mpq_archive)->mpq_block[i].flags & LIBMPQ_FLAG_EXISTS) == 0) {

			/* file does not exist, so nothing to do with that block. */
			continue;
		}

		/* create final indices tables. */
		(*mpq_archive)->block_table_indices[count] = i;

		/* increase file counter. */
		count++;
	}

	/* save the number of files. */
	(*mpq_archive)->files = count;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;

error:
	if ((*mpq_archive)->fp)
		fclose((*mpq_archive)->fp);

	free((*mpq_archive)->block_table_indices);
	free((*mpq_archive)->mpq_file);
	free((*mpq_archive)->mpq_hash);
	free((*mpq_archive)->mpq_block);
	free((*mpq_archive)->mpq_block_ex);
	free(*mpq_archive);

	*mpq_archive = NULL;

	return result;
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
	free(mpq_archive->block_table_indices);
	free(mpq_archive->mpq_file);
	free(mpq_archive->mpq_hash);
	free(mpq_archive->mpq_block);
	free(mpq_archive->mpq_block_ex);
	free(mpq_archive);

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the packed size of all files in the archive. */
int32_t libmpq__archive_packed_size(mpq_archive_s *mpq_archive, off_t *packed_size) {

	/* some common variables. */
	uint32_t i;

	CHECK_IS_INITIALIZED();

	/* loop through all files in archive and count packed size. */
	for (i = 0; i < mpq_archive->files; i++) {
		*packed_size += mpq_archive->mpq_block[mpq_archive->block_table_indices[i]].packed_size;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the unpacked size of all files in the archive. */
int32_t libmpq__archive_unpacked_size(mpq_archive_s *mpq_archive, off_t *unpacked_size) {

	/* some common variables. */
	uint32_t i;

	CHECK_IS_INITIALIZED();

	/* loop through all files in archive and count unpacked size. */
	for (i = 0; i < mpq_archive->files; i++) {
		*unpacked_size += mpq_archive->mpq_block[mpq_archive->block_table_indices[i]].unpacked_size;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the archive offset (beginning of archive in file). */
int32_t libmpq__archive_offset(mpq_archive_s *mpq_archive, off_t *offset) {

	CHECK_IS_INITIALIZED();

	/* return archive offset. */
	*offset = mpq_archive->archive_offset;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the archive offset. */
int32_t libmpq__archive_version(mpq_archive_s *mpq_archive, uint32_t *version) {

	CHECK_IS_INITIALIZED();

	/* return archive version. */
	*version = mpq_archive->mpq_header.version + 1;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the number of valid files in archive. */
int32_t libmpq__archive_files(mpq_archive_s *mpq_archive, uint32_t *files) {

	CHECK_IS_INITIALIZED();

	/* return archive version. */
	*files = mpq_archive->files;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the packed size of the given files in the archive. */
int32_t libmpq__file_packed_size(mpq_archive_s *mpq_archive, uint32_t file_number, off_t *packed_size) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* get the packed size of file. */
	*packed_size = mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].packed_size;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the unpacked size of the given file in the archive. */
int32_t libmpq__file_unpacked_size(mpq_archive_s *mpq_archive, uint32_t file_number, off_t *unpacked_size) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* get the unpacked size of file. */
	*unpacked_size = mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the file offset (beginning of file in archive). */
int32_t libmpq__file_offset(mpq_archive_s *mpq_archive, uint32_t file_number, off_t *offset) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* return file offset relative to archive start. */
	*offset = mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].offset + (((long long)mpq_archive->mpq_block_ex[mpq_archive->block_table_indices[file_number]].offset_high) << 32);

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the number of blocks for the given file in the archive. */
int32_t libmpq__file_blocks(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *blocks) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* return the number of blocks for the given file. */
	*blocks = (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? 1 : (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return if the file is encrypted or not. */
int32_t libmpq__file_encrypted(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *encrypted) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* return the encryption status of file. */
	*encrypted = (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_ENCRYPTED) != 0 ? TRUE : FALSE;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return if the file is compressed or not. */
int32_t libmpq__file_compressed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *compressed) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* return the compression status of file. */
	*compressed = (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_COMPRESS_MULTI) != 0 ? TRUE : FALSE;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return if the file is imploded or not. */
int32_t libmpq__file_imploded(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t *imploded) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* return the implosion status of file. */
	*imploded = (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_COMPRESS_PKWARE) != 0 ? TRUE : FALSE;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return filename by the given number. */
int32_t libmpq__file_name(mpq_archive_s *mpq_archive, uint32_t file_number, char *filename, size_t filename_size) {

	/* some common variables. */
	int32_t result = 0;

	CHECK_IS_INITIALIZED();

	/* check if we are in the range of available files. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file not in valid range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* file was found but no internal listfile exist. */
	if ((result = snprintf(filename, filename_size, "file%06i.xxx", file_number)) < 0) {

		/* something on output conversion failed. */
		return LIBMPQ_ERROR_FORMAT;
	}

	/* if no error was found, return number of bytes converted by snprintf. */
	return result;
}

/* this function return filenumber by the given name. */
int32_t libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename, uint32_t *number) {

	/* some common variables. */
	uint32_t i, j, hash1, hash2, hash3, ht_count;
	uint32_t count = 0;

	CHECK_IS_INITIALIZED();

	/* if the list of file names doesn't include this one, we'll have
	 * to figure out the file number the "hard" way.
	 */
	hash1 = libmpq__hash_string (filename, 0x0);
	hash2 = libmpq__hash_string (filename, 0x100);
	hash3 = libmpq__hash_string (filename, 0x200);

	ht_count = mpq_archive->mpq_header.hash_table_count;

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
		    mpq_archive->mpq_hash[i].hash_b == hash3) {

			/* loop through files in mpq archive until block table index from hash and check if they are valid. */
			for (j = 0; j < mpq_archive->mpq_hash[i].block_table_index; j++) {

				/* check if file exists, sizes and offsets are correct. */
				if ((mpq_archive->mpq_block[j].flags & LIBMPQ_FLAG_EXISTS) == 0) {

					/* file does not exist, so increase counter. */
					count++;
				}
			}

			/* return the file number. */
			*number = mpq_archive->mpq_hash[i].block_table_index - count;

			/* we found our file, return zero. */
			return LIBMPQ_SUCCESS;
		}
	}

	/* if no matching entry found, so return error. */
	return LIBMPQ_ERROR_EXIST;
}

/* this function read the given file from archive into a buffer. */
int32_t libmpq__file_read(mpq_archive_s *mpq_archive, uint32_t file_number, uint8_t *out_buf, off_t out_size, off_t *transferred) {

	/* some common variables. */
	uint32_t i;
	uint32_t blocks         = 0;
	int32_t result          = 0;
	off_t file_offset       = 0;
	off_t unpacked_size     = 0;
	off_t transferred_block = 0;
	off_t transferred_total = 0;

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* get target size of block. */
	libmpq__file_unpacked_size(mpq_archive, file_number, &unpacked_size);

	/* check if target buffer is to small. */
	if (unpacked_size > out_size) {

		/* output buffer size is to small or block size is unknown. */
		return LIBMPQ_ERROR_SIZE;
	}

	/* fetch file offset. */
	libmpq__file_offset(mpq_archive, file_number, &file_offset);

	/* get block count for file. */
	libmpq__file_blocks(mpq_archive, file_number, &blocks);

	/* open the packed block offset table. */
	if ((result = libmpq__block_open_offset(mpq_archive, file_number)) < 0) {

		/* something on opening packed block offset table failed. */
		return result;
	}

	/* loop through all blocks. */
	for (i = 0; i < blocks; i++) {

		/* cleanup size variable. */
		unpacked_size = 0;

		/* get unpacked block size. */
		libmpq__block_unpacked_size(mpq_archive, file_number, i, &unpacked_size);

		/* read block. */
		if ((result = libmpq__block_read(mpq_archive, file_number, i, out_buf + transferred_total, unpacked_size, &transferred_block)) < 0) {

			/* close the packed block offset table. */
			libmpq__block_close_offset(mpq_archive, file_number);

			/* something on reading block failed. */
			return result;
		}

		transferred_total += transferred_block;

	}

	/* close the packed block offset table. */
	libmpq__block_close_offset(mpq_archive, file_number);

	/* check for null pointer. */
	if (transferred != NULL) {

		/* store transferred bytes. */
		*transferred = transferred_total;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function open a file in the given archive and caches the block offset information. */
int32_t libmpq__block_open_offset(mpq_archive_s *mpq_archive, uint32_t file_number) {

	/* some common variables. */
	uint32_t i;
	uint32_t packed_size;
	int32_t rb     = 0;
	int32_t tb     = 0;
	int32_t result = 0;

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if file is not stored in a single sector. */
	if ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

		/* get packed size based on block size and block count. */
		packed_size = sizeof(uint32_t) * (((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size) + 1);
	} else {

		/* file is stored in single sector and we need only two entries for the packed block offset table. */
		packed_size = sizeof(uint32_t) * 2;
	}

	/* check if data has one extra entry. */
	if ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_EXTRA) != 0) {

		/* add one uint32_t. */
		packed_size += sizeof(uint32_t);
	}

	/* allocate memory for the file. */
	if ((mpq_archive->mpq_file[file_number] = calloc(1, sizeof(mpq_file_s))) == NULL) {

		/* memory allocation problem. */
		result = LIBMPQ_ERROR_MALLOC;
		goto error;
	}

	/* allocate memory for the packed block offset table. */
	if ((mpq_archive->mpq_file[file_number]->packed_offset = calloc(1, packed_size)) == NULL) {

		/* memory allocation problem. */
		result = LIBMPQ_ERROR_MALLOC;
		goto error;
	}

	/* check if we need to load the packed block offset table, we will maintain this table for unpacked files too. */
	if ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_COMPRESSED) != 0 &&
	    (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

		/* seek to block position. */
		if (fseeko(mpq_archive->fp, mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].offset + (((long long)mpq_archive->mpq_block_ex[mpq_archive->block_table_indices[file_number]].offset_high) << 32) + mpq_archive->archive_offset, SEEK_SET) < 0) {

			/* seek in file failed. */
			result = LIBMPQ_ERROR_SEEK;
			goto error;
		}

		/* read block positions from begin of file. */
		if ((rb = fread(mpq_archive->mpq_file[file_number]->packed_offset, 1, packed_size, mpq_archive->fp)) < 0) {

			/* something on read from archive failed. */
			result = LIBMPQ_ERROR_READ;
			goto error;
		}

		/* check if the archive is protected some way, sometimes the file appears not to be encrypted, but it is. */
		if (mpq_archive->mpq_file[file_number]->packed_offset[0] != rb) {

			/* file is encrypted. */
			mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags |= LIBMPQ_FLAG_ENCRYPTED;
		}

		/* check if packed offset block is encrypted, we have to decrypt it. */
		if (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_ENCRYPTED) {

			/* check if we don't know the file seed, try to find it. */
			if ((mpq_archive->mpq_file[file_number]->seed = libmpq__decrypt_key((uint8_t *)mpq_archive->mpq_file[file_number]->packed_offset, packed_size, mpq_archive->block_size)) < 0) {

				/* sorry without seed, we cannot extract file. */
				result = LIBMPQ_ERROR_DECRYPT;
				goto error;
			}

			/* decrypt block in input buffer. */
			if ((tb = libmpq__decrypt_block(mpq_archive->mpq_file[file_number]->packed_offset, packed_size, mpq_archive->mpq_file[file_number]->seed - 1)) < 0 ) {

				/* something on decrypt failed. */
				result = LIBMPQ_ERROR_DECRYPT;
				goto error;
			}

			/* check if the block positions are correctly decrypted. */
			if (mpq_archive->mpq_file[file_number]->packed_offset[0] != packed_size) {

				/* sorry without seed, we cannot extract file. */
				result = LIBMPQ_ERROR_DECRYPT;
				goto error;
			}
		}
	} else {

		/* check if file is not stored in a single sector. */
		if ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

			/* loop through all blocks and create packed block offset table based on block size. */
			for (i = 0; i < ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size + 1); i++) {

				/* check if we process the last block. */
				if (i == ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size)) {

					/* store size of last block. */
					mpq_archive->mpq_file[file_number]->packed_offset[i] = mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size;
				} else {

					/* store default block size. */
					mpq_archive->mpq_file[file_number]->packed_offset[i] = i * mpq_archive->block_size;
				}
			}
		} else {

			/* store offsets. */
			mpq_archive->mpq_file[file_number]->packed_offset[0] = 0;
			mpq_archive->mpq_file[file_number]->packed_offset[1] = mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].packed_size;
		}
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;

error:

	/* free packed block offset table and file pointer. */
	free(mpq_archive->mpq_file[file_number]->packed_offset);
	free(mpq_archive->mpq_file[file_number]);

	/* return error constant. */
	return result;
}

/* this function free the file pointer to the opened file in archive. */
int32_t libmpq__block_close_offset(mpq_archive_s *mpq_archive, uint32_t file_number) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* free packed block offset table and file pointer. */
	free(mpq_archive->mpq_file[file_number]->packed_offset);
	free(mpq_archive->mpq_file[file_number]);

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the unpacked size of the given file and block in the archive. */
int32_t libmpq__block_unpacked_size(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, off_t *unpacked_size) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if given block number is not out of range. */
	if (block_number < 0 || block_number >= ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? 1 : (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size)) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if packed block offset table is opened. */
	if (mpq_archive->mpq_file[file_number] == NULL ||
	    mpq_archive->mpq_file[file_number]->packed_offset == NULL) {

		/* packed block offset table is not opened. */
		return LIBMPQ_ERROR_OPEN;
	}

	/* check if block is stored as single sector. */
	if ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) != 0) {

		/* return the unpacked size of the block in the mpq archive. */
		*unpacked_size = mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size;
	}

	/* check if block is not stored as single sector. */
	if ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

		/* check if we not process the last block. */
		if (block_number < ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size) - 1) {

			/* return the block size as unpacked size. */
			*unpacked_size = mpq_archive->block_size;
		} else {

			/* return the unpacked size of the last block in the mpq archive. */
			*unpacked_size = mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size - mpq_archive->block_size * block_number;
		}
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return the decryption seed for the given file and block. */
int32_t libmpq__block_seed(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint32_t *seed) {

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if given block number is not out of range. */
	if (block_number < 0 || block_number >= ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? 1 : (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size)) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if packed block offset table is opened. */
	if (mpq_archive->mpq_file[file_number] == NULL ||
	    mpq_archive->mpq_file[file_number]->packed_offset == NULL) {

		/* packed block offset table is not opened. */
		return LIBMPQ_ERROR_OPEN;
	}

	/* return the decryption key. */
	*seed = mpq_archive->mpq_file[file_number]->seed + block_number;

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function read the given block from archive into a buffer. */
int32_t libmpq__block_read(mpq_archive_s *mpq_archive, uint32_t file_number, uint32_t block_number, uint8_t *out_buf, off_t out_size, off_t *transferred) {

	/* some common variables. */
	uint8_t *in_buf;
	uint32_t seed       = 0;
	uint32_t encrypted  = 0;
	uint32_t compressed = 0;
	uint32_t imploded   = 0;
	int32_t tb          = 0;
	off_t block_offset  = 0;
	off_t in_size       = 0;
	off_t unpacked_size = 0;

	CHECK_IS_INITIALIZED();

	/* check if given file number is not out of range. */
	if (file_number < 0 || file_number > mpq_archive->files - 1) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if given block number is not out of range. */
	if (block_number < 0 || block_number >= ((mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? 1 : (mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].unpacked_size + mpq_archive->block_size - 1) / mpq_archive->block_size)) {

		/* file number is out of range. */
		return LIBMPQ_ERROR_EXIST;
	}

	/* check if packed block offset table is opened. */
	if (mpq_archive->mpq_file[file_number] == NULL ||
	    mpq_archive->mpq_file[file_number]->packed_offset == NULL) {

		/* packed block offset table is not opened. */
		return LIBMPQ_ERROR_OPEN;
	}

	/* get target size of block. */
	libmpq__block_unpacked_size(mpq_archive, file_number, block_number, &unpacked_size);

	/* check if target buffer is to small. */
	if (unpacked_size > out_size) {

		/* output buffer size is to small or block size is unknown. */
		return LIBMPQ_ERROR_SIZE;
	}

	/* fetch some required values like input buffer size and block offset. */
	block_offset = mpq_archive->mpq_block[mpq_archive->block_table_indices[file_number]].offset + (((long long)mpq_archive->mpq_block_ex[mpq_archive->block_table_indices[file_number]].offset_high) << 32) + mpq_archive->mpq_file[file_number]->packed_offset[block_number];
	in_size = mpq_archive->mpq_file[file_number]->packed_offset[block_number + 1] - mpq_archive->mpq_file[file_number]->packed_offset[block_number];

	/* seek in file. */
	if (fseeko(mpq_archive->fp, block_offset + mpq_archive->archive_offset, SEEK_SET) < 0) {

		/* something with seek in file failed. */
		return LIBMPQ_ERROR_SEEK;
	}

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

	/* get encryption status. */
	libmpq__file_encrypted(mpq_archive, file_number, &encrypted);

	/* check if file is encrypted. */
	if (encrypted == 1) {

		/* get decryption key. */
		libmpq__block_seed(mpq_archive, file_number, block_number, &seed);

		/* decrypt block. */
		if ((tb = libmpq__decrypt_block((uint32_t *)in_buf, in_size, seed)) < 0) {

			/* free buffers. */
			free(in_buf);

			/* something on decrypting block failed. */
			return LIBMPQ_ERROR_DECRYPT;
		}
	}

	/* get compression status. */
	libmpq__file_compressed(mpq_archive, file_number, &compressed);

	/* check if file is compressed. */
	if (compressed == 1) {

		/* decompress block. */
		if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_MULTI)) < 0) {

			/* free temporary buffer. */
			free(in_buf);

			/* something on decompressing block failed. */
			return LIBMPQ_ERROR_UNPACK;
		}
	}

	/* get implosion status. */
	libmpq__file_imploded(mpq_archive, file_number, &imploded);

	/* check if file is imploded. */
	if (imploded == 1) {

		/* explode block. */
		if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_PKWARE)) < 0) {

			/* free temporary buffer. */
			free(in_buf);

			/* something on decompressing block failed. */
			return LIBMPQ_ERROR_UNPACK;
		}
	}

	/* check if file is neither compressed nor imploded. */
	if (compressed == 0 && imploded == 0) {

		/* copy block. */
		if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_NONE)) < 0) {

			/* free temporary buffer. */
			free(in_buf);

			/* something on decompressing block failed. */
			return LIBMPQ_ERROR_UNPACK;
		}
	}

	/* free read buffer. */
	free(in_buf);

	/* check for null pointer. */
	if (transferred != NULL) {

		/* store transferred bytes. */
		*transferred = tb;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}
