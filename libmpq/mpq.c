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
	unsigned int rb = 0;
	int result      = 0;

	/* allocate memory for the mpq header and file list. */
	if ((mpq_archive->mpq_header = malloc(sizeof(mpq_header_s))) == NULL ||
	    (mpq_archive->mpq_list   = malloc(sizeof(mpq_list_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_header, 0, sizeof(mpq_header_s));
	memset(mpq_archive->mpq_list, 0, sizeof(mpq_list_s));

	/* check if file exists and is readable */
	if ((mpq_archive->fd = open(mpq_filename, O_RDONLY)) == -1) {

		/* file could not be opened. */
		return LIBMPQ_ARCHIVE_ERROR_OPEN;
	}

	/* fill the structures with informations. */
	strncpy(mpq_archive->filename, mpq_filename, strlen(mpq_filename));

	/* initialize the decryption buffer. */
	libmpq__decrypt_buffer_init(mpq_archive);

	/* assign some default values. */
	mpq_archive->mpq_header->mpq_magic = 0;
	mpq_archive->files                 = 0;
	mpq_archive->archive_offset        = 0;

	/* loop through file and search for mpq signature. */
	while (TRUE) {

		/* reset header values. */
		mpq_archive->mpq_header->mpq_magic = 0;

		/* seek in file. */
		lseek(mpq_archive->fd, mpq_archive->archive_offset, SEEK_SET);

		/* read header from file. */
		if ((rb = read(mpq_archive->fd, mpq_archive->mpq_header, sizeof(mpq_header_s))) != sizeof(mpq_header_s)) {

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
		mpq_archive->archive_offset += 512;
	}

	/* store block size for later use. */
	mpq_archive->block_size = 512 << mpq_archive->mpq_header->block_size;

	/* allocate memory for the block table and hash table, some mpq archives have block table greater than hash table, avoid buffer overruns. */
	if ((mpq_archive->mpq_block                     = malloc(sizeof(mpq_block_s)  * mpq_archive->mpq_header->block_table_count)) == NULL ||
	    (mpq_archive->mpq_hash                      = malloc(sizeof(mpq_hash_s)   * mpq_archive->mpq_header->hash_table_count)) == NULL ||
	    (mpq_archive->mpq_list->file_names          = malloc(sizeof(char *)       * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL ||
	    (mpq_archive->mpq_list->block_table_indices = malloc(sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL ||
	    (mpq_archive->mpq_list->hash_table_indices  = malloc(sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_block,                     0, sizeof(mpq_block_s)  * mpq_archive->mpq_header->block_table_count);
	memset(mpq_archive->mpq_hash,                      0, sizeof(mpq_hash_s)   * mpq_archive->mpq_header->hash_table_count);
	memset(mpq_archive->mpq_list->file_names,          0, sizeof(char *)       * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));
	memset(mpq_archive->mpq_list->block_table_indices, 0, sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));
	memset(mpq_archive->mpq_list->hash_table_indices,  0, sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));

	/* try to read and decrypt the hash table. */
	if ((result = libmpq__read_table_hash(mpq_archive)) != 0) {

		/* the hash table seems corrupt. */
		return result;
	}

	/* try to read and decrypt the block table. */
	if ((result = libmpq__read_table_block(mpq_archive)) != 0) {

		/* the block table seems corrupt. */
		return result;
	}

	/* try to read list file. */
	if ((result = libmpq__read_file_list(mpq_archive)) != 0) {

		/* the list file seems corrupt. */
		return result;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function closes the file descriptor, frees the decryption buffer and the filelist. */
int libmpq__archive_close(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	unsigned int i;

	/* cleanup. */
	memset(mpq_archive->mpq_buffer, 0, sizeof(mpq_archive->mpq_buffer));

	/* free the filelist. */
	for (i = 0; i < max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count); i++) {

		/* free file list element if used. */
		if (mpq_archive->mpq_list->file_names[i] != NULL) {

			/* free the filelist element. */
			free(mpq_archive->mpq_list->file_names[i]);
		}
	}

	/* free hash table indices if used. */
	if (mpq_archive->mpq_list->hash_table_indices != NULL) {

		/* free hash table indices. */
		free(mpq_archive->mpq_list->hash_table_indices);
	}

	/* free block table indices if used. */
	if (mpq_archive->mpq_list->block_table_indices != NULL) {

		/* free hash table indices. */
		free(mpq_archive->mpq_list->block_table_indices);
	}

	/* free file list if used. */
	if (mpq_archive->mpq_list->file_names != NULL) {

		/* free file list. */
		free(mpq_archive->mpq_list->file_names);
	}

	/* free hash table if used. */
	if (mpq_archive->mpq_hash != NULL) {

		/* free hash table. */
		free(mpq_archive->mpq_hash);
	}

	/* free block table if used. */
	if (mpq_archive->mpq_block != NULL) {

		/* free block table. */
		free(mpq_archive->mpq_block);
	}

	/* free mpq file list, if used. */
	if (mpq_archive->mpq_list != NULL) {

		/* free mpq file list. */
		free(mpq_archive->mpq_list);
	}

	/* free mpq header if used. */
	if (mpq_archive->mpq_header != NULL) {

		/* free the allocated memory for mpq header. */
		free(mpq_archive->mpq_header);
	}

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
	unsigned int uncompressed_size = 0;
	unsigned int compressed_size   = 0;
	unsigned int i;

	/* check which information type should be returned. */
	switch (infotype) {
		case LIBMPQ_ARCHIVE_SIZE:

			/* return the archive size. */
			return mpq_archive->mpq_header->archive_size;
		case LIBMPQ_ARCHIVE_SIZE_COMPRESSED:

			/* loop through all files in archive and count compressed size. */
			for (i = 0; i < mpq_archive->files; i++) {
				compressed_size += mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[i]].compressed_size;
			}

			/* return the compressed size of all files in the mpq archive. */
			return compressed_size;
		case LIBMPQ_ARCHIVE_SIZE_UNCOMPRESSED:

			/* loop through all files in archive and count compressed size. */
			for (i = 0; i < mpq_archive->files; i++) {
				uncompressed_size += mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[i]].uncompressed_size;
			}

			/* return the uncompressed size of all files in the mpq archive. */
			return uncompressed_size;
		case LIBMPQ_ARCHIVE_FILES:

			/* return the number of files in archive. */
			return mpq_archive->files;
		case LIBMPQ_ARCHIVE_HASH_TABLE_COUNT:

			/* return the number of hash table entries. */
			return mpq_archive->mpq_header->hash_table_count;
		case LIBMPQ_ARCHIVE_BLOCK_TABLE_COUNT:

			/* return the number of block table entries. */
			return mpq_archive->mpq_header->block_table_count;
		case LIBMPQ_ARCHIVE_BLOCK_SIZE:

			/* return the block size. */
			return mpq_archive->block_size;
		default:

			/* if no error was found, return zero. */
			return LIBMPQ_SUCCESS;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function creates everything to extract or decompress a file from the mpq archive. */
int libmpq__file_open(mpq_archive_s *mpq_archive, const unsigned int number) {

	/* some common variables. */
	int result = 0;

	/* check if we are in the range of available files. */
	if (number < 1 || number > mpq_archive->files) {

		/* file not found by number, so return with error. */
		return LIBMPQ_FILE_ERROR_RANGE;
	}

	/* allocate memory for file structure */
	if ((mpq_archive->mpq_file = malloc(sizeof(mpq_file_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_FILE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_file, 0, sizeof(mpq_file_s));

	/* initialize file structure. */
	mpq_archive->mpq_file->mpq_block = &mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]];
	mpq_archive->mpq_file->mpq_hash  = &mpq_archive->mpq_hash[mpq_archive->mpq_list->hash_table_indices[number - 1]];
	mpq_archive->mpq_file->blocks    = (mpq_archive->mpq_file->mpq_block->uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size;
	snprintf(mpq_archive->mpq_file->filename, PATH_MAX, (const char *)mpq_archive->mpq_list->file_names[number - 1]);

	/* allocate memory for block buffer and compressed offset table, since world of warcraft the archive has extra data appended after the compressed offset table, so we add one more unsigned int. */
	if ((mpq_archive->mpq_file->compressed_offset = malloc(sizeof(unsigned int) * (mpq_archive->mpq_file->blocks + 1))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_FILE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_file->compressed_offset, 0, sizeof(unsigned int) * (mpq_archive->mpq_file->blocks + 1));

	/* check if block is compressed and no single sector. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_COMPRESSED) != 0 &&
	    (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_SINGLE) == 0) {

		/* load compressed block offset if necessary. */
		if ((result = libmpq__read_file_offset(mpq_archive)) != 0) {

			/* error on decrypting block positions. */
			return result;
		}
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function frees the file structure. */
int libmpq__file_close(mpq_archive_s *mpq_archive) {

	/* free the compressed offset table if used. */
	if (mpq_archive->mpq_file->compressed_offset != NULL) {

		/* free the compressed offset table. */
		free(mpq_archive->mpq_file->compressed_offset);
	}

	/* free file structure if used. */
	if (mpq_archive->mpq_file != NULL) {

		/* free file structure. */
		free(mpq_archive->mpq_file);
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function returns some useful file information. */
int libmpq__file_info(mpq_archive_s *mpq_archive, unsigned int infotype, const unsigned int number) {

	/* check if given number is not out of range. */
	if (number < 1 || number > mpq_archive->files) {

		/* file number is out of range. */
		return LIBMPQ_FILE_ERROR_RANGE;
	}

	/* check which information type should be returned. */
	switch (infotype) {
		case LIBMPQ_FILE_SIZE_COMPRESSED:

			/* return the compressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].compressed_size;
		case LIBMPQ_FILE_SIZE_UNCOMPRESSED:

			/* return the uncompressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].uncompressed_size;
		case LIBMPQ_FILE_TYPE_COMPRESSION:

			/* check if compression type is pkware. */
			if (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].flags & LIBMPQ_FILE_COMPRESS_PKWARE) {

				/* return the compression type pkware. */
				return LIBMPQ_FILE_COMPRESS_PKWARE;
			}

			/* check if compression type is multi. */
			if (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].flags & LIBMPQ_FILE_COMPRESS_MULTI) {

				/* return the compression type multi. */
				return LIBMPQ_FILE_COMPRESS_MULTI;
			}
		case LIBMPQ_FILE_BLOCK_COUNT:

			/* block number is (uncompressed size / block size). */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].uncompressed_size / mpq_archive->block_size + 1;
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
	if (number < 1 || number > mpq_archive->files) {

		/* file not found by number, so return NULL. */
		return NULL;
	}

	/* return the filename. */
	return mpq_archive->mpq_list->file_names[number - 1];
}

/* this function returns filenumber by the given name. */
int libmpq__file_number(mpq_archive_s *mpq_archive, const char *filename) {

	/* some common variables. */
	unsigned int i;

	/* TODO: check if this segfaults on invalid filename - it should? */
	/* loop through all filenames in mpq archive. */
	for (i = 0; mpq_archive->mpq_list->file_names[i]; i++) {

		/* check if given filename was found in list. */
		if (strncmp(mpq_archive->mpq_list->file_names[i], filename, strlen(filename)) == 0) {

			/* if file found return the number */
			return i + 1;
		}
	}

	/* if no matching entry found, so return error. */
	return LIBMPQ_FILE_ERROR_EXIST;
}

/* this function decompress a file from a mpq archive to disk. */
int libmpq__file_decompress_disk(mpq_archive_s *mpq_archive, const char *filename) {

	/* some common variables. */
	int rb = 0;
	int tb = 0;
	int wb = 0;
	unsigned char *out_buf;
	unsigned int block_number = 0;

	/* check if file could be written. */
	if ((mpq_archive->mpq_file->fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0644)) == -1) {

		/* file could not be created, so return with error. */
		return LIBMPQ_FILE_ERROR_OPEN;
	}

	/* check if file is stored in a single sector - first seen in world of warcraft. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_SINGLE) != 0) {

		/* allocate memory for output buffer. */
		if ((out_buf = malloc(mpq_archive->mpq_file->mpq_block->uncompressed_size)) == NULL) {

			/* memory allocation problem. */
			return LIBMPQ_FILE_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(out_buf, 0, mpq_archive->mpq_file->mpq_block->uncompressed_size);

		/* read single sector of file. */
		if ((rb = libmpq__read_file_single(mpq_archive, out_buf, mpq_archive->mpq_file->mpq_block->uncompressed_size)) < 0) {

			/* free output buffer if used. */
			if (out_buf != NULL) {

				/* free output buffer. */
				free(out_buf);
			}

			/* check if file descriptor is valid. */
			if ((close(mpq_archive->mpq_file->fd)) == -1) {

				/* file was not opened. */
				return LIBMPQ_FILE_ERROR_CLOSE;
			}

			/* something on transferring failed. */
			return rb;
		}

		/* write buffer to disk. */
		if ((wb = write(mpq_archive->mpq_file->fd, out_buf, rb)) < 0) {

			/* free output buffer if used. */
			if (out_buf != NULL) {

				/* free output buffer. */
				free(out_buf);
			}

			/* check if file descriptor is valid. */
			if ((close(mpq_archive->mpq_file->fd)) == -1) {

				/* file was not opened. */
				return LIBMPQ_FILE_ERROR_CLOSE;
			}

			/* something on write to disk failed. */
			return LIBMPQ_FILE_ERROR_WRITE;
		}

		/* free output buffer if used. */
		if (out_buf != NULL) {

			/* free output buffer. */
			free(out_buf);
		}

		/* save the number of transferred bytes. */
		tb += wb;
	}

	/* check if file is stored in multiple blocks. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_SINGLE) == 0) {

		/* allocate memory for output buffer. */
		if ((out_buf = malloc(mpq_archive->block_size)) == NULL) {

			/* memory allocation problem. */
			return LIBMPQ_FILE_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(out_buf, 0, mpq_archive->block_size);

		/* loop through all blocks and decompress them. */
		do {

			/* read file until its end. */
			if ((rb = libmpq__read_file_block(mpq_archive, out_buf, mpq_archive->block_size, block_number)) < 0) {

				/* free output buffer if used. */
				if (out_buf != NULL) {

					/* free output buffer. */
					free(out_buf);
				}

				/* check if file descriptor is valid. */
				if ((close(mpq_archive->mpq_file->fd)) == -1) {

					/* file was not opened. */
					return LIBMPQ_FILE_ERROR_CLOSE;
				}

				/* something on transferring failed. */
				return rb;
			}

			/* write buffer to disk. */
			if ((wb = write(mpq_archive->mpq_file->fd, out_buf, rb)) < 0) {

				/* free output buffer if used. */
				if (out_buf != NULL) {

					/* free output buffer. */
					free(out_buf);
				}

				/* check if file descriptor is valid. */
				if ((close(mpq_archive->mpq_file->fd)) == -1) {

					/* file was not opened. */
					return LIBMPQ_FILE_ERROR_CLOSE;
				}

				/* something on write to disk failed. */
				return LIBMPQ_FILE_ERROR_WRITE;
			}

			/* increase block counter. */
			block_number++;

			/* save the number of transferred bytes. */
			tb += wb;
		} while (rb > 0);

		/* free output buffer if used. */
		if (out_buf != NULL) {

			/* free output buffer. */
			free(out_buf);
		}
	}

	/* check if file descriptor is valid. */
	if ((close(mpq_archive->mpq_file->fd)) == -1) {

		/* file was not opened. */
		return LIBMPQ_FILE_ERROR_CLOSE;
	}

	/* if no error was found, return zero. */
	return tb;
}

/* this function decompress a file from a mpq archive to memory. */
int libmpq__file_decompress_memory(mpq_archive_s *mpq_archive, unsigned char *out_buf, unsigned int out_size) {

	/* some common variables. */
	int rb = 0;
	int tb = 0;
	unsigned char *temp_buf;
	unsigned int block_number = 0;

	/* check if file is stored in a single sector - first seen in world of warcraft. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_SINGLE) != 0) {

		/* read single sector of file. */
		if ((rb = libmpq__read_file_single(mpq_archive, out_buf, mpq_archive->mpq_file->mpq_block->uncompressed_size)) < 0) {

			/* something on transferring failed. */
			return rb;
		}

		/* save the number of transferred bytes. */
		tb += rb;
	}

	/* check if file is stored in multiple blocks. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FILE_SINGLE) == 0) {

		/* allocate memory for output buffer. */
		if ((temp_buf = malloc(mpq_archive->block_size)) == NULL) {

			/* memory allocation problem. */
			return LIBMPQ_FILE_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(temp_buf, 0, mpq_archive->block_size);

		/* loop through all blocks and decompress them. */
		do {

			/* read file until its end. */
			if ((rb = libmpq__read_file_block(mpq_archive, temp_buf, mpq_archive->block_size, block_number)) < 0) {

				/* free output buffer if used. */
				if (temp_buf != NULL) {

					/* free output buffer. */
					free(temp_buf);
				}

				/* something on transferring failed. */
				return rb;
			}

			/* copy temporary buffer to output buffer at right position for next block. */;
			memcpy(out_buf + (block_number * mpq_archive->block_size), temp_buf, rb);

			/* increase block counter. */
			block_number++;

			/* save the number of transferred bytes. */
			tb += rb;
		} while (rb > 0);

		/* free output buffer if used. */
		if (temp_buf != NULL) {

			/* free output buffer. */
			free(temp_buf);
		}
	}

	/* if no error was found, return zero. */
	return tb;
}
