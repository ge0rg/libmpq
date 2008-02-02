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

/* this function returns the library version information. */
unsigned char *libmpq__version() {

	/* return version information. */
	return (unsigned char *)VERSION;
}

/* this function reads a file and verify if it is a valid mpq archive, then it reads and decrypts the hash table. */
int libmpq__archive_open(mpq_archive_s *mpq_archive, const char *mpq_filename) {

	/* some common variables. */
	unsigned int rb             = 0;
	unsigned int archive_offset = 0;
	unsigned int i              = 0;
	int result                  = 0;

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

	/* assign some default values. */
	mpq_archive->mpq_header->mpq_magic = 0;
	mpq_archive->files                 = 0;

	/* loop through file and search for mpq signature. */
	while (TRUE) {

		/* reset header values. */
		mpq_archive->mpq_header->mpq_magic = 0;

		/* seek in file. */
		lseek(mpq_archive->fd, archive_offset, SEEK_SET);

		/* read header from file. */
		if ((rb = read(mpq_archive->fd, mpq_archive->mpq_header, sizeof(mpq_header_s))) != sizeof(mpq_header_s)) {

			/* no valid mpq archive. */
			return LIBMPQ_ARCHIVE_ERROR_FORMAT;
		}

		/* check if we found a valid mpq header. */
		if (mpq_archive->mpq_header->mpq_magic == LIBMPQ_HEADER) {

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
		archive_offset += 512;
	}

	/* store block size for later use. */
	mpq_archive->block_size = 512 << mpq_archive->mpq_header->block_size;

	/* add archive offset to size, hash and block table offset. */
	mpq_archive->mpq_header->archive_size       += archive_offset;
	mpq_archive->mpq_header->hash_table_offset  += archive_offset;
	mpq_archive->mpq_header->block_table_offset += archive_offset;

	/* allocate memory for the block table and hash table, some mpq archives have block table greater than hash table, avoid buffer overruns. */
	if ((mpq_archive->mpq_block                     = malloc(sizeof(mpq_block_s)  * mpq_archive->mpq_header->block_table_count)) == NULL ||
	    (mpq_archive->mpq_hash                      = malloc(sizeof(mpq_hash_s)   * mpq_archive->mpq_header->hash_table_count)) == NULL ||
	    (mpq_archive->mpq_list->file_names          = malloc(sizeof(char *)       * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL ||
	    (mpq_archive->mpq_list->block_table_indices = malloc(sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL ||
	    (mpq_archive->mpq_list->hash_table_indices  = malloc(sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL ||
	    (mpq_archive->mpq_file                      = malloc(sizeof(mpq_file_s))) == NULL ||
	    (mpq_archive->mpq_buffer                    = malloc(sizeof(unsigned int) * LIBMPQ_BUFFER_SIZE)) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_block,                     0, sizeof(mpq_block_s)  * mpq_archive->mpq_header->block_table_count);
	memset(mpq_archive->mpq_hash,                      0, sizeof(mpq_hash_s)   * mpq_archive->mpq_header->hash_table_count);
	memset(mpq_archive->mpq_list->file_names,          0, sizeof(char *)       * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));
	memset(mpq_archive->mpq_list->block_table_indices, 0, sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));
	memset(mpq_archive->mpq_list->hash_table_indices,  0, sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));
	memset(mpq_archive->mpq_file,                      0, sizeof(mpq_file_s));
	memset(mpq_archive->mpq_buffer,                    0, sizeof(unsigned int) * LIBMPQ_BUFFER_SIZE);

	/* initialize the decryption buffer. */
	libmpq__decrypt_buffer_init(mpq_archive->mpq_buffer);

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

	/* loop through all files in mpq archive and add archive offset to file offset. */
	for (i = 0; i < mpq_archive->mpq_header->block_table_count; i++) {

		/* add archive offset to file offset. */
		mpq_archive->mpq_block[i].offset += archive_offset;
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

	/* check if there is some real data in the file list. */
	if (mpq_archive->mpq_list->file_names != NULL) {

		/* free the filelist. */
		for (i = 0; i < max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count); i++) {

			/* free file list element if used. */
			if (mpq_archive->mpq_list->file_names[i] != NULL) {

				/* free the filelist element. */
				free(mpq_archive->mpq_list->file_names[i]);
			}
		}
	}

	/* free buffer structure if used. */
	if (mpq_archive->mpq_buffer != NULL) {

		/* free buffer structure. */
		free(mpq_archive->mpq_buffer);
	}

	/* free file structure if used. */
	if (mpq_archive->mpq_file != NULL) {

		/* free file structure. */
		free(mpq_archive->mpq_file);
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
int libmpq__archive_info(mpq_archive_s *mpq_archive, unsigned int info_type) {

	/* some common variables. */
	unsigned int uncompressed_size = 0;
	unsigned int compressed_size   = 0;
	unsigned int i;

	/* check which information type should be returned. */
	switch (info_type) {
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

			/* if no error was found, return zero. */
			return LIBMPQ_SUCCESS;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function returns some useful file information. */
int libmpq__file_info(mpq_archive_s *mpq_archive, unsigned int info_type, const unsigned int number) {

	/* check if given number is not out of range. */
	if (number < 1 || number > mpq_archive->files) {

		/* file number is out of range. */
		return LIBMPQ_FILE_ERROR_RANGE;
	}

	/* check which information type should be returned. */
	switch (info_type) {
		case LIBMPQ_FILE_SIZE_COMPRESSED:

			/* return the compressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].compressed_size;
		case LIBMPQ_FILE_SIZE_UNCOMPRESSED:

			/* return the uncompressed size of the file in the mpq archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].uncompressed_size;
		case LIBMPQ_FILE_ENCRYPTED:

			/* return true if file is encrypted, false otherwise. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].flags & LIBMPQ_FLAG_ENCRYPTED) != 0 ? TRUE : FALSE;
		case LIBMPQ_FILE_COMPRESSED:

			/* return true if file is compressed, false otherwise. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].flags & LIBMPQ_FLAG_COMPRESS_MULTI) != 0 ? TRUE : FALSE;
		case LIBMPQ_FILE_IMPLODED:

			/* return true if file is imploded, false otherwise. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].flags & LIBMPQ_FLAG_COMPRESS_PKWARE) != 0 ? TRUE : FALSE;
		case LIBMPQ_FILE_SINGLE:

			/* return true if file is stored in single sector, otherwise false. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? TRUE : FALSE;
		case LIBMPQ_FILE_OFFSET:

			/* return the absolute file start position in archive. */
			return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].offset;
		case LIBMPQ_FILE_BLOCKS:

			/* return the number of blocks for file, on single sector files return one. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? 1 : (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size;
		case LIBMPQ_FILE_BLOCKSIZE:

			/* return the blocksize for the file, if file is stored in single sector returns uncompressed size. */
			return (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].flags & LIBMPQ_FLAG_SINGLE) != 0 ? mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]].uncompressed_size : mpq_archive->block_size;
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

/* this function extract a file from a mpq archive. */
int libmpq__file_extract(mpq_archive_s *mpq_archive, const char *filename, const unsigned int number) {

	/* some common variables. */
	int rb = 0;
	int db = 0;
	int tb = 0;
	int wb = 0;
	unsigned char *in_buf;
	unsigned char *out_buf;
	unsigned int in_size = 0;
	unsigned int out_size = 0;
	unsigned int block_count = 0;
	unsigned int block_number = 0;
	unsigned int block_offset = 0;
	unsigned int read_offset = 0;
	unsigned int compression_type;

	/* check if we are in the range of available files. */
	if (number < 1 || number > mpq_archive->files) {

		/* file not found by number, so return with error. */
		return LIBMPQ_FILE_ERROR_RANGE;
	}

        /* initialize file structure. */
	mpq_archive->mpq_file->mpq_block = &mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[number - 1]];
	mpq_archive->mpq_file->mpq_hash  = &mpq_archive->mpq_hash[mpq_archive->mpq_list->hash_table_indices[number - 1]];
	snprintf(mpq_archive->mpq_file->filename, PATH_MAX, (const char *)mpq_archive->mpq_list->file_names[number - 1]);

	/* check if file could be written. */
	if ((mpq_archive->mpq_file->fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0644)) == -1) {

		/* file could not be created, so return with error. */
		return LIBMPQ_FILE_ERROR_OPEN;
	}

	/* get the number of blocks for the file. */
	block_count = (mpq_archive->mpq_file->mpq_block->uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size;

	/* check if file is stored in a single sector - first seen in world of warcraft. */
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_SINGLE) != 0) {

		/* buffer sizes. */
		in_size  = mpq_archive->mpq_file->mpq_block->compressed_size;
		out_size = mpq_archive->mpq_file->mpq_block->uncompressed_size;

		/* allocate memory for buffers. */
		if ((in_buf  = malloc(in_size)) == NULL ||
		    (out_buf = malloc(out_size)) == NULL) {

			/* check if file descriptor is valid. */
			if ((close(mpq_archive->mpq_file->fd)) == -1) {

				/* file was not opened. */
				return LIBMPQ_FILE_ERROR_CLOSE;
			}

			/* memory allocation problem. */
			return LIBMPQ_FILE_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(in_buf,  0, in_size);
		memset(out_buf, 0, out_size);

		/* seek in file. */
		lseek(mpq_archive->fd, mpq_archive->mpq_file->mpq_block->offset, SEEK_SET);

		/* read the compressed file data. */
		if ((rb = read(mpq_archive->fd, in_buf, in_size)) < 0) {

			/* free input buffer if used. */
			if (in_buf != NULL) {

				/* free input buffer. */
				free(in_buf);
			}

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

			/* something on read from archive failed. */
			return LIBMPQ_FILE_ERROR_READ;
		}

		/* check if file is imploded using pkware. */
		if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESS_PKWARE) != 0) {

			/* compression type is pkware algorithm. */
			compression_type = LIBMPQ_FLAG_COMPRESS_PKWARE;
		}

		/* check if file is compressed using multiple algorithm. */
		if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESS_MULTI) != 0) {

			/* compression type is multiple algorithm. */
			compression_type = LIBMPQ_FLAG_COMPRESS_MULTI;
		}

		/* decompress or explode single sector of file. */
		if ((db = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, compression_type)) < 0) {

			/* free input buffer if used. */
			if (in_buf != NULL) {

				/* free input buffer. */
				free(in_buf);
			}

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

			/* something on decompressing failed. */
			return db;
		}

		/* write buffer to disk. */
		if ((wb = write(mpq_archive->mpq_file->fd, out_buf, db)) < 0) {

			/* free input buffer if used. */
			if (in_buf != NULL) {

				/* free input buffer. */
				free(in_buf);
			}

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

		/* free input buffer if used. */
		if (in_buf != NULL) {

			/* free input buffer. */
			free(in_buf);
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
	if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_SINGLE) == 0) {

		/* check if block is compressed. */
		if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESSED) != 0) {

			/* allocate memory for block buffer and compressed offset table, since world of warcraft the archive has extra data appended after the compressed offset table, so we add one more unsigned int. */
			if ((mpq_archive->mpq_file->compressed_offset = malloc(sizeof(unsigned int) * (block_count + 1))) == NULL) {

				/* check if file descriptor is valid. */
				if ((close(mpq_archive->mpq_file->fd)) == -1) {

					/* file was not opened. */
					return LIBMPQ_FILE_ERROR_CLOSE;
				}

				/* memory allocation problem. */
				return LIBMPQ_FILE_ERROR_MALLOC;
			}

			/* cleanup. */
			memset(mpq_archive->mpq_file->compressed_offset, 0, sizeof(unsigned int) * (block_count + 1));

			/* seek to block position. */
			lseek(mpq_archive->fd, mpq_archive->mpq_file->mpq_block->offset, SEEK_SET);

			/* read block positions from begin of file. */
			if ((rb = read(mpq_archive->fd, mpq_archive->mpq_file->compressed_offset, sizeof(unsigned int) * (block_count + 1))) < 0) {

				/* free compressed block offset structure if used. */
				if (mpq_archive->mpq_file->compressed_offset != NULL) {

					/* free compressed block offset structure. */
					free(mpq_archive->mpq_file->compressed_offset);
				}

				/* check if file descriptor is valid. */
				if ((close(mpq_archive->mpq_file->fd)) == -1) {

					/* file was not opened. */
					return LIBMPQ_FILE_ERROR_CLOSE;
				}

				/* something on read from archive failed. */
				return LIBMPQ_FILE_ERROR_READ;
			}

			/* check if the archive is protected some way, sometimes the file appears not to be encrypted, but it is. */
			if (mpq_archive->mpq_file->compressed_offset[0] != rb) {

				/* file is encrypted. */
				mpq_archive->mpq_file->mpq_block->flags |= LIBMPQ_FLAG_ENCRYPTED;
			}

			/* check if compressed offset block is encrypted, we have to decrypt it. */
			if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_ENCRYPTED) {

				/* check if we don't know the file seed, try to find it. */
				if ((mpq_archive->mpq_file->seed = libmpq__decrypt_key(mpq_archive->mpq_buffer, mpq_archive->mpq_file->compressed_offset, sizeof(unsigned int) * (block_count + 1))) < 0) {

					/* free compressed block offset structure if used. */
					if (mpq_archive->mpq_file->compressed_offset != NULL) {

						/* free compressed block offset structure. */
						free(mpq_archive->mpq_file->compressed_offset);
					}

					/* check if file descriptor is valid. */
					if ((close(mpq_archive->mpq_file->fd)) == -1) {

						/* file was not opened. */
						return LIBMPQ_FILE_ERROR_CLOSE;
					}

					/* sorry without seed, we cannot extract file. */
					return LIBMPQ_FILE_ERROR_DECRYPT;
				}

				/* decrypt block in input buffer. */
				libmpq__decrypt_mpq_block(mpq_archive->mpq_buffer, mpq_archive->mpq_file->compressed_offset, sizeof(unsigned int) * (block_count + 1), mpq_archive->mpq_file->seed - 1);

				/* check if the block positions are correctly decrypted. */
				if (mpq_archive->mpq_file->compressed_offset[0] != sizeof(unsigned int) * (block_count + 1)) {

					/* free compressed block offset structure if used. */
					if (mpq_archive->mpq_file->compressed_offset != NULL) {

						/* free compressed block offset structure. */
						free(mpq_archive->mpq_file->compressed_offset);
					}

					/* check if file descriptor is valid. */
					if ((close(mpq_archive->mpq_file->fd)) == -1) {

						/* file was not opened. */
						return LIBMPQ_FILE_ERROR_CLOSE;
					}

					/* sorry without seed, we cannot extract file. */
					return LIBMPQ_FILE_ERROR_DECRYPT;
				}
			}
		}

		/* loop through all blocks and decompress them. */
		do {

			/* block offset stores the relative block position inside the archive. */
			block_offset = mpq_archive->block_size * block_number;

			/* check if file is compressed. */
			if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESSED) != 0) {

				/* input buffer size for compressed block. */
				in_size = mpq_archive->mpq_file->compressed_offset[block_number + 1] - mpq_archive->mpq_file->compressed_offset[block_number];

				/* offset for file read. */
				read_offset = mpq_archive->mpq_file->mpq_block->offset + mpq_archive->mpq_file->compressed_offset[block_number];
			} else {

				/* input buffer size for uncompressed block. */
				in_size = mpq_archive->block_size;

				/* offset for file read. */
				read_offset = mpq_archive->mpq_file->mpq_block->offset + block_offset;
			}

			/* if remaining bytes are less block size, decrease the block size. */
			if ((block_offset + mpq_archive->block_size) > mpq_archive->mpq_file->mpq_block->uncompressed_size) {

				/* last block is smaller than default block size. */
				out_size = mpq_archive->mpq_file->mpq_block->uncompressed_size - block_offset;
			} else {

				/* not the last block, so use default block size. */
				out_size = mpq_archive->block_size;
			}

			/* allocate memory for buffers. */
			if ((in_buf  = malloc(in_size)) == NULL ||
			    (out_buf = malloc(out_size)) == NULL) {

				/* check if file is compressed. */
				if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESSED) != 0) {

					/* free compressed block offset structure if used. */
					if (mpq_archive->mpq_file->compressed_offset != NULL) {

						/* free compressed block offset structure. */
						free(mpq_archive->mpq_file->compressed_offset);
					}
				}

				/* check if file descriptor is valid. */
				if ((close(mpq_archive->mpq_file->fd)) == -1) {

					/* file was not opened. */
					return LIBMPQ_FILE_ERROR_CLOSE;
				}

				/* memory allocation problem. */
				return LIBMPQ_FILE_ERROR_MALLOC;
			}

			/* cleanup. */
			memset(in_buf,  0, in_size);
			memset(out_buf, 0, out_size);

			/* seek in file. */
			lseek(mpq_archive->fd, read_offset, SEEK_SET);

			/* read the file data. */
			if ((rb = read(mpq_archive->fd, in_buf, in_size)) < 0) {

				/* check if file is compressed. */
				if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESSED) != 0) {

					/* free compressed block offset structure if used. */
					if (mpq_archive->mpq_file->compressed_offset != NULL) {

						/* free compressed block offset structure. */
						free(mpq_archive->mpq_file->compressed_offset);
					}
				}

				/* free input buffer if used. */
				if (in_buf != NULL) {

					/* free input buffer. */
					free(in_buf);
				}

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

				/* something on read from archive failed. */
				return LIBMPQ_FILE_ERROR_READ;
			}

			/* check if file is compressed. */
			if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESSED) != 0) {

				/* check if block is encrypted, we have to decrypt it. */
				if (mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_ENCRYPTED) {

					/* decrypt block in input buffer. */
					libmpq__decrypt_mpq_block(mpq_archive->mpq_buffer, (unsigned int *)in_buf, in_size, mpq_archive->mpq_file->seed + block_number);
				}

				/* check if file is imploded using pkware. */
				if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESS_PKWARE) != 0) {

					/* compression type is pkware algorithm. */
					compression_type = LIBMPQ_FLAG_COMPRESS_PKWARE;
				}

				/* check if file is compressed using multiple algorithm. */
				if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESS_MULTI) != 0) {

					/* compression type is multiple algorithm. */
					compression_type = LIBMPQ_FLAG_COMPRESS_MULTI;
				}

				/* decompress or explode block. */
				if ((db = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, compression_type)) < 0) {

					/* free compressed block offset structure if used. */
					if (mpq_archive->mpq_file->compressed_offset != NULL) {

						/* free compressed block offset structure. */
						free(mpq_archive->mpq_file->compressed_offset);
					}

					/* free input buffer if used. */
					if (in_buf != NULL) {

						/* free input buffer. */
						free(in_buf);
					}

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

					/* something on decompressing failed. */
					return db;
				}
			} else {

				/* no compressed data, so copy input buffer to output buffer. */
				memcpy(out_buf, in_buf, out_size);

				/* store number of bytes copied. */
				db = out_size;
			}

			/* write buffer to disk. */
			if ((wb = write(mpq_archive->mpq_file->fd, out_buf, db)) < 0) {

				/* check if file is compressed. */
				if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESSED) != 0) {

					/* free compressed block offset structure if used. */
					if (mpq_archive->mpq_file->compressed_offset != NULL) {

						/* free compressed block offset structure. */
						free(mpq_archive->mpq_file->compressed_offset);
					}
				}

				/* free input buffer if used. */
				if (in_buf != NULL) {

					/* free input buffer. */
					free(in_buf);
				}

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

			/* free input buffer if used. */
			if (in_buf != NULL) {

				/* free input buffer. */
				free(in_buf);
			}

			/* free output buffer if used. */
			if (out_buf != NULL) {

				/* free output buffer. */
				free(out_buf);
			}
		} while (block_offset + mpq_archive->block_size < mpq_archive->mpq_file->mpq_block->uncompressed_size);

		/* check if block is compressed. */
		if ((mpq_archive->mpq_file->mpq_block->flags & LIBMPQ_FLAG_COMPRESSED) != 0) {

			/* free compressed block offset structure if used. */
			if (mpq_archive->mpq_file->compressed_offset != NULL) {

				/* free compressed block offset structure. */
				free(mpq_archive->mpq_file->compressed_offset);
			}
		}
	}

	/* check if file descriptor is valid. */
	if ((close(mpq_archive->mpq_file->fd)) == -1) {

		/* file was not opened. */
		return LIBMPQ_FILE_ERROR_CLOSE;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function decrypt the given input buffer to output buffer. */
int libmpq__memory_decrypt(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_count) {

	/* some common variables. */
	unsigned int *mpq_buffer;
	unsigned int *compressed_offset;
	unsigned int seed;
	unsigned int i;
	unsigned char *work_buf;
	unsigned int out_offset;

	/* allocate memory for the buffers. */
	if ((mpq_buffer        = malloc(sizeof(unsigned int) * LIBMPQ_BUFFER_SIZE)) == NULL ||
	    (compressed_offset = malloc(sizeof(unsigned int) * (block_count + 1))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ARCHIVE_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_buffer,        0, sizeof(unsigned int) * LIBMPQ_BUFFER_SIZE);
	memset(compressed_offset, 0, sizeof(unsigned int) * (block_count + 1));

	/* initialize the decryption buffer. */
	libmpq__decrypt_buffer_init(mpq_buffer);

	/* copy compressed offset block from input buffer. */
	memcpy(compressed_offset, in_buf, sizeof(unsigned int) * (block_count + 1));

	/* check if we don't know the file seed, try to find it. */
	if ((seed = libmpq__decrypt_key(mpq_buffer, compressed_offset, sizeof(unsigned int) * (block_count + 1))) < 0) {

		/* sorry without seed, we cannot extract file. */
		return LIBMPQ_FILE_ERROR_DECRYPT;
	}

	/* decrypt the compressed offset block. */
	libmpq__decrypt_mpq_block(mpq_buffer, compressed_offset, sizeof(unsigned int) * (block_count + 1), seed - 1);

	/* check if the block positions are correctly decrypted. */
	if (compressed_offset[0] != sizeof(unsigned int) * (block_count + 1)) {

		/* sorry without seed, we cannot extract file. */
		return LIBMPQ_FILE_ERROR_DECRYPT;
	}

	/* copy compressed offset as first block to output buffer. */
	memcpy(out_buf, compressed_offset, sizeof(unsigned int) * (block_count + 1));

	/* store new output offset. */
	out_offset += sizeof(unsigned int) * (block_count + 1);

	/* loop through all blocks and decrypt them. */
	for (i = 0; i < block_count; i++) {

		/* allocate memory for the buffers. */
		if ((work_buf = malloc(compressed_offset[i + 1] - compressed_offset[i])) == NULL) {

			/* free compressed offset block structure if used. */
			if (compressed_offset != NULL) {

				/* free compressed offset block structure. */
				free(compressed_offset);
			}

			/* free mpq buffer structure if used. */
			if (mpq_buffer != NULL) {

				/* free mpq buffer structure. */
				free(mpq_buffer);
			}

			/* memory allocation problem. */
			return LIBMPQ_ARCHIVE_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(work_buf, 0, compressed_offset[i + 1] - compressed_offset[i]);

		/* copy block from input buffer to working buffer. */
		memcpy(work_buf, in_buf + compressed_offset[i], compressed_offset[i + 1] - compressed_offset[i]);

		/* decrypt block. */
		libmpq__decrypt_mpq_block(mpq_buffer, (unsigned int *)work_buf, compressed_offset[i + 1] - compressed_offset[i], seed + i);

		/* copy decrypted working buffer to output buffer. */
		memcpy(out_buf + out_offset, work_buf, compressed_offset[i + 1] - compressed_offset[i]);

		/* store working buffer size as offset for next block. */
		out_offset += compressed_offset[i + 1] - compressed_offset[i];

		/* free working buffer structure if used. */
		if (work_buf != NULL) {

			/* free working buffer structure. */
			free(work_buf);
		}
	}

	/* free compressed offset block structure if used. */
	if (compressed_offset != NULL) {

		/* free compressed offset block structure. */
		free(compressed_offset);
	}

	/* free mpq buffer structure if used. */
	if (mpq_buffer != NULL) {

		/* free mpq buffer structure. */
		free(mpq_buffer);
	}

	/* if no error was found, return transferred bytes. */
	return out_offset;
}

/* this function decompress the given input buffer to output buffer. */
int libmpq__memory_decompress(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_size) {

	/* some common variables. */
	int tb = 0;

	/* call real decompress function. */
	if ((tb = libmpq__decompress_memory(in_buf, in_size, out_buf, out_size, block_size, LIBMPQ_FLAG_COMPRESS_MULTI)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function explode the given input buffer to output buffer. */
int libmpq__memory_explode(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_size) {

	/* some common variables. */
	int tb = 0;

	/* call real decompress function. */
	if ((tb = libmpq__decompress_memory(in_buf, in_size, out_buf, out_size, block_size, LIBMPQ_FLAG_COMPRESS_PKWARE)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}
