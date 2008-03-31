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
char *libmpq__version() {

	/* return version information. */
	return VERSION;
}

/* this function read a file and verify if it is a valid mpq archive, then it read and decrypt the hash table. */
int libmpq__archive_open(mpq_archive_s *mpq_archive, char *mpq_filename) {

	/* some common variables. */
	unsigned int rb             = 0;
	unsigned int archive_offset = 0;
	unsigned int i              = 0;
	int result                  = 0;

	/* check if file exists and is readable */
	if ((mpq_archive->fd = open(mpq_filename, O_RDONLY)) < 0) {

		/* file could not be opened. */
		return LIBMPQ_ERROR_OPEN;
	}

	/* allocate memory for the mpq header and file list. */
	if ((mpq_archive->mpq_header = malloc(sizeof(mpq_header_s))) == NULL) {

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_header, 0, sizeof(mpq_header_s));

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

			/* free mpq header if used. */
			if (mpq_archive->mpq_header != NULL) {

				/* free the allocated memory for mpq header. */
				free(mpq_archive->mpq_header);
			}

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

			/* free mpq header if used. */
			if (mpq_archive->mpq_header != NULL) {

				/* free the allocated memory for mpq header. */
				free(mpq_archive->mpq_header);
			}

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

				/* free mpq header if used. */
				if (mpq_archive->mpq_header != NULL) {

					/* free the allocated memory for mpq header. */
					free(mpq_archive->mpq_header);
				}

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
	if ((mpq_archive->mpq_block = malloc(sizeof(mpq_block_s)  * mpq_archive->mpq_header->block_table_count)) == NULL ||
	    (mpq_archive->mpq_hash  = malloc(sizeof(mpq_hash_s)   * mpq_archive->mpq_header->hash_table_count)) == NULL) {

		/* free mpq header if used. */
		if (mpq_archive->mpq_header != NULL) {

			/* free the allocated memory for mpq header. */
			free(mpq_archive->mpq_header);
		}

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_block, 0, sizeof(mpq_block_s)  * mpq_archive->mpq_header->block_table_count);
	memset(mpq_archive->mpq_hash,  0, sizeof(mpq_hash_s)   * mpq_archive->mpq_header->hash_table_count);

	/* try to read and decrypt the hash table. */
	if ((result = libmpq__read_table_hash(mpq_archive)) != 0) {

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

		/* free mpq header if used. */
		if (mpq_archive->mpq_header != NULL) {

			/* free the allocated memory for mpq header. */
			free(mpq_archive->mpq_header);
		}

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* the hash table seems corrupt. */
		return result;
	}

	/* try to read and decrypt the block table. */
	if ((result = libmpq__read_table_block(mpq_archive)) != 0) {

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

		/* free mpq header if used. */
		if (mpq_archive->mpq_header != NULL) {

			/* free the allocated memory for mpq header. */
			free(mpq_archive->mpq_header);
		}

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
	if ((mpq_archive->mpq_list = malloc(sizeof(mpq_list_s))) == NULL) {

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

		/* free mpq header if used. */
		if (mpq_archive->mpq_header != NULL) {

			/* free the allocated memory for mpq header. */
			free(mpq_archive->mpq_header);
		}

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_list, 0, sizeof(mpq_list_s));

	/* allocate memory, some mpq archives have block table greater than hash table, avoid buffer overruns. */
	if ((mpq_archive->mpq_file                      = malloc(sizeof(mpq_file_s)   * mpq_archive->mpq_header->hash_table_count)) == NULL ||
	    (mpq_archive->mpq_list->file_names          = malloc(sizeof(char *)       * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL ||
	    (mpq_archive->mpq_list->block_table_indices = malloc(sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL ||
	    (mpq_archive->mpq_list->hash_table_indices  = malloc(sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count))) == NULL) {

		/* free mpq file list, if used. */
		if (mpq_archive->mpq_list != NULL) {

			/* free mpq file list. */
			free(mpq_archive->mpq_list);
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

		/* free mpq header if used. */
		if (mpq_archive->mpq_header != NULL) {

			/* free the allocated memory for mpq header. */
			free(mpq_archive->mpq_header);
		}

		/* check if file descriptor is valid. */
		if ((close(mpq_archive->fd)) < 0) {

			/* file was not opened. */
			return LIBMPQ_ERROR_CLOSE;
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_file,                      0, sizeof(mpq_file_s)   * mpq_archive->mpq_header->hash_table_count);
	memset(mpq_archive->mpq_list->file_names,          0, sizeof(char *)       * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));
	memset(mpq_archive->mpq_list->block_table_indices, 0, sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));
	memset(mpq_archive->mpq_list->hash_table_indices,  0, sizeof(unsigned int) * max(mpq_archive->mpq_header->block_table_count, mpq_archive->mpq_header->hash_table_count));

	/* try to read list file. */
	if ((result = libmpq__read_file_list(mpq_archive)) != 0) {

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

		/* free file pointer if used. */
		if (mpq_archive->mpq_file != NULL) {

			/* free file pointer. */
			free(mpq_archive->mpq_file);
		}

		/* free mpq file list, if used. */
		if (mpq_archive->mpq_list != NULL) {

			/* free mpq file list. */
			free(mpq_archive->mpq_list);
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

		/* free mpq header if used. */
		if (mpq_archive->mpq_header != NULL) {

			/* free the allocated memory for mpq header. */
			free(mpq_archive->mpq_header);
		}

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
int libmpq__archive_close(mpq_archive_s *mpq_archive) {

	/* some common variables. */
	unsigned int i;

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

	/* free file pointer if used. */
	if (mpq_archive->mpq_file != NULL) {

		/* free file pointer. */
		free(mpq_archive->mpq_file);
	}

	/* free mpq file list, if used. */
	if (mpq_archive->mpq_list != NULL) {

		/* free mpq file list. */
		free(mpq_archive->mpq_list);
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

	/* free mpq header if used. */
	if (mpq_archive->mpq_header != NULL) {

		/* free the allocated memory for mpq header. */
		free(mpq_archive->mpq_header);
	}

	/* check if file descriptor is valid. */
	if ((close(mpq_archive->fd)) < 0) {

		/* file was not opened. */
		return LIBMPQ_ERROR_CLOSE;
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return some information for the requested type of a mpq archive. */
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
int libmpq__file_open(mpq_archive_s *mpq_archive, unsigned int file_number) {

	/* some common variables. */
	unsigned int i;
	unsigned int *mpq_buf;
	unsigned int mpq_size = sizeof(unsigned int) * LIBMPQ_BUFFER_SIZE;
	unsigned int compressed_size = sizeof(unsigned int) * (((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size) + 1);
	int rb = 0;
	int tb = 0;

	/* allocate memory for the file. */
	if ((mpq_archive->mpq_file[file_number - 1] = malloc(sizeof(mpq_file_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_file[file_number - 1], 0, sizeof(mpq_file_s));

	/* allocate memory for the compressed block offset table. */
	if ((mpq_archive->mpq_file[file_number - 1]->compressed_offset = malloc(compressed_size)) == NULL) {

		/* free file pointer if used. */
		if (mpq_archive->mpq_file[file_number - 1] != NULL) {

			/* free file pointer. */
			free(mpq_archive->mpq_file[file_number - 1]);
		}

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive->mpq_file[file_number - 1]->compressed_offset, 0, compressed_size);

	/* check if we need to load the compressed block offset table, we will maintain this table for uncompressed files too. */
	if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_COMPRESSED) != 0 &&
	    (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_SINGLE) == 0) {

		/* seek to block position. */
		if (lseek(mpq_archive->fd, mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].offset, SEEK_SET) < 0) {

			/* free compressed block offset table if used. */
			if (mpq_archive->mpq_file[file_number - 1]->compressed_offset != NULL) {

				/* free compressed block offset table. */
				free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
			}

			/* free file pointer if used. */
			if (mpq_archive->mpq_file[file_number - 1] != NULL) {

				/* free file pointer. */
				free(mpq_archive->mpq_file[file_number - 1]);
			}

			/* seek in file failed. */
			return LIBMPQ_ERROR_LSEEK;
		}

		/* read block positions from begin of file. */
		if ((rb = read(mpq_archive->fd, mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size)) < 0) {

			/* free compressed block offset table if used. */
			if (mpq_archive->mpq_file[file_number - 1]->compressed_offset != NULL) {

				/* free compressed block offset table. */
				free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
			}

			/* free file pointer if used. */
			if (mpq_archive->mpq_file[file_number - 1] != NULL) {

				/* free file pointer. */
				free(mpq_archive->mpq_file[file_number - 1]);
			}

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

			/* allocate memory for the buffers. */
			if ((mpq_buf = malloc(mpq_size)) == NULL) {

				/* free compressed block offset table if used. */
				if (mpq_archive->mpq_file[file_number - 1]->compressed_offset != NULL) {

					/* free compressed block offset table. */
					free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				}

				/* free file pointer if used. */
				if (mpq_archive->mpq_file[file_number - 1] != NULL) {

					/* free file pointer. */
					free(mpq_archive->mpq_file[file_number - 1]);
				}

				/* memory allocation problem. */
				return LIBMPQ_ERROR_MALLOC;
			}

			/* cleanup. */
			memset(mpq_buf, 0, mpq_size);

			/* initialize the decryption buffer. */
			if ((tb = libmpq__decrypt_buffer_init(mpq_buf)) < 0) {

				/* free mpq buffer structure if used. */
				if (mpq_buf != NULL) {

					/* free mpq buffer structure. */
					free(mpq_buf);
				}

				/* free compressed block offset table if used. */
				if (mpq_archive->mpq_file[file_number - 1]->compressed_offset != NULL) {

					/* free compressed block offset table. */
					free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				}

				/* free file pointer if used. */
				if (mpq_archive->mpq_file[file_number - 1] != NULL) {

					/* free file pointer. */
					free(mpq_archive->mpq_file[file_number - 1]);
				}

				/* something on initialize the decryption buffer failed. */
				return LIBMPQ_ERROR_DECRYPT;
			}

			/* check if we don't know the file seed, try to find it. */
			if ((mpq_archive->mpq_file[file_number - 1]->seed = libmpq__decrypt_key((unsigned char *)mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, (unsigned char *)mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, mpq_buf)) < 0) {

				/* free mpq buffer structure if used. */
				if (mpq_buf != NULL) {

					/* free mpq buffer structure. */
					free(mpq_buf);
				}

				/* free compressed block offset table if used. */
				if (mpq_archive->mpq_file[file_number - 1]->compressed_offset != NULL) {

					/* free compressed block offset table. */
					free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				}

				/* free file pointer if used. */
				if (mpq_archive->mpq_file[file_number - 1] != NULL) {

					/* free file pointer. */
					free(mpq_archive->mpq_file[file_number - 1]);
				}

				/* sorry without seed, we cannot extract file. */
				return LIBMPQ_ERROR_DECRYPT;
			}

			/* decrypt block in input buffer. */
			if ((tb = libmpq__decrypt_block((unsigned char *)mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, (unsigned char *)mpq_archive->mpq_file[file_number - 1]->compressed_offset, compressed_size, mpq_archive->mpq_file[file_number - 1]->seed - 1, mpq_buf)) < 0 ) {

				/* free mpq buffer structure if used. */
				if (mpq_buf != NULL) {

					/* free mpq buffer structure. */
					free(mpq_buf);
				}

				/* free compressed block offset table if used. */
				if (mpq_archive->mpq_file[file_number - 1]->compressed_offset != NULL) {

					/* free compressed block offset table. */
					free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				}

				/* free file pointer if used. */
				if (mpq_archive->mpq_file[file_number - 1] != NULL) {

					/* free file pointer. */
					free(mpq_archive->mpq_file[file_number - 1]);
				}

				/* something on decrypt failed. */
				return LIBMPQ_ERROR_DECRYPT;
			}

			/* check if the block positions are correctly decrypted. */
			if (mpq_archive->mpq_file[file_number - 1]->compressed_offset[0] != compressed_size) {

				/* free mpq buffer structure if used. */
				if (mpq_buf != NULL) {

					/* free mpq buffer structure. */
					free(mpq_buf);
				}

				/* free compressed block offset table if used. */
				if (mpq_archive->mpq_file[file_number - 1]->compressed_offset != NULL) {

					/* free compressed block offset table. */
					free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
				}

				/* free file pointer if used. */
				if (mpq_archive->mpq_file[file_number - 1] != NULL) {

					/* free file pointer. */
					free(mpq_archive->mpq_file[file_number - 1]);
				}

				/* sorry without seed, we cannot extract file. */
				return LIBMPQ_ERROR_DECRYPT;
			}

			/* free mpq buffer structure if used. */
			if (mpq_buf != NULL) {

				/* free mpq buffer structure. */
				free(mpq_buf);
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
int libmpq__file_close(mpq_archive_s *mpq_archive, unsigned int file_number) {

	/* free compressed block offset table if used. */
	if (mpq_archive->mpq_file[file_number - 1]->compressed_offset != NULL) {

		/* free compressed block offset table. */
		free(mpq_archive->mpq_file[file_number - 1]->compressed_offset);
	}

	/* free file pointer if used. */
	if (mpq_archive->mpq_file[file_number - 1] != NULL) {

		/* free file pointer. */
		free(mpq_archive->mpq_file[file_number - 1]);
	}

	/* if no error was found, return zero. */
	return LIBMPQ_SUCCESS;
}

/* this function return some useful file information. */
int libmpq__file_info(mpq_archive_s *mpq_archive, unsigned int info_type, unsigned int file_number) {

	/* some common variables. */
	unsigned int decrypted_size = 0;
	unsigned int encrypted_size = 0;
	unsigned int i;

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

			/* check if file is compressed. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_ENCRYPTED) != 0) {

				/* loop through all blocks and count compressed block size. */
				for (i = 0; i < (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size; i++ ) {
					encrypted_size += mpq_archive->mpq_file[file_number - 1]->compressed_offset[i + 1] - mpq_archive->mpq_file[file_number - 1]->compressed_offset[i];
				}

				/* return the decrypted size of file. */
				return encrypted_size;
			} else {

				/* return the compressed size as decrypted size, because file is neither encrypted nor compressed. */
				return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
			}
		case LIBMPQ_FILE_DECRYPTED_SIZE:

			/* check if file is compressed. */
			if ((mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].flags & LIBMPQ_FLAG_ENCRYPTED) != 0) {

				/* loop through all blocks and count compressed block size. */
				for (i = 0; i < (mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].uncompressed_size + mpq_archive->block_size - 1) / mpq_archive->block_size; i++ ) {
					decrypted_size += mpq_archive->mpq_file[file_number - 1]->compressed_offset[i + 1] - mpq_archive->mpq_file[file_number - 1]->compressed_offset[i];
				}

				/* return the decrypted size of file. */
				return decrypted_size;
			} else {

				/* return the compressed size as decrypted size, because file is neither encrypted nor compressed. */
				return mpq_archive->mpq_block[mpq_archive->mpq_list->block_table_indices[file_number - 1]].compressed_size;
			}
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
char *libmpq__file_name(mpq_archive_s *mpq_archive, unsigned int file_number) {

	/* check if we are in the range of available files. */
	if (file_number < 1 || file_number > mpq_archive->files) {

		/* file not found by number, so return NULL. */
		return NULL;
	}

	/* return the filename. */
	return mpq_archive->mpq_list->file_names[file_number - 1];
}

/* this function return filenumber by the given name. */
int libmpq__file_number(mpq_archive_s *mpq_archive, char *filename) {

	/* some common variables. */
	unsigned int i;

	/* loop through all filenames in mpq archive. */
	for (i = 0; mpq_archive->mpq_list->file_names[i]; i++) {

		/* check if given filename was found in list. */
		if (strncmp(mpq_archive->mpq_list->file_names[i], filename, strlen(filename)) == 0) {

			/* if file found return the number */
			return i + 1;
		}
	}

	/* if no matching entry found, so return error. */
	return LIBMPQ_ERROR_EXIST;
}

/* this function return some useful block information. */
int libmpq__block_info(mpq_archive_s *mpq_archive, unsigned int info_type, unsigned int file_number, unsigned int block_number) {

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
int libmpq__block_decrypt(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int seed) {

	/* some common variables. */
	unsigned int *mpq_buf;
	unsigned int mpq_size = sizeof(unsigned int) * LIBMPQ_BUFFER_SIZE;
	int tb = 0;

	/* allocate memory for the buffers. */
	if ((mpq_buf = malloc(mpq_size)) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_buf, 0, mpq_size);

	/* initialize the decryption buffer. */
	if ((tb = libmpq__decrypt_buffer_init(mpq_buf)) < 0) {

		/* free mpq buffer structure if used. */
		if (mpq_buf != NULL) {

			/* free mpq buffer structure. */
			free(mpq_buf);
		}

		/* something on initialize the decryption buffer failed. */
		return LIBMPQ_ERROR_DECRYPT;
	}

	/* decrypt the mpq block. */
	if ((tb = libmpq__decrypt_block(in_buf, in_size, out_buf, out_size, seed, mpq_buf)) < 0) {

		/* free mpq buffer structure if used. */
		if (mpq_buf != NULL) {

			/* free mpq buffer structure. */
			free(mpq_buf);
		}

		/* something on decrypt failed. */
		return LIBMPQ_ERROR_DECRYPT;
	}

	/* free mpq buffer structure if used. */
	if (mpq_buf != NULL) {

		/* free mpq buffer structure. */
		free(mpq_buf);
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function decompress the given block in input buffer to output buffer. */
int libmpq__block_decompress(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size) {

	/* some common variables. */
	int tb = 0;

	/* call real decompress function. */
	if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_MULTI)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function explode the given block in input buffer to output buffer. */
int libmpq__block_explode(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size) {

	/* some common variables. */
	int tb = 0;

	/* call real decompress function. */
	if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_PKWARE)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function copy the given block in input buffer to output buffer. */
int libmpq__block_copy(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size) {

	/* some common variables. */
	int tb = 0;

	/* call real decompress function. */
	if ((tb = libmpq__decompress_block(in_buf, in_size, out_buf, out_size, LIBMPQ_FLAG_COMPRESS_NONE)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}

/* this function decrypt the given input buffer to output buffer. */
int libmpq__memory_decrypt(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_count) {

	/* some common variables. */
	unsigned int *mpq_buf;
	unsigned int mpq_size = sizeof(unsigned int) * LIBMPQ_BUFFER_SIZE;
	int tb = 0;

	/* allocate memory for the buffers. */
	if ((mpq_buf = malloc(mpq_size)) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_buf, 0, mpq_size);

	/* initialize the decryption buffer. */
	if ((tb = libmpq__decrypt_buffer_init(mpq_buf)) < 0) {

		/* free mpq buffer structure if used. */
		if (mpq_buf != NULL) {

			/* free mpq buffer structure. */
			free(mpq_buf);
		}

		/* something on initialize the decryption buffer failed. */
		return LIBMPQ_ERROR_DECRYPT;
	}

	/* call real decrypt function. */
	if ((tb = libmpq__decrypt_memory(in_buf, in_size, out_buf, out_size, block_count, mpq_buf)) < 0) {

		/* free mpq buffer structure if used. */
		if (mpq_buf != NULL) {

			/* free mpq buffer structure. */
			free(mpq_buf);
		}

		/* sorry without seed, we cannot extract file. */
		return LIBMPQ_ERROR_DECRYPT;
	}

	/* free mpq buffer structure if used. */
	if (mpq_buf != NULL) {

		/* free mpq buffer structure. */
		free(mpq_buf);
	}

	/* if no error was found, return transferred bytes. */
	return tb;
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

/* this function copy the given input buffer to output buffer. */
int libmpq__memory_copy(unsigned char *in_buf, unsigned int in_size, unsigned char *out_buf, unsigned int out_size, unsigned int block_size) {

	/* some common variables. */
	int tb = 0;

	/* call real decompress function. */
	if ((tb = libmpq__decompress_memory(in_buf, in_size, out_buf, out_size, block_size, LIBMPQ_FLAG_COMPRESS_NONE)) < 0) {

		/* something on decompression failed. */
		return tb;
	}

	/* if no error was found, return transferred bytes. */
	return tb;
}
