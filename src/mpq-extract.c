/*
 *  mpq-extract.c -- functions for extract files from a given mpq archive.
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
 *
 *  $Id: mpq-extract.c,v 1.18 2004/02/12 00:39:17 mbroemme Exp $
 */

/* generic includes. */
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libmpq includes. */
#include "libmpq/mpq.h"

/* zlib includes. */
#include <zlib.h>

/* mpq-tools configuration includes. */
#include "config.h"

/* define new print functions for error. */
#define ERROR(...) fprintf(stderr, __VA_ARGS__);

/* define new print functions for notification. */
#define NOTICE(...) printf(__VA_ARGS__);

/* this function show the usage. */
int mpq_extract__usage(char *program_name) {

	/* show the help. */
	NOTICE("Usage: %s [OPTION] [ARCHIVE]...\n", program_name);
	NOTICE("Extracts files from a mpq-archive. (Example: %s d2speech.mpq)\n", program_name);
	NOTICE("\n");
	NOTICE("  -h, --help		shows this help screen\n");
	NOTICE("  -v, --version		shows the version information\n");
	NOTICE("  -e, --extract		extract files from the given mpq archive\n");
	NOTICE("  -l, --list		list the contents of the mpq archive\n");
	NOTICE("\n");
	NOTICE("Please report bugs to the appropriate authors, which can be found in the\n");
	NOTICE("version information. All other things can be send to <%s>\n", PACKAGE_BUGREPORT);

        /* if no error was found, return zero. */
        return 0;
}

/* this function shows the version information. */
int mpq_extract__version(char *program_name) {

	/* show the version. */
	NOTICE("%s (mopaq) %s (zlib %s)\n", program_name, libmpq__version(), zlibVersion());
	NOTICE("Written by %s\n", AUTHOR);
	NOTICE("\n");
	NOTICE("This is free software; see the source for copying conditions.  There is NO\n");
	NOTICE("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");

	/* if no error was found, return zero. */
	return 0;
}

/* this function will list the archive content. */
int mpq_extract__list(char *mpq_filename, char *filename, unsigned int number, unsigned int files) {

	/* some common variables. */
	int result = 0;
	unsigned int i;
	mpq_archive_s *mpq_archive;

	/* allocate memory for the mpq header and file list. */
	if ((mpq_archive = malloc(sizeof(mpq_archive_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive, 0, sizeof(mpq_archive_s));

	/* open the mpq-archive. */
	if ((result = libmpq__archive_open(mpq_archive, mpq_filename)) < 0) {

		/* something on open file failed. */
		return result;
	}

	/* check if we should process all files. */
	if (filename != NULL) {

		/* check if processing multiple files. */
		if (number > 0 && files > 1 && number < files) {

			/* show empty line. */
			NOTICE("\n");
		}

		/* get file number of given filename. */
		if ((result = libmpq__file_number(mpq_archive, filename)) < 0) {

			/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
			libmpq__archive_close(mpq_archive);

			/* something on retrieving file number failed. */
			return result;
		}

		/* show the file information. */
		NOTICE("file number:			%i/%i\n", result, libmpq__archive_info(mpq_archive, LIBMPQ_ARCHIVE_FILES));
		NOTICE("file compressed size:		%i\n", libmpq__file_info(mpq_archive, LIBMPQ_FILE_COMPRESSED_SIZE, result));
		NOTICE("file uncompressed size:		%i\n", libmpq__file_info(mpq_archive, LIBMPQ_FILE_UNCOMPRESSED_SIZE, result));
		NOTICE("file compression ratio:		%.2f%%\n", (100 - fabs(((float)libmpq__file_info(mpq_archive, LIBMPQ_FILE_COMPRESSED_SIZE, result) / (float)libmpq__file_info(mpq_archive, LIBMPQ_FILE_UNCOMPRESSED_SIZE, result) * 100))));
		NOTICE("file compressed:		%s\n", libmpq__file_info(mpq_archive, LIBMPQ_FILE_COMPRESSED, result) ? "yes" : "no");
		NOTICE("file imploded:			%s\n", libmpq__file_info(mpq_archive, LIBMPQ_FILE_IMPLODED, result) ? "yes" : "no");
		NOTICE("file encrypted:			%s\n", libmpq__file_info(mpq_archive, LIBMPQ_FILE_ENCRYPTED, result) ? "yes" : "no");
		NOTICE("file name:			%s\n", filename);
	} else {

		/* show header. */
		NOTICE("number   ucmp. size   cmp. size   ratio   cmp   imp   enc   filename\n");
		NOTICE("------   ----------   ---------   -----   ---   ---   ---   --------\n");

		/* loop through all files. */
		for (i = 1; i <= libmpq__archive_info(mpq_archive, LIBMPQ_ARCHIVE_FILES); i++) {

			/* show file information. */
			NOTICE("  %4i   %10i   %9i %6.0f%%   %3s   %3s   %3s   %s\n",
				i,
				libmpq__file_info(mpq_archive, LIBMPQ_FILE_UNCOMPRESSED_SIZE, i),
				libmpq__file_info(mpq_archive, LIBMPQ_FILE_COMPRESSED_SIZE, i),
				(100 - fabs(((float)libmpq__file_info(mpq_archive, LIBMPQ_FILE_COMPRESSED_SIZE, i) / (float)libmpq__file_info(mpq_archive, LIBMPQ_FILE_UNCOMPRESSED_SIZE, i) * 100))),
				libmpq__file_info(mpq_archive, LIBMPQ_FILE_COMPRESSED, i) ? "yes" : "no",
				libmpq__file_info(mpq_archive, LIBMPQ_FILE_IMPLODED, i) ? "yes" : "no",
				libmpq__file_info(mpq_archive, LIBMPQ_FILE_ENCRYPTED, i) ? "yes" : "no",
				libmpq__file_name(mpq_archive, i)
			);
		}

		/* show footer. */
		NOTICE("------   ----------   ---------   -----   ---   ---   ---   --------\n");
		NOTICE("  %4i   %10i   %9i %6.0f%%   %s\n",
			libmpq__archive_info(mpq_archive, LIBMPQ_ARCHIVE_FILES),
			libmpq__archive_info(mpq_archive, LIBMPQ_ARCHIVE_UNCOMPRESSED_SIZE),
			libmpq__archive_info(mpq_archive, LIBMPQ_ARCHIVE_COMPRESSED_SIZE),
			(100 - fabs(((float)libmpq__archive_info(mpq_archive, LIBMPQ_ARCHIVE_COMPRESSED_SIZE) / (float)libmpq__archive_info(mpq_archive, LIBMPQ_ARCHIVE_UNCOMPRESSED_SIZE) * 100))),
			mpq_filename);
	}

	/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
	libmpq__archive_close(mpq_archive);

	/* free mpq archive if used. */
	if (mpq_archive != NULL) {

		/* free mpq archive. */
		free(mpq_archive);
	}

	/* if no error was found, return zero. */
	return 0;
}

/* this function extract a single file from archive. */
int mpq_extract__extract_file(mpq_archive_s *mpq_archive, unsigned int file_number, char *filename, int fd) {

	/* some common variables. */
	unsigned int i;
	unsigned char *in_buf;
	unsigned char *out_buf;
	unsigned char *temp_buf;
	unsigned int in_size;
	unsigned int out_size;
	unsigned int temp_size;
	int result = 0;
	int rb = 0;
	int tb = 0;

	/* open the file. */
	if ((result = libmpq__file_open(mpq_archive, file_number)) < 0) {

		/* something on open file failed. */
		return result;
	}

	/* show filename to extract. */
	NOTICE("extracting %s\n", filename);

	/* loop through all blocks. */
	for (i = 1; i <= libmpq__file_info(mpq_archive, LIBMPQ_FILE_BLOCKS, file_number); i++) {

		/* check if file is encrypted. */
		if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_ENCRYPTED, file_number) == 1) {

			/* get buffer sizes. */
			in_size   = libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_ENCRYPTED_SIZE, file_number, i);
			temp_size = libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_DECRYPTED_SIZE, file_number, i);

			/* allocate memory for the buffers. */
			if ((in_buf   = malloc(in_size))   == NULL ||
			    (temp_buf = malloc(temp_size)) == NULL) {

				/* memory allocation problem. */
				return LIBMPQ_ERROR_MALLOC;
			}

			/* cleanup. */
			memset(in_buf,   0, in_size);
			memset(temp_buf, 0, temp_size);

			/* seek in file. */
			if (lseek(mpq_archive->fd, libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_OFFSET, file_number, i), SEEK_SET) < 0) {

				/* something with seek in file failed. */
				return LIBMPQ_ERROR_LSEEK;
			}

			/* read block from file. */
			if ((rb = read(mpq_archive->fd, in_buf, in_size)) < 0) {

				/* free temporary buffer if used. */
				if (temp_buf != NULL) {

					/* free temporary buffer. */
					free(temp_buf);
				}

				/* free input buffer if used. */
				if (in_buf != NULL) {

					/* free input buffer. */
					free(in_buf);
				}

				/* something on reading block failed. */
				return LIBMPQ_ERROR_READ;
			}

			/* decrypt the block. */
			if ((tb = libmpq__block_decrypt(in_buf, in_size, temp_buf, temp_size, libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_SEED, file_number, i))) < 0) {

				/* free temporary buffer if used. */
				if (temp_buf != NULL) {

					/* free temporary buffer. */
					free(temp_buf);
				}

				/* free input buffer if used. */
				if (in_buf != NULL) {

					/* free input buffer. */
					free(in_buf);
				}

				/* something on decrypting block failed. */
				return tb;
			}

			/* free input buffer if used. */
			if (in_buf != NULL) {

				/* free input buffer. */
				free(in_buf);
			}
		}

		/* get buffer sizes. */
		in_size  = libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_COMPRESSED_SIZE, file_number, i);
		out_size = libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_UNCOMPRESSED_SIZE, file_number, i);

		/* allocate memory for the buffers. */
		if ((in_buf  = malloc(in_size))  == NULL ||
		    (out_buf = malloc(out_size)) == NULL) {

			/* check if file is encrypted. */
			if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_ENCRYPTED, file_number) == 1) {

				/* free temporary buffer if used. */
				if (temp_buf != NULL) {

					/* free temporary buffer. */
					free(temp_buf);
				}
			}

			/* memory allocation problem. */
			return LIBMPQ_ERROR_MALLOC;
		}

		/* cleanup. */
		memset(in_buf,  0, in_size);
		memset(out_buf, 0, out_size);

		/* check if file is encrypted. */
		if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_ENCRYPTED, file_number) == 1) {

			/* copy temporary buffer to input buffer. */
			memcpy(in_buf, temp_buf, in_size);

			/* free temporary buffer if used. */
			if (temp_buf != NULL) {

				/* free temporary buffer. */
				free(temp_buf);
			}
		} else {

			/* seek in file. */
			if (lseek(mpq_archive->fd, libmpq__block_info(mpq_archive, LIBMPQ_BLOCK_OFFSET, file_number, i), SEEK_SET) < 0) {

				/* something with seek in file failed. */
				return LIBMPQ_ERROR_LSEEK;
			}

			/* read block from file. */
			if ((rb = read(mpq_archive->fd, in_buf, in_size)) < 0) {

				/* free output buffer if used. */
				if (out_buf != NULL) {

					/* free output buffer. */
					free(out_buf);
				}

				/* free input buffer if used. */
				if (in_buf != NULL) {

					/* free input buffer. */
					free(in_buf);
				}

				/* something on reading block failed. */
				return LIBMPQ_ERROR_READ;
			}
		}

		/* check if file is compressed. */
		if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_COMPRESSED, file_number) == 1) {

			/* decompress the block. */
			if ((tb = libmpq__block_decompress(in_buf, in_size, out_buf, out_size)) < 0) {

				/* free output buffer if used. */
				if (out_buf != NULL) {

					/* free output buffer. */
					free(out_buf);
				}

				/* free input buffer if used. */
				if (in_buf != NULL) {

					/* free input buffer. */
					free(in_buf);
				}

				/* something on decrypting block failed. */
				return tb;
			}
		}

		/* check if file is imploded. */
		if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_IMPLODED, file_number) == 1) {

			/* explode the block. */
			if ((tb = libmpq__block_explode(in_buf, in_size, out_buf, out_size)) < 0) {

				/* free output buffer if used. */
				if (out_buf != NULL) {

					/* free output buffer. */
					free(out_buf);
				}

				/* free input buffer if used. */
				if (in_buf != NULL) {

					/* free input buffer. */
					free(in_buf);
				}

				/* something on decrypting block failed. */
				return tb;
			}
		}

		/* check if file is neither compressed nor imploded. */
		if (libmpq__file_info(mpq_archive, LIBMPQ_FILE_COPIED, file_number) == 1) {

			/* copy the block. */
			if ((tb = libmpq__block_copy(in_buf, in_size, out_buf, out_size)) < 0) {

				/* free output buffer if used. */
				if (out_buf != NULL) {

					/* free output buffer. */
					free(out_buf);
				}

				/* free input buffer if used. */
				if (in_buf != NULL) {

					/* free input buffer. */
					free(in_buf);
				}

				/* something on decrypting block failed. */
				return tb;
			}
		}

		/* write block to file. */
		write(fd, out_buf, out_size);

		/* free output buffer if used. */
		if (out_buf != NULL) {

			/* free output buffer. */
			free(out_buf);
		}

		/* free input buffer if used. */
		if (in_buf != NULL) {

			/* free input buffer. */
			free(in_buf);
		}
	}

	/* if no error was found, return zero. */
	return 0;
}

/* this function will extract the archive content. */
int mpq_extract__extract(char *mpq_filename, char *filename) {

	/* some common variables. */
	mpq_archive_s *mpq_archive;
	unsigned int i;
	int result = 0;
	int fd = 0;

	/* allocate memory for the mpq header and file list. */
	if ((mpq_archive = malloc(sizeof(mpq_archive_s))) == NULL) {

		/* memory allocation problem. */
		return LIBMPQ_ERROR_MALLOC;
	}

	/* cleanup. */
	memset(mpq_archive, 0, sizeof(mpq_archive_s));

	/* open the mpq-archive. */
	if ((result = libmpq__archive_open(mpq_archive, mpq_filename)) < 0) {

		/* something on open archive failed. */
		return result;
	}

	/* check if we should process all files. */
	if (filename != NULL) {

		/* get file number of given filename. */
		if ((result = libmpq__file_number(mpq_archive, filename)) < 0) {

			/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
			libmpq__archive_close(mpq_archive);

			/* something on retrieving file number failed. */
			return result;
		}

		/* open file for writing. */
		if ((fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0644)) < 0) {

			/* open file failed. */
			return LIBMPQ_ERROR_OPEN;
		}

		/* extract file. */
		if ((result = mpq_extract__extract_file(mpq_archive, result, filename, fd)) < 0) {

			/* close file. */
			if ((close(fd)) < 0) {

				/* close file failed. */
				return LIBMPQ_ERROR_CLOSE;
			}

			/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
			libmpq__archive_close(mpq_archive);

			/* something on extracting file failed. */
			return result;
		}

		/* close file. */
		if ((close(fd)) < 0) {

			/* close file failed. */
			return LIBMPQ_ERROR_CLOSE;
		}
	} else {

		/* loop through all files. */
		for (i = 1; i <= libmpq__archive_info(mpq_archive, LIBMPQ_ARCHIVE_FILES); i++) {

			/* get filename. */
			if ((filename = libmpq__file_name(mpq_archive, i)) == NULL) {

				/* filename was not found. */
				return LIBMPQ_ERROR_EXIST;
			}

			/* open file for writing. */
			if ((fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0644)) < 0) {

				/* open file failed. */
				return LIBMPQ_ERROR_OPEN;
			}

			/* extract file. */
			if ((result = mpq_extract__extract_file(mpq_archive, i, filename, fd)) < 0) {

				/* close file. */
				if ((close(fd)) < 0) {

					/* close file failed. */
					return LIBMPQ_ERROR_CLOSE;
				}

				/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
				libmpq__archive_close(mpq_archive);

				/* something on extracting file failed. */
				return result;
			}

			/* close file. */
			if ((close(fd)) < 0) {

				/* close file failed. */
				return LIBMPQ_ERROR_CLOSE;
			}
		}
	}

	/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
	libmpq__archive_close(mpq_archive);

	/* free mpq archive if used. */
	if (mpq_archive != NULL) {

		/* free mpq archive. */
		free(mpq_archive);
	}

	/* if no error was found, return zero. */
	return 0;
}

/* the main function starts here. */
int main(int argc, char **argv) {

	/* common variables for the command line. */
	int result;
	int opt;
	int option_index = 0;
	static char const short_options[] = "hvelf:";
	static struct option const long_options[] = {
		{"help",	no_argument,		0,	'h'},
		{"version",	no_argument,		0,	'v'},
		{"extract",	no_argument,		0,	'e'},
		{"list",	no_argument,		0,	'l'},
		{0,		0,			0,	0}
	};
	optind = 0;
	opterr = 0;

	/* some common variables. */
	char *program_name;
	char mpq_filename[PATH_MAX];
	unsigned int option = 0;
	unsigned int count;

	/* get program name. */
	program_name = argv[0];
	if (program_name && strrchr(program_name, '/')) {
		program_name = strrchr(program_name, '/') + 1;
	}

	/* if no command line option was given, show some info. */
	if (argc <= 1) {

		/* show some info on how to get help. :) */
		ERROR("%s: no action was given\n", program_name);
		ERROR("Try `%s --help' for more information.\n", program_name);

		/* exit with error. */
		exit(1);
	}

	/* if no command line option was given, show some info. */
	if (argc <= 1) {

		/* show some info on how to get help. :) */
		ERROR("%s: no action was given\n", program_name);
		ERROR("Try `%s --help' for more information.\n", program_name);

		/* exit with error. */
		exit(1);
	}

	/* parse command line. */
	while ((opt = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {

		/* check if all command line options are parsed. */
		if (opt == -1) {
			break;
		}

		/* parse option. */
		switch (opt) {
			case 'h':
				mpq_extract__usage(program_name);
				exit(0);
			case 'v':
				mpq_extract__version(program_name);
				exit(0);
			case 'l':
				option = 1;
				continue;
			case 'e':
				option = 2;
				continue;
			default:

				/* show some info on how to get help. :) */
				ERROR("%s: unrecognized option `%s'\n", program_name, argv[optind - 1]);
				ERROR("Try `%s --help' for more information.\n", program_name);

				/* exit with error. */
				exit(1);
		}
	}

	/* we assume first parameter which is left as archive. */
	strncpy(mpq_filename, argv[optind++], PATH_MAX);

	/* count number of files to process in archive. */
	count = argc - optind;

	/* process file names. */
	do {

		/* check if we should list archive only. */
		if (option == 1) {

			/* process archive. */
			result = mpq_extract__list(mpq_filename, argv[optind], argc - optind, count);
		}

		/* check if we should extract archive content. */
		if (option == 2) {

			/* extract archive content. */
			result = mpq_extract__extract(mpq_filename, argv[optind]);
		}

		/* check if archive was correctly opened. */
		if (result == LIBMPQ_ERROR_OPEN) {

			/* open archive failed. */
			ERROR("%s: '%s' no such file or directory\n", program_name, mpq_filename);

			/* if archive did not exist, we can stop everything. :) */
			exit(1);
		}

		/* check if file in archive exist. */
		if (result == LIBMPQ_ERROR_EXIST) {

			/* file was not found in archive. */
			ERROR("%s: '%s' no such file or directory in archive '%s'\n", program_name, argv[optind], mpq_filename);

			/* if file did not exist, we continue to next file. */
			continue;
		}
	} while (++optind < argc);

	/* execution was successful. */
	exit(0);
}
