/*
 *  mpq-extract.c -- functions for extract files from a given mpq archive.
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
 *  $Id: mpq-extract.c,v 1.18 2004/02/12 00:39:17 mbroemme Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>
#include "libmpq/mpq.h"
#include "mpq-extract.h"

static char *program_name;

static int mpq_extract_usage(unsigned int status) {
	if (status != 0) {
		fprintf(stderr, "Usage: %s [option]... [mpq-archive]\n", program_name);
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	} else {
		printf("%s %i.%i.%i - shows information about the given mpq-archive.\n", program_name, MPQ_EXTRACT_MAJOR_VERSION, MPQ_EXTRACT_MINOR_VERSION, MPQ_EXTRACT_PATCH_VERSION);
		printf("Usage: %s [option]... [mpq-archive]\n", program_name);
		printf("Example: %s d2speech.mpq\n", program_name);
		printf("\n");
		printf("Main operation mode:\n");
		printf("  -e, --extract             extract files from the given mpq archive\n");
		printf("  -l, --list                list the contents of a mpq archive\n");
		printf("  -f, --file                list or extract only selected file\n");
		printf("      --listfile            listfile for mapping filenames to hash entries\n");
		printf("\n");
		printf("Sub options if --file is given:\n");
		printf("      --number              list or extract file by given number\n");
		printf("\n");
		printf("Informative output:\n");
		printf("  -h, --help                display this help and exit\n");
		printf("  -v, --version             print version information and exit\n");
		printf("\n");
		printf("Report bugs to <mbroemme@plusserver.de>\n");
	}
	return 0;
}

static char *mpq_extract_version() {
	static char version[200];
	static char temp[200];

	snprintf(temp, sizeof(temp), "%s %i.%i.%i (%s)", program_name, MPQ_EXTRACT_MAJOR_VERSION, MPQ_EXTRACT_MINOR_VERSION, MPQ_EXTRACT_PATCH_VERSION, OS);
	strncat(version, temp, sizeof(version));

	snprintf(temp, sizeof(temp), " libmpq/%s", libmpq_version());
	strncat(version, temp, sizeof(version));

#ifdef HAVE_LIBZ
	snprintf(temp, sizeof(temp), " zlib/%s", zlibVersion());
	strncat(version, temp, sizeof(version));
#endif

	return version;
}

static int mpq_extract_show_version() {
	fprintf(stderr, "%s\n", mpq_extract_version(program_name));
	fprintf(stderr, "\n");
	fprintf(stderr, "Copyright (C) 2003-2004 Maik Broemme <mbroemme@plusserver.de>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "This program comes with ABSOLUTELY NO WARRANTY. You may redistribute\n");
	fprintf(stderr, "copies of this program under the terms of the GNU General Public License.\n");
	return 0;
}

static int mpq_extract_file_extract(mpq_extract_options_s *mpq_extract_options, unsigned char *mpq_filename) {
	unsigned int result = 0;
	int i = 0;
	unsigned int filenumber = 0;
	mpq_archive *mpq_a;

	mpq_a = malloc(sizeof(mpq_archive));
	memset(mpq_a, 0, sizeof(mpq_archive));

	result = libmpq_archive_open(mpq_a, mpq_filename);
	if (!result) {
		printf("detecting listfile... ");

		/* check if there occurs an error while processing the listfile */
		switch (libmpq_listfile_open(mpq_a, mpq_extract_options->listfile)) {
			case LIBMPQ_CONF_EFILE_OPEN:
				printf("found filelist, but could not open, so disabling listfile\n");
				break;
			case LIBMPQ_CONF_EFILE_CORRUPT:
				printf("found filelist with errors, so disabling listfile\n");
				break;
			case LIBMPQ_CONF_EFILE_LIST_CORRUPT:
				printf("found filelist, header matches %s, but filelist is corrupt.\n", mpq_a->mpq_l->mpq_name);
				break;
			case LIBMPQ_CONF_EFILE_VERSION:
				printf("found filelist, but libmpq %s is required.\n", mpq_a->mpq_l->mpq_version);
				break;
			case LIBMPQ_CONF_EFILE_NOT_FOUND:
				printf("not found\n");
				break;
			default:
				printf("found\n");
				printf("game: %s, file: %s, version: %s\n", mpq_a->mpq_l->mpq_game, mpq_a->mpq_l->mpq_name, mpq_a->mpq_l->mpq_game_version);
				break;
		}

		/* if -f, --file option is given try to get filename */
		if (mpq_extract_options->file) {
			if (mpq_extract_options->number) {
				filenumber = atoi(mpq_extract_options->filename);
				if (libmpq_file_check(mpq_a, &filenumber, LIBMPQ_FILE_TYPE_INT)) {
					fprintf(stderr, "file %i not found\n", filenumber);
				} else {
					printf("extracting %s ...\n", libmpq_file_name(mpq_a, filenumber));
					libmpq_file_extract(mpq_a, filenumber);
				}
			} else {
				if (libmpq_file_check(mpq_a, mpq_extract_options->filename, LIBMPQ_FILE_TYPE_CHAR)) {
					fprintf(stderr, "file %s not found\n", mpq_extract_options->filename);
				} else {

					/* get filenumber from filename for internal handling */
					filenumber = libmpq_file_number(mpq_a, mpq_extract_options->filename);
					printf("extracting %s ...\n", libmpq_file_name(mpq_a, filenumber));
					libmpq_file_extract(mpq_a, filenumber);
				}
			}
		}

		/* list all files */
		if (!mpq_extract_options->file) {
			for (i = 1; i <= libmpq_archive_info(mpq_a, LIBMPQ_MPQ_NUMFILES); i++) {
				printf("extracting %s ...\n", libmpq_file_name(mpq_a, i));
				libmpq_file_extract(mpq_a, i);
			}
		}
	} else {
		printf("archive name: %s\n", mpq_filename);
		printf("archive type: no mpq archive\n");
	}

	/* close listfile for the hashes */
	libmpq_listfile_close(mpq_a);

	/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
	libmpq_archive_close(mpq_a);
                
	if (mpq_extract_options->last_file < mpq_extract_options->filenumber) {
		printf("\n-- next archive --\n\n");
	}

	free(mpq_a);

	return 0;
}

static int mpq_extract_file_list(mpq_extract_options_s *mpq_extract_options, unsigned char *mpq_filename) {
	unsigned int result = 0;
	unsigned int csize = 0;
	unsigned int fsize = 0;
	unsigned char ctype[8];
	int i = 0;
	unsigned int filenumber = 0;
	float ratio = 0;
	mpq_archive *mpq_a;

	mpq_a = malloc(sizeof(mpq_archive));
	memset(mpq_a, 0, sizeof(mpq_archive));

	result = libmpq_archive_open(mpq_a, mpq_filename);
	if (!result) {
		printf("detecting listfile... ");

		/* check if there occurs an error while processing the listfile */
		switch (libmpq_listfile_open(mpq_a, mpq_extract_options->listfile)) {
			case LIBMPQ_CONF_EFILE_OPEN:
				printf("found filelist, but could not open, so disabling listfile\n");
				break;
			case LIBMPQ_CONF_EFILE_CORRUPT:
				printf("found filelist with errors, so disabling listfile\n");
				break;
			case LIBMPQ_CONF_EFILE_LIST_CORRUPT:
				printf("found filelist, header matches %s, but filelist is corrupt.\n", mpq_a->mpq_l->mpq_name);
				break;
			case LIBMPQ_CONF_EFILE_VERSION:
				printf("found filelist, but libmpq %s is required.\n", mpq_a->mpq_l->mpq_version);
				break;
			case LIBMPQ_CONF_EFILE_NOT_FOUND:
				printf("not found\n");
				break;
			default:
				printf("found\n");
				printf("game: %s, file: %s, version: %s\n", mpq_a->mpq_l->mpq_game, mpq_a->mpq_l->mpq_name, mpq_a->mpq_l->mpq_game_version);
				break;
		}

		/* if -f, --file option is given try to get filename */
		if (mpq_extract_options->file) {
			if (mpq_extract_options->number) {
				filenumber = atoi(mpq_extract_options->filename);
				if (libmpq_file_check(mpq_a, &filenumber, LIBMPQ_FILE_TYPE_INT)) {
					fprintf(stderr, "file %i not found\n", filenumber);
				} else {
					printf("number   ucmp. size   cmp. size   ratio   cmp. type   filename\n");
					printf("------   ----------   ---------   -----   ---------   --------\n");
					csize = libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSED_SIZE, filenumber);
					fsize = libmpq_file_info(mpq_a, LIBMPQ_FILE_UNCOMPRESSED_SIZE, filenumber);
					if (libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSION_TYPE, filenumber) == LIBMPQ_FILE_COMPRESS_PKWARE) {
						snprintf(ctype, sizeof(ctype), "PKWARE");
					}
					if (libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSION_TYPE, filenumber) == LIBMPQ_FILE_COMPRESS_MULTI) {
						snprintf(ctype, sizeof(ctype), "MULTI");
					}
					ratio = 100 - ((float)csize / (float)fsize * 100);
					printf("  %4i   %10i   %9i %6.0f%%    %8s   %s\n", filenumber, fsize, csize, fabs(ratio), ctype, libmpq_file_name(mpq_a, filenumber));

					/* collect archive information */
					csize = libmpq_archive_info(mpq_a, LIBMPQ_MPQ_COMPRESSED_SIZE);
					fsize = libmpq_archive_info(mpq_a, LIBMPQ_MPQ_UNCOMPRESSED_SIZE);
					ratio = 100 - ((float)csize / (float)fsize * 100);
					printf("------   ----------   ---------   -----   ---------   --------\n");
					printf("  %4i   %10i   %9i %6.0f%%   %s\n", libmpq_archive_info(mpq_a, LIBMPQ_MPQ_NUMFILES), libmpq_archive_info(mpq_a, LIBMPQ_MPQ_UNCOMPRESSED_SIZE), libmpq_archive_info(mpq_a, LIBMPQ_MPQ_COMPRESSED_SIZE), fabs(ratio), mpq_filename);
				}
			} else {
				if (libmpq_file_check(mpq_a, mpq_extract_options->filename, LIBMPQ_FILE_TYPE_CHAR)) {
					fprintf(stderr, "file %s not found\n", mpq_extract_options->filename);
				} else {

					/* get filenumber from filename for internal handling */
					filenumber = libmpq_file_number(mpq_a, mpq_extract_options->filename);
					printf("number   ucmp. size   cmp. size   ratio   cmp. type   filename\n");
					printf("------   ----------   ---------   -----   ---------   --------\n");
					csize = libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSED_SIZE, filenumber);
					fsize = libmpq_file_info(mpq_a, LIBMPQ_FILE_UNCOMPRESSED_SIZE, filenumber);
					if (libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSION_TYPE, filenumber) == LIBMPQ_FILE_COMPRESS_PKWARE) {
						snprintf(ctype, sizeof(ctype), "PKWARE");
					}
					if (libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSION_TYPE, filenumber) == LIBMPQ_FILE_COMPRESS_MULTI) {
						snprintf(ctype, sizeof(ctype), "MULTI");
					}
					ratio = 100 - ((float)csize / (float)fsize * 100);
					printf("  %4i   %10i   %9i %6.0f%%    %8s   %s\n", filenumber, fsize, csize, fabs(ratio), ctype, libmpq_file_name(mpq_a, filenumber));

					/* collect archive information */
					csize = libmpq_archive_info(mpq_a, LIBMPQ_MPQ_COMPRESSED_SIZE);
					fsize = libmpq_archive_info(mpq_a, LIBMPQ_MPQ_UNCOMPRESSED_SIZE);
					ratio = 100 - ((float)csize / (float)fsize * 100);
					printf("------   ----------   ---------   -----   ---------   --------\n");
					printf("  %4i   %10i   %9i %6.0f%%   %s\n", libmpq_archive_info(mpq_a, LIBMPQ_MPQ_NUMFILES), libmpq_archive_info(mpq_a, LIBMPQ_MPQ_UNCOMPRESSED_SIZE), libmpq_archive_info(mpq_a, LIBMPQ_MPQ_COMPRESSED_SIZE), fabs(ratio), mpq_filename);
				}
			}
		}

		/* list all files */
		if (!mpq_extract_options->file) {
			printf("number   ucmp. size   cmp. size   ratio   cmp. type   filename\n");
			printf("------   ----------   ---------   -----   ---------   --------\n");
			for (i = 1; i <= libmpq_archive_info(mpq_a, LIBMPQ_MPQ_NUMFILES); i++) {
				csize = libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSED_SIZE, i);
				fsize = libmpq_file_info(mpq_a, LIBMPQ_FILE_UNCOMPRESSED_SIZE, i);
				if (libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSION_TYPE, i) == LIBMPQ_FILE_COMPRESS_PKWARE) {
					snprintf(ctype, sizeof(ctype), "PKWARE");
				}
				if (libmpq_file_info(mpq_a, LIBMPQ_FILE_COMPRESSION_TYPE, i) == LIBMPQ_FILE_COMPRESS_MULTI) {
					snprintf(ctype, sizeof(ctype), "MULTI");
				}
				ratio = 100 - ((float)csize / (float)fsize * 100);
				printf("  %4i   %10i   %9i %6.0f%%    %8s   %s\n", i, fsize, csize, fabs(ratio), ctype, libmpq_file_name(mpq_a, i));
			}
			/* collect archive information */
			csize = libmpq_archive_info(mpq_a, LIBMPQ_MPQ_COMPRESSED_SIZE);
			fsize = libmpq_archive_info(mpq_a, LIBMPQ_MPQ_UNCOMPRESSED_SIZE);
			ratio = 100 - ((float)csize / (float)fsize * 100);
			printf("------   ----------   ---------   -----   ---------   --------\n");
			printf("  %4i   %10i   %9i %6.0f%%   %s\n", libmpq_archive_info(mpq_a, LIBMPQ_MPQ_NUMFILES), libmpq_archive_info(mpq_a, LIBMPQ_MPQ_UNCOMPRESSED_SIZE), libmpq_archive_info(mpq_a, LIBMPQ_MPQ_COMPRESSED_SIZE), fabs(ratio), mpq_filename);
		}
	} else {
		printf("archive name: %s\n", mpq_filename);
		printf("archive type: no mpq archive\n");
	}

	/* close listfile for the hashes */
	libmpq_listfile_close(mpq_a);

	/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
	libmpq_archive_close(mpq_a);
                
	if (mpq_extract_options->last_file < mpq_extract_options->filenumber) {
		printf("\n-- next archive --\n\n");
	}

	free(mpq_a);

	return 0;
}

int main(int argc, char **argv) {
	int opt;
	int option_index = 0;
	unsigned char mpq_filename[PATH_MAX];

	mpq_extract_options_s *mpq_extract_options;

	static char const short_options[] = "hevlf:";
	static struct option const long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"extract", no_argument, 0, 'e'},
		{"version", no_argument, 0, 'v'},
		{"list", no_argument, 0, 'l'},
		{"listfile", required_argument, 0, MPQ_EXTRACT_LISTFILE_OPTION},
		{"file", required_argument, 0, 'f'},
		{"number", no_argument, 0, MPQ_EXTRACT_NUMBER_OPTION},
		{0, 0, 0, 0}
	};
	extern int optind;
	struct stat statbuf;

	program_name = argv[0];
	if (program_name && strrchr(program_name, '/')) {
		program_name = strrchr(program_name, '/') + 1;
	}

	if (argc <= 1) {
		mpq_extract_usage(1);
		exit(1);
	}

	/* allocate memory for argument structure */
	mpq_extract_options = malloc(sizeof(mpq_extract_options_s));
	memset(mpq_extract_options, 0, sizeof(mpq_extract_options_s));

	/* initialize some default values for the options */
	mpq_extract_options->number = 0;
	mpq_extract_options->listfile = NULL;

	while (TRUE) {
		opt = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (opt == -1) {
			break;
		}
		if (opt == 'h') {
			mpq_extract_usage(0);
			exit(0);
		}
		switch (opt) {
			case 'e':
				mpq_extract_options->extract = 1;
				break;
			case 'l':
				mpq_extract_options->list = 1;
				break;
			case 'v':
				mpq_extract_show_version();
				free(mpq_extract_options);
				exit(0);
			case 'f':
				mpq_extract_options->filename = optarg;
				mpq_extract_options->file = 1;
				break;
			case MPQ_EXTRACT_LISTFILE_OPTION:
				stat(optarg, &statbuf);
				if (S_ISREG(statbuf.st_mode)) {
					mpq_extract_options->listfile = optarg;
				} else {
					mpq_extract_options->listfile = LIBMPQ_LISTDB_PATH;
				}
				break;
			case MPQ_EXTRACT_NUMBER_OPTION:
				mpq_extract_options->number = 1;
				break;
			default:
				mpq_extract_usage(1);
				free(mpq_extract_options);
				exit(1);
		}
	}

	/* if extract and list are set -> exit */
	if (mpq_extract_options->extract == 1 && mpq_extract_options->list == 1) {
		fprintf(stderr, "You can not list and extract contents of an archive at the same time.\n");
		mpq_extract_usage(1);
		free(mpq_extract_options);
		exit(1);
	}

	/* if no extract or list set -> exit */
	if (mpq_extract_options->extract == 0 && mpq_extract_options->list == 0) {
		fprintf(stderr, "No operation selected.\n");
		mpq_extract_usage(1);
		free(mpq_extract_options);
		exit(1);
	}

	/* fill option structure with long option arguments */
	mpq_extract_options->filenumber = argc - optind;
	mpq_extract_options->last_file  = 1;

	/* if no listfile was forced, try internal one */
	if (mpq_extract_options->listfile == NULL) {
		mpq_extract_options->listfile = LIBMPQ_LISTDB_PATH;
	}

	/* done parsing arguments, check for filenumbers. */
	if (optind < argc) {
		do {
			strncpy(mpq_filename, argv[optind], PATH_MAX);
			if (mpq_extract_options->list == 1) {
				mpq_extract_file_list(mpq_extract_options, mpq_filename);
			}
			if (mpq_extract_options->extract == 1) {
				mpq_extract_file_extract(mpq_extract_options, mpq_filename);
			}
			mpq_extract_options->last_file++;
		} while (++optind < argc);
	} else {
		fprintf(stderr, "No mpq archive given.\n");
		mpq_extract_usage(1);
	}

	/* finaly free argument structure */
	free(mpq_extract_options);
}
