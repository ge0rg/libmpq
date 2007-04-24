/*
 *  mpq-info.c -- functions for information about the given mpq archive.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "libmpq/mpq.h"
#include "mpq-info.h"

static int mpq_info_usage(unsigned int status, char *program_name) {
	if (status != 0) {
		fprintf(stderr, "Usage: %s [option]... [mpq-archive]...\n", program_name);
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	} else {
		printf("%s %i.%i.%i - shows information about the given mpq-archive.\n", program_name, MPQ_INFO_MAJOR_VERSION, MPQ_INFO_MINOR_VERSION, MPQ_INFO_PATCH_VERSION);
		printf("Usage: %s [option]... [mpq-archive]...\n", program_name);
		printf("Example: %s d2speech.mpq\n", program_name);
		printf("\n");
		printf("Main operation mode:\n");
		printf("  -h, --help                display this help and exit\n");
		printf("  -v, --version             print version information and exit\n");
		printf("\n");
		printf("Report bugs to <mbroemme@plusserver.de>\n");
	}
	return 0;
}

static char *mpq_info_version(char *program_name) {
	static char version[200];
	static char temp[200];

	snprintf(temp, sizeof(temp), "%s %i.%i.%i (%s)", program_name, MPQ_INFO_MAJOR_VERSION, MPQ_INFO_MINOR_VERSION, MPQ_INFO_PATCH_VERSION, OS);
	strncat(version, temp, sizeof(version));

	snprintf(temp, sizeof(temp), " libmpq/%s", libmpq_version());
	strncat(version, temp, sizeof(version));

#ifdef HAVE_LIBZ
	snprintf(temp, sizeof(temp), " zlib/%s", zlibVersion());
	strncat(version, temp, sizeof(version));
#endif

	return version;
}

static int mpq_info_show_version(char *program_name) {
	fprintf(stderr, "%s\n", mpq_info_version(program_name));
	fprintf(stderr, "\n");
	fprintf(stderr, "Copyright (C) 2003-2004 Maik Broemme <mbroemme@plusserver.de>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "This program comes with ABSOLUTELY NO WARRANTY. You may redistribute\n");
	fprintf(stderr, "copies of this program under the terms of the GNU General Public License.\n");
	return 0;
}

static int mpq_info_archive_info(mpq_info_options_s *mpq_info_options, unsigned char *filename) {
	unsigned int result = 0;
	unsigned int csize = 0;
	unsigned int fsize = 0;
	float ratio = 0;
	mpq_archive *mpq_a;

	mpq_a = malloc(sizeof(mpq_archive));
	memset(mpq_a, 0, sizeof(mpq_archive));

	result = libmpq_archive_open(mpq_a, filename);
	if (!result) {
		printf("archive number:          %i/%i\n", mpq_info_options->last_file, mpq_info_options->filenumber);
		printf("archive name:            %s\n", filename);
		if (mpq_a->flags == 0) {
			printf("archive type:            unprotected\n");
		} else {
			printf("archive type:            protected\n");
		}
		printf("archive size:            %i\n", libmpq_archive_info(mpq_a, LIBMPQ_MPQ_ARCHIVE_SIZE));
		printf("archive hashtable size:  %i\n", libmpq_archive_info(mpq_a, LIBMPQ_MPQ_HASHTABLE_SIZE));
		printf("archive blocktable size: %i\n", libmpq_archive_info(mpq_a, LIBMPQ_MPQ_BLOCKTABLE_SIZE));
		printf("archive blocksize:       %i\n", libmpq_archive_info(mpq_a, LIBMPQ_MPQ_BLOCKSIZE));
		printf("files in archive:        %i\n", libmpq_archive_info(mpq_a, LIBMPQ_MPQ_NUMFILES));
		csize = libmpq_archive_info(mpq_a, LIBMPQ_MPQ_COMPRESSED_SIZE);
		printf("compressed size:         %i\n", csize);
		fsize = libmpq_archive_info(mpq_a, LIBMPQ_MPQ_UNCOMPRESSED_SIZE);
		printf("uncompressed size:       %i\n", fsize);
		ratio = 100 - ((float)csize / (float)fsize * 100);
		printf("compression ratio:       %.2f%\n", ratio);
	} else {
		printf("archive number:          %i/%i\n", mpq_info_options->last_file, mpq_info_options->filenumber);
		printf("archive name:            %s\n", filename);
		printf("archive type:            no mpq archive\n");
	}

	/* always close file descriptor, file could be opened also if it is no valid mpq archive. */
	libmpq_archive_close(mpq_a);

	if (mpq_info_options->last_file < mpq_info_options->filenumber) {
		printf("\n-- next archive --\n\n");
	}

	free(mpq_a);
	return 0;
}

int main(int argc, char **argv) {
	char *program_name;
	int opt;
	int option_index = 0;
	unsigned char mpq_filename[PATH_MAX];

	mpq_info_options_s *mpq_info_options;

	static char const short_options[] = "vh";
	static struct option const long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"version", no_argument, 0, 'v'},
		{0, 0, 0, 0}
	};
	extern int optind;

	program_name = argv[0];
	if (program_name && strrchr(program_name, '/')) {
		program_name = strrchr(program_name, '/') + 1;
	}

	if (argc <= 1) {
		mpq_info_usage(1, program_name);
		exit(1);
	}

	/* allocate memory for argument structure */
	mpq_info_options = malloc(sizeof(mpq_info_options_s));
	memset(mpq_info_options, 0, sizeof(mpq_info_options_s));

	while (TRUE) {
		opt = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (opt == -1) {
			break;
		}
		if (opt == 'h') {
			mpq_info_usage(0, program_name);
			free(mpq_info_options);
			exit(0);
		}
		switch (opt) {
			case 'v':
				mpq_info_show_version(program_name);
				free(mpq_info_options);
				exit(0);
			default:
				mpq_info_usage(1, program_name);
				free(mpq_info_options);
				exit(1);
		}
	}

	/* fill option structure with long option arguments */
	mpq_info_options->filenumber = argc - optind;
	mpq_info_options->last_file  = 1;

	/* done parsing arguments, check for filenames. */
	if (optind < argc) {
		do {
			strncpy(mpq_filename, argv[optind], PATH_MAX);
			mpq_info_archive_info(mpq_info_options, mpq_filename);
			mpq_info_options->last_file++;
		} while (++optind < argc);
	} else {
		fprintf(stderr, "No filename given.\n");
		mpq_info_usage(1, program_name);
	}

	/* finaly free argument structure */
	free(mpq_info_options);
}
