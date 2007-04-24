/*
 *  mpq-extract.h -- some default types and defines.
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
 *  $Id: mpq-extract.h,v 1.4 2004/02/12 00:36:13 mbroemme Exp $
 */

#ifndef _MPQ_EXTRACT_H
#define _MPQ_EXTRACT_H

#define MPQ_EXTRACT_MAJOR_VERSION	0
#define MPQ_EXTRACT_MINOR_VERSION	2
#define MPQ_EXTRACT_PATCH_VERSION	0

#define MPQ_EXTRACT_LISTFILE_OPTION	1
#define MPQ_EXTRACT_NUMBER_OPTION	2

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef OS
#define OS "unknown"
#endif

typedef struct {
	unsigned int	filenumber;	/* number of archives to check. */
	unsigned int	last_file;	/* number of last accessed archive. */
	unsigned int	extract;	/* extract files from an archive. */
	unsigned int	list;		/* list files from an archive. */
	unsigned char	*listfile;	/* listfile option set? */
	unsigned int	number;		/* handle file as number */
	unsigned int	file;		/* handle a specific file */
	unsigned char	*filename;	/* process only this file */
} mpq_extract_options_s;

#endif		/* _MPQ_EXTRACT_H */
