/*
 *  huffman.h -- structures used for huffman compression.
 *
 *  Copyright (c) 2003-2007 Maik Broemme <mbroemme@plusserver.de>
 *
 *  This source was adepted from the C++ version of huffman.h included
 *  in stormlib. The C++ version belongs to the following authors:
 *
 *  Ladislav Zezula <ladik@zezula.net>
 *  ShadowFlare <BlakFlare@hotmail.com>
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

#ifndef _HUFFMAN_H
#define _HUFFMAN_H

/* define pointer conversions. */
#define PTR_NOT(ptr)				(struct huffman_tree_item *)(~(unsigned long)(ptr))
#define PTR_PTR(ptr)				((struct huffman_tree_item *)(ptr))
#define PTR_INT(ptr)				(long)(ptr)

/* define item handling. */
#define INSERT_ITEM				1		/* insert item into huffman tree. */
#define SWITCH_ITEMS				2		/* switch items isnide huffman tree. */

/* input stream for huffmann decompression. */
struct huffman_input_stream {
	unsigned char		*in_buf;				/* 00 - input data. */
	unsigned int	bit_buf;				/* 04 - input bit buffer. */
	unsigned int	bits;					/* 08 - number of bits remaining in byte. */
};

/* huffman tree item. */
struct huffman_tree_item {
	struct		huffman_tree_item *next;		/* 00 - pointer to next huffman tree item. */
	struct		huffman_tree_item *prev;		/* 04 - pointer to prev huffman tree item (< 0 if none). */
	unsigned int	dcmp_byte;				/* 08 - index of this item in item pointer array, decompressed byte value. */
	unsigned int	byte_value;				/* 0C - some byte value. */
	struct		huffman_tree_item *parent;		/* 10 - pointer to parent huffman tree item (NULL if none). */
	struct		huffman_tree_item *child;		/* 14 - pointer to child huffman tree item. */
};

/* structure used for quick decompression. */
struct huffman_decompress {
	unsigned int	offs00;					/* 00 - 1 if resolved. */
	unsigned int	bits;					/* 04 - bit count. */
	union {
		unsigned int	dcmp_byte;			/* 08 - byte value for decompress (if bitCount <= 7). */
		struct		huffman_tree_item *p_item;	/* 08 - huffman tree item (if number of bits is greater than 7). */
	};
};

/* structure for huffman tree. */
struct huffman_tree {
	unsigned int	cmp0;					/* 0000 - 1 if compression type 0. */
	unsigned int	offs0004;				/* 0004 - some flag. */
	struct		huffman_tree_item items0008[0x203];	/* 0008 - huffman tree items. */
	struct		huffman_tree_item *item3050;		/* 3050 - always NULL? */
	struct		huffman_tree_item *item3054;		/* 3054 - pointer to huffman tree item. */
	struct		huffman_tree_item *item3058;		/* 3058 - pointer to huffman tree item (< 0 if invalid). */
	struct		huffman_tree_item *item305C;		/* 305C - usually NULL. */
	struct		huffman_tree_item *first;		/* 3060 - pointer to top (first) huffman tree item. */
	struct		huffman_tree_item *last;		/* 3064 - pointer to bottom (last) huffman tree item (< 0 if invalid). */
	unsigned int	items;					/* 3068 - number of used huffman tree items. */
	struct		huffman_tree_item *items306C[0x102];	/* 306C - huffman tree item pointer array. */
	struct		huffman_decompress qd3474[0x80];	/* 3474 - array for quick decompression. */
	unsigned char	table_1502A630[];			/* some table to make struct size flexible. */
};

/* insert a new item into huffman tree. */
void libmpq__huffman_insert_item(
	struct		huffman_tree_item **p_item,
	struct		huffman_tree_item *item,
	unsigned int	where,
	struct		huffman_tree_item *item2
);

/* remove item from huffman tree. */
void libmpq__huffman_remove_item(
	struct		huffman_tree_item *hi
);

/* get previous item from huffman tree. */
struct huffman_tree_item *libmpq__huffman_previous_item(
	struct		huffman_tree_item *hi,
	long		value
);

/* get one bit from stream. */
unsigned int libmpq__huffman_get_1bit(
	struct		huffman_input_stream *is
);

/* get seven bit from stream. */
unsigned int libmpq__huffman_get_7bit(
	struct		huffman_input_stream *is
);

/* get eight bit from stream. */
unsigned int libmpq__huffman_get_8bit(
	struct		huffman_input_stream *is
);

/* call 1500E740. */
struct huffman_tree_item *libmpq__huffman_call_1500E740(
	struct		huffman_tree *ht
);

/* call 1500E820- */
void libmpq__huffman_call_1500E820(
	struct		huffman_tree *ht,
	struct		huffman_tree_item *p_item
);

/* initialize the huffman tree. */
void libmpq__huffman_tree_init(
	struct		huffman_tree *ht,
	struct		huffman_tree_item *hi,
	unsigned int	cmp
);

/* build the huffman tree. */
void libmpq__huffman_tree_build(
	struct		huffman_tree *ht,
	unsigned int	cmp_type
);

/* decompress the stream using huffman compression. */
int libmpq__do_decompress_huffman(
	struct		huffman_tree *ht,
	struct		huffman_input_stream *is,
	unsigned char	*out_buf,
	unsigned int	out_length
);

#endif						/* _HUFFMAN_H */
