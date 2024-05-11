/*
 * dname.c -- Domain name handling.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */



#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
#include "dname.h"

const dname_type *
dname_make(region_type *region, const uint8_t *name, int normalize)
{
	size_t name_size = 0;
	uint8_t label_offsets[MAXDOMAINLEN];
	uint8_t label_count = 0;
	const uint8_t *label = name;
	dname_type *result;
	ssize_t i;

	assert(name);

	while (1) {
		if (label_is_pointer(label))
			return NULL;

		label_offsets[label_count] = (uint8_t) (label - name);
		++label_count;
		name_size += label_length(label) + 1;

		if (label_is_root(label))
			break;

		label = label_next(label);
	}

	if (name_size > MAXDOMAINLEN)
		return NULL;

	assert(label_count <= MAXDOMAINLEN / 2 + 1);

	/* Reverse label offsets.  */
	for (i = 0; i < label_count / 2; ++i) {
		uint8_t tmp = label_offsets[i];
		label_offsets[i] = label_offsets[label_count - i - 1];
		label_offsets[label_count - i - 1] = tmp;
	}

	result = (dname_type *) region_alloc(
		region,
		(sizeof(dname_type)
		 + (((size_t)label_count) + ((size_t)name_size)) * sizeof(uint8_t)));
	result->name_size = name_size;
	result->label_count = label_count;
	memcpy((uint8_t *) dname_label_offsets(result),
	       label_offsets,
	       label_count * sizeof(uint8_t));
	if (normalize) {
		uint8_t *dst = (uint8_t *) dname_name(result);
		const uint8_t *src = name;
		while (!label_is_root(src)) {
			ssize_t len = label_length(src);
			*dst++ = *src++;
			for (i = 0; i < len; ++i) {
				*dst++ = DNAME_NORMALIZE((unsigned char)*src++);
			}
		}
		*dst = *src;
	} else {
		memcpy((uint8_t *) dname_name(result),
		       name,
		       name_size * sizeof(uint8_t));
	}
	return result;
}

const dname_type *
dname_concatenate(region_type *region,
		  const dname_type *left,
		  const dname_type *right)
{
	uint8_t temp[MAXDOMAINLEN];

	assert(left->name_size + right->name_size - 1 <= MAXDOMAINLEN);

	memcpy(temp, dname_name(left), left->name_size - 1);
	memcpy(temp + left->name_size - 1, dname_name(right), right->name_size);

	return dname_make(region, temp, 0);
}

int dname_equal_nocase(uint8_t* a, uint8_t* b, uint16_t len)
{
	uint8_t i, lablen;
	while(len > 0) {
		/* check labellen */
		if(*a != *b)
			return 0;
		lablen = *a++;
		b++;
		len--;
		/* malformed or compression ptr; we stop scanning */
		if((lablen & 0xc0) || len < lablen)
			return (memcmp(a, b, len) == 0);
		/* check the label, lowercased */
		for(i=0; i<lablen; i++) {
			if(DNAME_NORMALIZE((unsigned char)*a++) != DNAME_NORMALIZE((unsigned char)*b++))
				return 0;
		}
		len -= lablen;
	}
	return 1;
}
