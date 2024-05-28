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
#include "util.h"

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
dname_parse(region_type *region, const char *name)
{
  uint8_t dname[MAXDOMAINLEN];
  if(!dname_parse_wire(dname, name))
    return 0;
  return dname_make(region, dname, 1);
}

int dname_parse_wire(uint8_t* dname, const char* name)
{
  const uint8_t *s = (const uint8_t *) name;
  uint8_t *h;
  uint8_t *p;
  uint8_t *d = dname;
  size_t label_length;

  if (strcmp(name, ".") == 0) {
    /* Root domain.  */
    dname[0] = 0;
    return 1;
  }

  for (h = d, p = h + 1; *s; ++s, ++p) {
    if (p - dname >= MAXDOMAINLEN) {
      return 0;
    }

    switch (*s) {
    case '.':
      if (p == h + 1) {
        /* Empty label.  */
        return 0;
      } else {
        label_length = p - h - 1;
        if (label_length > MAXLABELLEN) {
          return 0;
        }
        *h = label_length;
        h = p;
      }
      break;
    case '\\':
      /* Handle escaped characters (RFC1035 5.1) */
      if (isdigit((unsigned char)s[1]) && isdigit((unsigned char)s[2]) && isdigit((unsigned char)s[3])) {
        int val = (hexdigit_to_int(s[1]) * 100 +
             hexdigit_to_int(s[2]) * 10 +
             hexdigit_to_int(s[3]));
        if (0 <= val && val <= 255) {
          s += 3;
          *p = val;
        } else {
          *p = *++s;
        }
      } else if (s[1] != '\0') {
        *p = *++s;
      }
      break;
    default:
      *p = *s;
      break;
    }
  }

  if (p != h + 1) {
    /* Terminate last label.  */
    label_length = p - h - 1;
    if (label_length > MAXLABELLEN) {
      return 0;
    }
    *h = label_length;
    h = p;
    p++;
  }

  /* Add root label.  */
  if (h - dname >= MAXDOMAINLEN) {
    return 0;
  }
  *h = 0;

  return p-dname;
}

const dname_type *
dname_copy(region_type *region, const dname_type *dname)
{
  return (dname_type *) region_alloc_init(
    region, dname, dname_total_size(dname));
}

const dname_type *
dname_make_from_label(region_type *region,
          const uint8_t *label, const size_t length)
{
  uint8_t temp[MAXLABELLEN + 2];

  assert(length > 0 && length <= MAXLABELLEN);

  temp[0] = length;
  memcpy(temp + 1, label, length * sizeof(uint8_t));
  temp[length + 1] = '\000';

  return dname_make(region, temp, 1);
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
