/*
 * util.c -- set of various support routines.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */


#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "zonec.h"

#define MSB_32 0x80000000

int verbosity = 0;

static const char *global_ident = NULL;

void
log_msg(int priority, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(priority, format, args);
	va_end(args);
}

void
log_vmsg(int priority, const char *format, va_list args)
{
	vfprintf(stderr, format, args);
}

void
set_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	bits[index / 8] |= (1 << (7 - index % 8));
}

void
clear_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	bits[index / 8] &= ~(1 << (7 - index % 8));
}

int
get_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	return bits[index / 8] & (1 << (7 - index % 8));
}

lookup_table_type *
lookup_by_name(lookup_table_type *table, const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0)
			return table;
		table++;
	}
	return NULL;
}

lookup_table_type *
lookup_by_id(lookup_table_type *table, int id)
{
	while (table->name != NULL) {
		if (table->id == id)
			return table;
		table++;
	}
	return NULL;
}

char *
xstrdup(const char *src)
{
	char *result = strdup(src);

	if(!result) {
		log_msg(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(1);
	}

	return result;
}

void *
xalloc(size_t size)
{
	void *result = malloc(size);

	if (!result) {
		log_msg(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(1);
	}
	return result;
}

void *
xmallocarray(size_t num, size_t size)
{
        void *result = reallocarray(NULL, num, size);

        if (!result) {
                log_msg(LOG_ERR, "reallocarray failed: %s", strerror(errno));
                exit(1);
        }
        return result;
}

void *
xalloc_zero(size_t size)
{
	void *result = calloc(1, size);
	if (!result) {
		log_msg(LOG_ERR, "calloc failed: %s", strerror(errno));
		exit(1);
	}
	return result;
}

void *
xalloc_array_zero(size_t num, size_t size)
{
	void *result = calloc(num, size);
	if (!result) {
		log_msg(LOG_ERR, "calloc failed: %s", strerror(errno));
		exit(1);
	}
	return result;
}

void *
xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (!ptr) {
		log_msg(LOG_ERR, "realloc failed: %s", strerror(errno));
		exit(1);
	}
	return ptr;
}

uint32_t
strtoserial(const char* nptr, const char** endptr)
{
	uint32_t i = 0;
	uint32_t serial = 0;

	for(*endptr = nptr; **endptr; (*endptr)++) {
		switch (**endptr) {
		case ' ':
		case '\t':
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			if((i*10)/10 != i)
				/* number too large, return i
				 * with *endptr != 0 as a failure*/
				return i;
			i *= 10;
			i += (**endptr - '0');
			break;
		default:
			return 0;
		}
	}
	serial += i;
	return serial;
}

uint32_t
strtottl(const char *nptr, const char **endptr)
{
	uint32_t i = 0;
	uint32_t seconds = 0;

	for(*endptr = nptr; **endptr; (*endptr)++) {
		switch (**endptr) {
		case ' ':
		case '\t':
			break;
		case 's':
		case 'S':
			seconds += i;
			i = 0;
			break;
		case 'm':
		case 'M':
			seconds += i * 60;
			i = 0;
			break;
		case 'h':
		case 'H':
			seconds += i * 60 * 60;
			i = 0;
			break;
		case 'd':
		case 'D':
			seconds += i * 60 * 60 * 24;
			i = 0;
			break;
		case 'w':
		case 'W':
			seconds += i * 60 * 60 * 24 * 7;
			i = 0;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			i *= 10;
			i += (**endptr - '0');
			break;
		default:
			seconds += i;
			/**
			 * According to RFC2308, Section 8, the MSB
			 * (sign bit) should be set to zero.
			 * If we encounter a value larger than 2^31 -1,
			 * we fall back to the default TTL.
			 */
			if ((seconds & MSB_32)) {
				seconds = DEFAULT_TTL;
			}
			return seconds;
		}
	}
	seconds += i;
	if ((seconds & MSB_32)) {
		seconds = DEFAULT_TTL;
	}
	return seconds;
}

ssize_t
hex_pton(const char* src, uint8_t* target, size_t targsize)
{
	uint8_t *t = target;
	if(strlen(src) % 2 != 0 || strlen(src)/2 > targsize) {
		return -1;
	}
	while(*src) {
		if(!isxdigit((unsigned char)src[0]) ||
			!isxdigit((unsigned char)src[1]))
			return -1;
		*t++ = hexdigit_to_int(src[0]) * 16 +
			hexdigit_to_int(src[1]) ;
		src += 2;
	}
	return t-target;
}

int
b32_pton(const char *src, uint8_t *target, size_t tsize)
{
	char ch;
	size_t p=0;

	memset(target,'\0',tsize);
	while((ch = *src++)) {
		uint8_t d;
		size_t b;
		size_t n;

		if(p+5 >= tsize*8)
		       return -1;

		if(isspace((unsigned char)ch))
			continue;

		if(ch >= '0' && ch <= '9')
			d=ch-'0';
		else if(ch >= 'A' && ch <= 'V')
			d=ch-'A'+10;
		else if(ch >= 'a' && ch <= 'v')
			d=ch-'a'+10;
		else
			return -1;

		b=7-p%8;
		n=p/8;

		if(b >= 4)
			target[n]|=d << (b-4);
		else {
			target[n]|=d >> (4-b);
			target[n+1]|=d << (b+4);
		}
		p+=5;
	}
	return (p+7)/8;
}

void
strip_string(char *str)
{
	char *start = str;
	char *end = str + strlen(str) - 1;

	while (isspace((unsigned char)*start))
		++start;
	if (start > end) {
		/* Completely blank. */
		str[0] = '\0';
	} else {
		while (isspace((unsigned char)*end))
			--end;
		*++end = '\0';

		if (str != start)
			memmove(str, start, end - start + 1);
	}
}

int
hexdigit_to_int(char ch)
{
	switch (ch) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': case 'A': return 10;
	case 'b': case 'B': return 11;
	case 'c': case 'C': return 12;
	case 'd': case 'D': return 13;
	case 'e': case 'E': return 14;
	case 'f': case 'F': return 15;
	default:
		abort();
	}
}

/* Number of days per month (except for February in leap years). */
static const int mdays[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static int
is_leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int
leap_days(int y1, int y2)
{
    --y1;
    --y2;
    return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
 * Code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
time_t
mktime_from_utc(const struct tm *tm)
{
    int year = 1900 + tm->tm_year;
    time_t days = 365 * (year - 1970) + leap_days(1970, year);
    time_t hours;
    time_t minutes;
    time_t seconds;
    int i;

    for (i = 0; i < tm->tm_mon; ++i) {
        days += mdays[i];
    }
    if (tm->tm_mon > 1 && is_leap_year(year)) {
        ++days;
    }
    days += tm->tm_mday - 1;

    hours = days * 24 + tm->tm_hour;
    minutes = hours * 60 + tm->tm_min;
    seconds = minutes * 60 + tm->tm_sec;

    return seconds;
}

/*
 * Something went wrong, give error messages and exit.
 */
void
error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_ERR, format, args);
	va_end(args);
	exit(1);
}
