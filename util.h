/*
 * util.h -- set of various support routines.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
struct rr;
struct buffer;
struct region;
struct nsd;

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#else
#  define LOG_ERR 3
#  define LOG_WARNING 4
#  define LOG_NOTICE 5
#  define LOG_INFO 6

/* Unused, but passed to log_open. */
#  define LOG_PID 0x01
#  define LOG_DAEMON (3<<3)
#endif

#define ALIGN_UP(n, alignment)  \
	(((n) + (alignment) - 1) & (~((alignment) - 1)))
#define PADDING(n, alignment)   \
	(ALIGN_UP((n), (alignment)) - (n))

/*
 * Type of function to use for the actual logging.
 */
typedef void log_function_type(int priority, const char *message);

/*
 * Log a message using the current log function.
 */
void log_msg(int priority, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

/*
 * Log a message using the current log function.
 */
void log_vmsg(int priority, const char *format, va_list args);

/*
 * Verbose output switch
 */
extern int verbosity;
#define VERBOSITY(level, args)					\
	do {							\
		if ((level) <= verbosity) {			\
			log_msg args ;				\
		}						\
	} while (0)

/*
 * Set the INDEXth bit of BITS to 1.
 */
void set_bit(uint8_t bits[], size_t index);

/*
 * Set the INDEXth bit of BITS to 0.
 */
void clear_bit(uint8_t bits[], size_t index);

/*
 * Return the value of the INDEXth bit of BITS.
 */
int get_bit(uint8_t bits[], size_t index);

/* A general purpose lookup table */
typedef struct lookup_table lookup_table_type;
struct lookup_table {
	int id;
	const char *name;
};

/*
 * Looks up the table entry by name, returns NULL if not found.
 */
lookup_table_type *lookup_by_name(lookup_table_type table[], const char *name);

/*
 * Looks up the table entry by id, returns NULL if not found.
 */
lookup_table_type *lookup_by_id(lookup_table_type table[], int id);

/*
 * (Re-)allocate SIZE bytes of memory.  Report an error if the memory
 * could not be allocated and exit the program.  These functions never
 * return NULL.
 */
void *xalloc(size_t size);
void *xmallocarray(size_t num, size_t size);
void *xalloc_zero(size_t size);
void *xalloc_array_zero(size_t num, size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *src);

/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
static inline uint16_t
read_uint16(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
  return ntohs(* (const uint16_t *) src);
#else
  const uint8_t *p = (const uint8_t *) src;
  return (p[0] << 8) | p[1];
#endif
}

/*
 * Converts a string representation of a period of time into
 * a long integer of seconds or serial value.
 *
 * Set the endptr to the first illegal character.
 *
 * Interface is similar as strtol(3)
 *
 * Returns:
 *	LONG_MIN if underflow occurs
 *	LONG_MAX if overflow occurs.
 *	otherwise number of seconds
 *
 * XXX These functions do not check the range.
 *
 */
uint32_t strtoserial(const char *nptr, const char **endptr);
uint32_t strtottl(const char *nptr, const char **endptr);

/*
 * Convert binary data to a string of hexadecimal characters.
 */
ssize_t hex_ntop(uint8_t const *src, size_t srclength, char *target,
		 size_t targsize);
ssize_t hex_pton(const char* src, uint8_t* target, size_t targsize);

/*
 * convert base32 data from and to string. Returns length.
 * -1 on error. Use (byte count*8)%5==0.
 */
int b32_pton(char const *src, uint8_t *target, size_t targsize);

/*
 * Strip trailing and leading whitespace from str.
 */
void strip_string(char *str);

/*
 * Convert a single (hexadecimal) digit to its integer value.
 */
int hexdigit_to_int(char ch);

/*
 * Convert TM to seconds since epoch (midnight, January 1st, 1970).
 * Like timegm(3), which is not always available.
 */
time_t mktime_from_utc(const struct tm *tm);

/*
 * Compares two 32-bit serial numbers as defined in RFC1982.  Returns
 * <0 if a < b, 0 if a == b, and >0 if a > b.  The result is undefined
 * if a != b but neither is greater or smaller (see RFC1982 section
 * 3.2.).
 */
int compare_serial(uint32_t a, uint32_t b);

/*
 * Generate a random query ID.
 */
uint16_t qid_generate(void);
/* value between 0 .. (max-1) inclusive */
int random_generate(int max);

/*
 * call region_destroy on (region*)data, useful for region_add_cleanup().
 */
void cleanup_region(void *data);

/** Something went wrong, give error messages and exit. */
void error(const char *format, ...); /// ATTR_FORMAT(printf, 1, 2) ATTR_NORETURN;
#endif /* UTIL_H */
