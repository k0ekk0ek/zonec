/*
 * zonec.c -- zone compiler.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

//#include "config.h"
#define _XOPEN_SOURCE       /* See feature_test_macros(7) */
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <arpa/inet.h>
#include <netinet/in.h>

#include <netdb.h>

#include "zonec.h"

#include "dname.h"
#include "dns.h"
//#include "namedb.h"
#include "rdata.h"
#include "region-allocator.h"
#include "util.h"
#include "zparser.h"
#include "b64_pton.h"

#define ILNP_MAXDIGITS 4
#define ILNP_NUMGROUPS 4
#define SVCB_MAX_COMMA_SEPARATED_VALUES 1000

extern uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];
extern uint16_t nsec_highest_rcode;

/*
 * These are parser function for generic zone file stuff.
 */
int32_t
zadd_rdata_hex(const char *hex, size_t len)
{
	/* convert a hex value to wireformat */
	uint8_t *t;
	int i;

	if(len == 1 && hex[0] == '0') {
		/* single 0 represents empty buffer */
    return 1;
	}
	if (len % 2 != 0) {
		zc_error_prev_line("number of hex digits must be a multiple of 2");
	} else if (len > parser_rdata_left(parser) * 2) {
		zc_error_prev_line("hex data exceeds maximum rdata length (%d)",
				   MAX_RDLENGTH);
	} else {
		/* the length part */
		t = (uint8_t *)parser_rdata(parser);

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				if (isxdigit((unsigned char)*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					zc_error_prev_line(
						"illegal hex character '%c'",
						(int) *hex);
					return 0;
				}
				++hex;
			}
			++t;
		}
    parser_rdata_advance(parser, len / 2);
	}
	return 1;
}

/* convert hex, precede by a 1-byte length */
int32_t
zadd_rdata_hex_length(const char *hex, size_t len)
{
	if (len % 2 != 0) {
		zc_error_prev_line("number of hex digits must be a multiple of 2");
	} else if (len > 255 * 2 || len > parser_rdata_left(parser) * 2) {
		zc_error_prev_line("hex data exceeds 255 bytes");
	} else {
		uint8_t *l, *t;

		t = parser_rdata(parser);

		l = t++;
		*l = '\0';

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (int i = 16; i >= 1; i -= 15) {
				if (isxdigit((unsigned char)*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					zc_error_prev_line(
						"illegal hex character '%c'",
						(int) *hex);
					return 0;
				}
				++hex;
			}
			++t;
			++*l;
		}
    parser_rdata_advance(parser, *l);
	}
	return 1;
}

int32_t
zadd_rdata_time(const char *time)
{
	/* convert a time YYHM to wireformat */
	struct tm tm;

	/* Try to scan the time... */
	if (!strptime(time, "%Y%m%d%H%M%S", &tm)) {
		zc_error_prev_line("date and time is expected");
    return 0;
	} else {
		uint32_t l = htonl(mktime_from_utc(&tm));
    memcpy(parser_rdata(parser), &l, sizeof(l));
    parser_rdata_advance(parser, sizeof(l));
	}
	return 1;
}

int32_t
zadd_rdata_services(const char *protostr, char *servicestr)
{
	/*
	 * Convert a protocol and a list of service port numbers
	 * (separated by spaces) in the rdata to wireformat
	 */
	//uint16_t *r = NULL;
  size_t s;
	uint8_t *p;
	uint8_t bitmap[65536/8];
	char sep[] = " ";
	char *word;
	int max_port = -8;
	/* convert a protocol in the rdata to wireformat */
	struct protoent *proto;

	memset(bitmap, 0, sizeof(bitmap));

	proto = getprotobyname(protostr);
	if (!proto) {
		proto = getprotobynumber(atoi(protostr));
	}
	if (!proto) {
		zc_error_prev_line("unknown protocol '%s'", protostr);
		return 0;
	}

	for (word = strtok(servicestr, sep); word; word = strtok(NULL, sep)) {
		struct servent *service;
		int port;

		service = getservbyname(word, proto->p_name);
		if (service) {
			/* Note: ntohs not ntohl!  Strange but true.  */
			port = ntohs((uint16_t) service->s_port);
		} else {
			char *end;
			port = strtol(word, &end, 10);
			if (*end != '\0') {
				zc_error_prev_line("unknown service '%s' for protocol '%s'",
						   word, protostr);
				continue;
			}
		}

		if (port < 0 || port > 65535) {
			zc_error_prev_line("bad port number %d", port);
		} else {
			set_bit(bitmap, port);
			if (port > max_port)
				max_port = port;
		}
	}

  s = sizeof(uint8_t) + max_port / 8 + 1;
	p = parser_rdata(parser);
	*p = proto->p_proto;
	memcpy(p + 1, bitmap, s);
  parser_rdata_advance(parser, s);
	return 1;
}

int32_t
zadd_rdata_serial(const char *serialstr)
{
	uint32_t serial;
	const char *t;

	serial = strtoserial(serialstr, &t);
	if (*t != '\0') {
		zc_error_prev_line("serial is expected or serial too big");
    return 0;
	} else {
    uint8_t *p;
		serial = htonl(serial);
    p = parser_rdata(parser);
    memcpy(p, &serial, sizeof(serial));
    parser_rdata_advance(parser, sizeof(serial));
	}
	return 1;
}

int32_t
zadd_rdata_period(const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */
	uint32_t period;
	const char *end;

	/* Allocate required space... */
	period = strtottl(periodstr, &end);
	if (*end != '\0') {
		zc_error_prev_line("time period is expected");
    return 0;
	} else {
    uint8_t *p;
		period = htonl(period);
    p = parser_rdata(parser);
    memcpy(p, &period, sizeof(period));
    parser_rdata_advance(parser, sizeof(period));
	}
	return 1;
}

int32_t
zadd_rdata_short(const char *text)
{
	uint16_t value;
	char *end;

	value = htons((uint16_t) strtol(text, &end, 10));
	if (*end != '\0') {
		zc_error_prev_line("integer value is expected");
    return 0;
	} else {
    uint8_t *p;
    p = parser_rdata(parser);
    memcpy(p, &value, sizeof(value));
    parser_rdata_advance(parser, sizeof(value));
	}
	return 1;
}

int32_t
zadd_rdata_byte(const char *text)
{
	uint8_t value;
	char *end;

	value = (uint8_t) strtol(text, &end, 10);
	if (*end != '\0') {
		zc_error_prev_line("integer value is expected");
    return 0;
	} else {
    uint8_t *p;
    p = parser_rdata(parser);
    memcpy(p, &value, sizeof(value));
    parser_rdata_advance(parser, sizeof(value));
	}
	return 1;
}

int32_t
zadd_rdata_algorithm(const char *text)
{
	const lookup_table_type *alg;
	uint8_t id;
  uint8_t *p;

	alg = lookup_by_name(dns_algorithms, text);
	if (alg) {
		id = (uint8_t) alg->id;
	} else {
		char *end;
		id = (uint8_t) strtol(text, &end, 10);
		if (*end != '\0') {
			zc_error_prev_line("algorithm is expected");
			return 0;
		}
	}

  p = parser_rdata(parser);
  memcpy(p, &id, sizeof(id));
  parser_rdata_advance(parser, sizeof(id));
  return 1;
}

int32_t
zadd_rdata_certificate_type(const char *text)
{
	/* convert an algorithm string to integer */
	const lookup_table_type *type;
	uint16_t id;
  uint8_t *p;

	type = lookup_by_name(dns_certificate_types, text);
	if (type) {
		id = htons((uint16_t) type->id);
	} else {
		char *end;
		id = htons((uint16_t) strtol(text, &end, 10));
		if (*end != '\0') {
			zc_error_prev_line("certificate type is expected");
			return 0;
		}
	}

  p = parser_rdata(parser);
  memcpy(p, &id, sizeof(id));
  parser_rdata_advance(parser, sizeof(id));
  return 1;
}

int32_t
zadd_rdata_a(const char *text)
{
	in_addr_t address;
	if (inet_pton(AF_INET, text, &address) != 1) {
		zc_error_prev_line("invalid IPv4 address '%s'", text);
    return 0;
	} else {
    uint8_t *p;
    p = parser_rdata(parser);
    memcpy(p, &address, sizeof(address));
    parser_rdata_advance(parser, sizeof(address));
	}
	return 1;
}

int32_t
zadd_rdata_aaaa(const char *text)
{
	uint8_t address[IP6ADDRLEN];

	if (inet_pton(AF_INET6, text, address) != 1) {
		zc_error_prev_line("invalid IPv6 address '%s'", text);
    return 0;
	} else {
    uint8_t *p;
    p = parser_rdata(parser);
    memcpy(p, address, sizeof(address));
    parser_rdata_advance(parser, sizeof(address));
	}
	return 1;
}


int32_t
zadd_rdata_ilnp64(const char *text)
{
	int ngroups, num;
	unsigned long hex;
	const char *ch;
	char digits[ILNP_MAXDIGITS+1];
	unsigned int ui[ILNP_NUMGROUPS];
	uint16_t a[ILNP_NUMGROUPS];
  uint8_t *p;

	ngroups = 1; /* Always at least one group */
	num = 0;
	for (ch = text; *ch != '\0'; ch++) {
		if (*ch == ':') {
			if (num <= 0) {
				zc_error_prev_line("ilnp64: empty group of "
					"digits is not allowed");
				return 0;
			}
			digits[num] = '\0';
			hex = (unsigned long) strtol(digits, NULL, 16);
			num = 0;
			ui[ngroups - 1] = hex;
			if (ngroups >= ILNP_NUMGROUPS) {
				zc_error_prev_line("ilnp64: more than %d groups "
					"of digits", ILNP_NUMGROUPS);
				return 0;
			}
			ngroups++;
		} else {
			/* Our grammar is stricter than the one accepted by
			 * strtol. */
			if (!isxdigit((unsigned char)*ch)) {
				zc_error_prev_line("ilnp64: invalid "
					"(non-hexadecimal) character %c", *ch);
				return 0;
			}
			if (num >= ILNP_MAXDIGITS) {
				zc_error_prev_line("ilnp64: more than %d digits "
					"in a group", ILNP_MAXDIGITS);
				return 0;
			}
			digits[num++] = *ch;
		}
	}
	if (num <= 0) {
		zc_error_prev_line("ilnp64: empty group of digits is not "
			"allowed");
		return 0;
	}
	digits[num] = '\0';
	hex = (unsigned long) strtol(digits, NULL, 16);
	ui[ngroups - 1] = hex;
	if (ngroups < 4) {
		zc_error_prev_line("ilnp64: less than %d groups of digits",
			ILNP_NUMGROUPS);
		return 0;
	}

	a[0] = htons(ui[0]);
	a[1] = htons(ui[1]);
	a[2] = htons(ui[2]);
	a[3] = htons(ui[3]);
  p = parser_rdata(parser);
  memcpy(p, a, sizeof(a));
  parser_rdata_advance(parser, sizeof(a));
	return 1;
}

static int32_t
zparser_conv_eui48(const char *text)
{
  uint8_t *p;
	uint8_t nums[6];
	unsigned int a, b, c, d, e, f;
	int l;

	if (sscanf(text, "%2x-%2x-%2x-%2x-%2x-%2x%n",
		&a, &b, &c, &d, &e, &f, &l) != 6 ||
		l != (int)strlen(text)){
		zc_error_prev_line("eui48: invalid rr");
		return 0;
	}
	nums[0] = (uint8_t)a;
	nums[1] = (uint8_t)b;
	nums[2] = (uint8_t)c;
	nums[3] = (uint8_t)d;
	nums[4] = (uint8_t)e;
	nums[5] = (uint8_t)f;
	p = parser_rdata(parser);
  memcpy(p, nums, sizeof(nums));
  parser_rdata_advance(parser, sizeof(nums));
	return 1;
}

static int32_t
zparser_conv_eui64(const char *text)
{
  uint8_t *p;
	uint8_t nums[8];
	unsigned int a, b, c, d, e, f, g, h;
	int l;
	if (sscanf(text, "%2x-%2x-%2x-%2x-%2x-%2x-%2x-%2x%n",
		&a, &b, &c, &d, &e, &f, &g, &h, &l) != 8 ||
		l != (int)strlen(text)) {
		zc_error_prev_line("eui64: invalid rr");
		return 0;
	}
	nums[0] = (uint8_t)a;
	nums[1] = (uint8_t)b;
	nums[2] = (uint8_t)c;
	nums[3] = (uint8_t)d;
	nums[4] = (uint8_t)e;
	nums[5] = (uint8_t)f;
	nums[6] = (uint8_t)g;
	nums[7] = (uint8_t)h;
  p = parser_rdata(parser);
  memcpy(p, nums, sizeof(nums));
  parser_rdata_advance(parser, sizeof(nums));
	return 1;
}

int32_t
zadd_rdata_eui(const char *text, size_t len)
{
	int nnum, num;
	const char* ch;

	nnum = len/8;
	num = 1;
	for (ch = text; *ch != '\0'; ch++) {
		if (*ch == '-') {
			num++;
		} else if (!isxdigit((unsigned char)*ch)) {
			zc_error_prev_line("eui%u: invalid (non-hexadecimal) "
				"character %c", (unsigned) len, *ch);
			return 0;
		}
	}
	if (num != nnum) {
		zc_error_prev_line("eui%u: wrong number of hex numbers",
			(unsigned) len);
		return 0;
	}

	switch (len) {
		case 48:
			return zparser_conv_eui48(text);
			break;
		case 64:
			return zparser_conv_eui64(text);
		break;
		default:
			zc_error_prev_line("eui%u: invalid length",
				(unsigned) len);
			return 0;
			break;
	}
	return 0;
}

int32_t
zadd_rdata_text(const char *text, size_t len)
{
	uint8_t *p;

	if (len > 255) {
		zc_error_prev_line("text string is longer than 255 characters,"
				   " try splitting it into multiple parts");
		len = 255;
	}
	p = parser_rdata(parser);
	*p = len;
	memcpy(p + 1, text, len);
  parser_rdata_advance(parser, len + 1);
	return 1;
}

/* for CAA Value [RFC 6844] */
int32_t
zadd_rdata_long_text(const char *text, size_t len)
{
	uint8_t *p;
	if (len > parser_rdata_left(parser)) {
		zc_error_prev_line("text string is longer than max rdlen");
		return 0;
	}
	p = parser_rdata(parser);
  memcpy(p, text, len);
  parser_rdata_advance(parser, len);
	return 1;
}

/* for CAA Tag [RFC 6844] */
int32_t
zadd_rdata_tag(const char *text, size_t len)
{
	uint8_t *p;
	const char* ptr;

	if (len < 1) {
		zc_error_prev_line("invalid tag: zero length");
		return 0;
	}
	if (len > 15) {
		zc_error_prev_line("invalid tag %s: longer than 15 characters (%u)",
			text, (unsigned) len);
		return 0;
	}
	for (ptr = text; *ptr; ptr++) {
		if (!isdigit((unsigned char)*ptr) && !islower((unsigned char)*ptr)) {
			zc_error_prev_line("invalid tag %s: contains invalid char %c",
				text, *ptr);
			return 0;
		}
	}
  p = parser_rdata(parser);
  *p = len;
  memmove(p + 1, text, len);
  return 1;
}

int32_t
zadd_rdata_dns_name(const uint8_t* name, size_t len)
{
	uint8_t* p = NULL;
	p = parser_rdata(parser);
	memcpy(p, name, len);
  parser_rdata_advance(parser, len);

	return 1;
}

int32_t
zadd_rdata_b32(const char *b32)
{
	uint8_t buffer[B64BUFSIZE];
  uint8_t *p;
	int i;

	if(strcmp(b32, "-") == 0) {
    p = parser_rdata(parser);
    *p = 0;
    parser_rdata_advance(parser, 1);
    return 1;
	}
	i = b32_pton(b32, buffer+1, B64BUFSIZE-1);
	if (i == -1 || i > 255) {
		zc_error_prev_line("invalid base32 data");
    return 0;
	} else {
		buffer[0] = i; /* store length byte */
    p = parser_rdata(parser);
    memcpy(p, buffer, i+1);
    parser_rdata_advance(parser, i+1);
	}
	return 1;
}

int32_t
zadd_rdata_b64(const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
  uint8_t *p;
	int i;

	if(strcmp(b64, "0") == 0) {
		/* single 0 represents empty buffer */
		return 1;
	}
	i = b64_pton(b64, buffer, B64BUFSIZE);
	if (i == -1) {
		zc_error_prev_line("invalid base64 data");
    return 0;
	} else {
		p = parser_rdata(parser);
    memcpy(p, buffer, i);
    parser_rdata_advance(parser, i);
	}
	return 1;
}

int32_t
zadd_rdata_rrtype(const char *text)
{
	uint8_t *p;
	uint16_t type = rrtype_from_string(text);

	if (type == 0) {
		zc_error_prev_line("unrecognized RR type '%s'", text);
    return 0;
	} else {
		type = htons(type);
    p = parser_rdata(parser);
    memcpy(p, &type, sizeof(type));
    parser_rdata_advance(parser, sizeof(type));
	}
	return 1;
}

int32_t
zadd_rdata_nxt(uint8_t nxtbits[])
{
	/* nxtbits[] consists of 16 bytes with some zero's in it
	 * copy every byte with zero to r and write the length in
	 * the first byte
	 */
	uint16_t i;
	uint16_t last = 0;
  uint8_t *p;

	for (i = 0; i < 16; i++) {
		if (nxtbits[i] != 0)
			last = i + 1;
	}

  p = parser_rdata(parser);
  memcpy(p, nxtbits, last);
  parser_rdata_advance(parser, last);
  return 1;
}


/* we potentially have 256 windows, each one is numbered. empty ones
 * should be discarded
 */
int32_t
zadd_rdata_nsec(
		  uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE])
{
	/* nsecbits contains up to 64K of bits which represent the
	 * types available for a name. Walk the bits according to
	 * nsec++ draft from jakob
	 */
	uint16_t *r;
	uint8_t *ptr;
	size_t i,j;
	uint16_t window_count = 0;
	uint16_t total_size = 0;
	uint16_t window_max = 0;

	/* The used windows.  */
	int used[NSEC_WINDOW_COUNT];
	/* The last byte used in each the window.  */
	int size[NSEC_WINDOW_COUNT];

	window_max = 1 + (nsec_highest_rcode / 256);

	/* used[i] is the i-th window included in the nsec
	 * size[used[0]] is the size of window 0
	 */

	/* walk through the 256 windows */
	for (i = 0; i < window_max; ++i) {
		int empty_window = 1;
		/* check each of the 32 bytes */
		for (j = 0; j < NSEC_WINDOW_BITS_SIZE; ++j) {
			if (nsecbits[i][j] != 0) {
				size[i] = j + 1;
				empty_window = 0;
			}
		}
		if (!empty_window) {
			used[window_count] = i;
			window_count++;
		}
	}

	for (i = 0; i < window_count; ++i) {
		total_size += sizeof(uint16_t) + size[used[i]];
	}

  ptr = parser_rdata(parser);

	/* now walk used and copy it */
	for (i = 0; i < window_count; ++i) {
		ptr[0] = used[i];
		ptr[1] = size[used[i]];
		memcpy(ptr + 2, &nsecbits[used[i]], size[used[i]]);
		ptr += size[used[i]] + 2;
	}
  parser_rdata_advance(parser, total_size);

	return 1;
}

static uint16_t
svcbparam_lookup_key(const char *key, size_t key_len)
{
	char buf[64];
	char *endptr;
	unsigned long int key_value;

	if (key_len >= 4  && key_len <= 8 && !strncmp(key, "key", 3)) {
		memcpy(buf, key + 3, key_len - 3);
		buf[key_len - 3] = 0;
		key_value = strtoul(buf, &endptr, 10);
		if (endptr > buf	/* digits seen */
		&& *endptr == 0		/* no non-digit chars after digits */
		&&  key_value <= 65535)	/* no overflow */
			return key_value;

	} else switch (key_len) {
	case sizeof("mandatory")-1:
		if (!strncmp(key, "mandatory", sizeof("mandatory")-1))
			return SVCB_KEY_MANDATORY;
		if (!strncmp(key, "echconfig", sizeof("echconfig")-1))
			return SVCB_KEY_ECH; /* allow "echconfig" as well as "ech" */
		break;

	case sizeof("alpn")-1:
		if (!strncmp(key, "alpn", sizeof("alpn")-1))
			return SVCB_KEY_ALPN;
		if (!strncmp(key, "port", sizeof("port")-1))
			return SVCB_KEY_PORT;
		break;

	case sizeof("no-default-alpn")-1:
		if (!strncmp( key  , "no-default-alpn"
		            , sizeof("no-default-alpn")-1))
			return SVCB_KEY_NO_DEFAULT_ALPN;
		break;

	case sizeof("ipv4hint")-1:
		if (!strncmp(key, "ipv4hint", sizeof("ipv4hint")-1))
			return SVCB_KEY_IPV4HINT;
		if (!strncmp(key, "ipv6hint", sizeof("ipv6hint")-1))
			return SVCB_KEY_IPV6HINT;
		break;
	case sizeof("dohpath")-1:
		if (!strncmp(key, "dohpath", sizeof("dohpath")-1))
			return SVCB_KEY_DOHPATH;
		break;
	case sizeof("ech")-1:
		if (!strncmp(key, "ech", sizeof("ech")-1))
			return SVCB_KEY_ECH;
		break;
	default:
		break;
	}
	if (key_len > sizeof(buf) - 1)
		zc_error_prev_line("Unknown SvcParamKey");
	else {
		memcpy(buf, key, key_len);
		buf[key_len] = 0;
		zc_error_prev_line("Unknown SvcParamKey: %s", buf);
	}
	/* Although the returned value might be used by the caller,
	 * the parser has erred, so the zone will not be loaded.
	 */
	return -1;
}

static int32_t
zadd_rdata_svcbparam_port_value(const char *val)
{
	unsigned long int port;
	char *endptr;
  uint16_t *p;

	port = strtoul(val, &endptr, 10);
	if (endptr > val	/* digits seen */
	&& *endptr == 0		/* no non-digit chars after digits */
	&&  port <= 65535) {	/* no overflow */

		p = (uint16_t *)parser_rdata(parser);
		p[1] = htons(SVCB_KEY_PORT);
		p[2] = htons(sizeof(uint16_t));
		p[3] = htons(port);
    parser_rdata_advance(parser, 3 * sizeof(uint16_t));
		return 1;
	}
	zc_error_prev_line("Could not parse port SvcParamValue: \"%s\"", val);
	return 0;
}

static int32_t
zadd_rdata_svcbparam_ipv4hint_value(const char *val)
{
	uint16_t *p;
	int count;
	char ip_str[INET_ADDRSTRLEN+1];
	char *next_ip_str;
	uint32_t *ip_wire_dst;
	size_t i, total_size;

	for (i = 0, count = 1; val[i]; i++) {
		if (val[i] == ',')
			count += 1;
		if (count > SVCB_MAX_COMMA_SEPARATED_VALUES) {
			zc_error_prev_line("Too many IPV4 addresses in ipv4hint");
			return 0;
		}
	}

	/* count == number of comma's in val + 1, so the actual number of IPv4
	 * addresses in val
	 */
  p = (uint16_t *)parser_rdata(parser);
	p[0] = htons(SVCB_KEY_IPV4HINT);
	p[1] = htons(IP4ADDRLEN * count);
	ip_wire_dst = (void *)&p[2];
  total_size = (count * sizeof(*ip_wire_dst)) + 2 * sizeof(*p);

	while (count) {
		if (!(next_ip_str = strchr(val, ','))) {
			if (inet_pton(AF_INET, val, ip_wire_dst) != 1)
				break;

			assert(count == 1);

		} else if (next_ip_str - val >= (int)sizeof(ip_str))
			break;

		else {
			memcpy(ip_str, val, next_ip_str - val);
			ip_str[next_ip_str - val] = 0;
			if (inet_pton(AF_INET, ip_str, ip_wire_dst) != 1) {
				val = ip_str; /* to use in error reporting below */
				break;
			}

			val = next_ip_str + 1;
		}
		ip_wire_dst++;
		count--;
	}
	if (count) {
		zc_error_prev_line("Could not parse ipv4hint SvcParamValue: %s", val);
    return 0;
  }

  parser_rdata_advance(parser, total_size);
	return 1;
}

static int32_t
zadd_rdata_svcbparam_ipv6hint_value(const char *val)
{
	uint16_t *p;
	int i, count;
	char ip6_str[INET6_ADDRSTRLEN+1];
	char *next_ip6_str;
	uint8_t *ipv6_wire_dst;

	for (i = 0, count = 1; val[i]; i++) {
		if (val[i] == ',')
			count += 1;
		if (count > SVCB_MAX_COMMA_SEPARATED_VALUES) {
			zc_error_prev_line("Too many IPV6 addresses in ipv6hint");
			return 0;
		}
	}

	/* count == number of comma's in val + 1 
	 * so actually the number of IPv6 addresses in val
	 */
  p = (int16_t *)parser_rdata(parser);
	p[0] = htons(SVCB_KEY_IPV6HINT);
	p[1] = htons(IP6ADDRLEN * count);
	ipv6_wire_dst = (void *)&p[2];
  size_t total_size = (count * 16 * sizeof(uint8_t)) + 2 * sizeof(*p);

	while (count) {
		if (!(next_ip6_str = strchr(val, ','))) {
			if ((inet_pton(AF_INET6, val, ipv6_wire_dst) != 1))
				break;

			assert(count == 1);

		} else if (next_ip6_str - val >= (int)sizeof(ip6_str))
			break;

		else {
			memcpy(ip6_str, val, next_ip6_str - val);
			ip6_str[next_ip6_str - val] = 0;
			if (inet_pton(AF_INET6, ip6_str, ipv6_wire_dst) != 1) {
				val = ip6_str; /* for error reporting below */
				break;
			}

			val = next_ip6_str + 1; /* skip the comma */
		}
		ipv6_wire_dst += IP6ADDRLEN;
		count--;
	}
	if (count) {
		zc_error_prev_line("Could not parse ipv6hint SvcParamValue: %s", val);
    return 0;
  }

  parser_rdata_advance(parser, total_size);
	return 1;
}

static int
network_uint16_cmp(const void *a, const void *b)
{
	return ((int)read_uint16(a)) - ((int)read_uint16(b));
}

static int32_t
zadd_rdata_svcbparam_mandatory_value(
		const char *val, size_t val_len)
{
	uint16_t *p;
	size_t i, count;
	char* next_key;
	uint16_t* key_dst;

	for (i = 0, count = 1; val[i]; i++) {
		if (val[i] == ',')
			count += 1;
		if (count > SVCB_MAX_COMMA_SEPARATED_VALUES) {
			zc_error_prev_line("Too many keys in mandatory");
			return 0;
		}
	}

	p = (uint16_t*)parser_rdata(parser); 
	p[0] = htons(SVCB_KEY_MANDATORY);
	p[1] = htons(sizeof(uint16_t) * count);
	key_dst = (void *)&p[2];

	for(;;) {
		if (!(next_key = strchr(val, ','))) {
			*key_dst = htons(svcbparam_lookup_key(val, val_len));
			break;	
		} else {
			*key_dst = htons(svcbparam_lookup_key(val, next_key - val));
		}

		val_len -= next_key - val + 1;
		val = next_key + 1; /* skip the comma */
		key_dst += 1;
	}

	/* In draft-ietf-dnsop-svcb-https-04 Section 7:
	 *
	 *     In wire format, the keys are represented by their numeric
	 *     values in network byte order, concatenated in ascending order.
	 */
	qsort((void *)&p[2], count, sizeof(uint16_t), network_uint16_cmp);
  parser_rdata_advance(parser, (count + 2) * sizeof(uint16_t));

	return 1;
}

static int32_t
zadd_rdata_svcbparam_ech_value(const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *p;
	int wire_len;

	if(strcmp(b64, "0") == 0) {
		/* single 0 represents empty buffer */
    return 1;
	}
	wire_len = b64_pton(b64, buffer, B64BUFSIZE);
	if (wire_len == -1) {
		zc_error_prev_line("invalid base64 data in ech");
    return 0;
	} else {
		p = (uint16_t*)parser_rdata(parser);
		p[0] = htons(SVCB_KEY_ECH);
		p[1] = htons(wire_len);
		memcpy(&p[1], buffer, wire_len);
    parser_rdata_advance(parser, 2 * sizeof(uint16_t) + wire_len);
	}

	return 1;
}

static const char* parse_alpn_next_unescaped_comma(const char *val)
{
	while (*val) {
		/* Only return when the comma is not escaped*/
		if (*val == '\\'){
			++val;
			if (!*val)
				break;
		} else if (*val == ',')
				return val;

		val++;
	}
	return NULL;
}

static size_t
parse_alpn_copy_unescaped(uint8_t *dst, const char *src, size_t len)
{
	uint8_t *orig_dst = dst;

	while (len) {
		if (*src == '\\') {
			src++;
			len--;
			if (!len)
				break;
		}
		*dst++ = *src++;
		len--;
	}
	return (size_t)(dst - orig_dst);
}

static int32_t
zadd_rdata_svcbparam_alpn_value(
		const char *val, size_t val_len)
{
	uint8_t     unescaped_dst[65536];
	uint8_t    *dst = unescaped_dst;
	const char *next_str;
	size_t      str_len;
	size_t      dst_len;
	uint16_t   *p;

	if (val_len > sizeof(unescaped_dst)) {
		zc_error_prev_line("invalid alpn");
		return 0;
	}
	while (val_len) {
		size_t dst_len;

		str_len = (next_str = parse_alpn_next_unescaped_comma(val))
		        ? (size_t)(next_str - val) : val_len;

		if (str_len > 255) {
			zc_error_prev_line("alpn strings need to be"
					   " smaller than 255 chars");
			return 0;
		}
		dst_len = parse_alpn_copy_unescaped(dst + 1, val, str_len);
		*dst++ = dst_len;
		 dst  += dst_len;

		if (!next_str)
			break;

		/* skip the comma for the next iteration */
		val_len -= next_str - val + 1;
		val = next_str + 1;
	}
	dst_len = dst - unescaped_dst;
  p = (uint16_t*)parser_rdata(parser);
	p[0] = htons(SVCB_KEY_ALPN);
	p[1] = htons(dst_len);
	memcpy(&p[2], unescaped_dst, dst_len);
  parser_rdata_advance(parser, 2 * sizeof(uint16_t) + dst_len);
	return 1;
}

static int32_t
zadd_rdata_svcbparam_key_value(
    const char *key, size_t key_len, const char *val, size_t val_len)
{
	uint16_t svcparamkey = svcbparam_lookup_key(key, key_len);
	uint16_t *p;

	switch (svcparamkey) {
	case SVCB_KEY_PORT:
		return zadd_rdata_svcbparam_port_value(val);
	case SVCB_KEY_IPV4HINT:
		return zadd_rdata_svcbparam_ipv4hint_value(val);
	case SVCB_KEY_IPV6HINT:
		return zadd_rdata_svcbparam_ipv6hint_value(val);
	case SVCB_KEY_MANDATORY:
		return zadd_rdata_svcbparam_mandatory_value(val, val_len);
	case SVCB_KEY_NO_DEFAULT_ALPN:
//		if(zone_is_slave(parser->current_zone->opts))
//			zc_warning_prev_line("no-default-alpn should not have a value");
//		else
			zc_error_prev_line("no-default-alpn should not have a value");
		break;
	case SVCB_KEY_ECH:
		return zadd_rdata_svcbparam_ech_value(val);
	case SVCB_KEY_ALPN:
		return zadd_rdata_svcbparam_alpn_value(val, val_len);
	case SVCB_KEY_DOHPATH:
		/* fallthrough */
	default:
		break;
	}
	p = (uint16_t*)parser_rdata(parser);
	p[0] = htons(svcparamkey);
	p[1] = htons(val_len);
	memcpy(p+2, val, val_len);
  parser_rdata_advance(parser, 2 * sizeof(uint16_t) + val_len);
	return 1;
}

int32_t
zadd_rdata_svcbparam(const char *key, size_t key_len
                                          , const char *val, size_t val_len)
{
	const char *eq;
	uint16_t *p;
	uint16_t svcparamkey;

	/* Form <key>="<value>" (or at least with quoted value) */
	if (val && val_len) {
		/* Does key end with '=' */
		if (key_len && key[key_len - 1] == '=')
			return zadd_rdata_svcbparam_key_value(
			    key, key_len - 1, val, val_len);

		zc_error_prev_line( "SvcParam syntax error in param: %s\"%s\""
		                  , key, val);
	}
	assert(val == NULL);
	if ((eq = memchr(key, '=', key_len))) {
		size_t new_key_len = eq - key;

		if (key_len - new_key_len - 1 > 0)
			return zadd_rdata_svcbparam_key_value(
			    key, new_key_len, eq+1, key_len - new_key_len - 1);
		key_len = new_key_len;
	}
	/* Some SvcParamKeys require values */
	svcparamkey = svcbparam_lookup_key(key, key_len);
	switch (svcparamkey) {
		case SVCB_KEY_MANDATORY:
		case SVCB_KEY_ALPN:
		case SVCB_KEY_PORT:
		case SVCB_KEY_IPV4HINT:
		case SVCB_KEY_IPV6HINT:
		case SVCB_KEY_DOHPATH:
//			if(zone_is_slave(parser->current_zone->opts))
//				zc_warning_prev_line("value expected for SvcParam: %s", key);
//			else
				zc_error_prev_line("value expected for SvcParam: %s", key);
			break;
		default:
			break;
	}
	/* SvcParam is only a SvcParamKey */
	p = (uint16_t*)parser_rdata(parser);
	p[0] = htons(svcparamkey);
	p[1] = 0;
  parser_rdata_advance(parser, 2 * sizeof(uint16_t));
	return 1;
}

/* Parse an int terminated in the specified range. */
static int
parse_int(const char *str,
	  char **end,
	  int *result,
	  const char *name,
	  int min,
	  int max)
{
	*result = (int) strtol(str, end, 10);
	if (*result < min || *result > max) {
		zc_error_prev_line("%s must be within the range [%d .. %d]",
				   name,
				   min,
				   max);
		return 0;
	} else {
		return 1;
	}
}

/* RFC1876 conversion routines */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				1000000,10000000,100000000,1000000000};

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
static uint8_t
precsize_aton (char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	int exponent;
	int mantissa;

	while (isdigit((unsigned char)*cp))
		mval = mval * 10 + hexdigit_to_int(*cp++);

	if (*cp == '.') {	/* centimeters */
		cp++;
		if (isdigit((unsigned char)*cp)) {
			cmval = hexdigit_to_int(*cp++) * 10;
			if (isdigit((unsigned char)*cp)) {
				cmval += hexdigit_to_int(*cp++);
			}
		}
	}

	if(mval >= poweroften[7]) {
		assert(poweroften[7] != 0);
		/* integer overflow possible for *100 */
		mantissa = mval / poweroften[7];
		exponent = 9; /* max */
	}
	else {
		cmval = (mval * 100) + cmval;

		for (exponent = 0; exponent < 9; exponent++)
			if (cmval < poweroften[exponent+1])
				break;

		assert(poweroften[exponent] != 0);
		mantissa = cmval / poweroften[exponent];
	}
	if (mantissa > 9)
		mantissa = 9;

	retval = (mantissa << 4) | exponent;

	if (*cp == 'm') cp++;

	*endptr = cp;

	return (retval);
}

/*
 * Parses a specific part of rdata.
 *
 * Returns:
 *
 *	number of elements parsed
 *	zero on error
 *
 */
int32_t
zadd_rdata_loc(char *str)
{
	uint16_t *r;
	uint32_t *p;
	int i;
	int deg, min, secs;	/* Secs is stored times 1000.  */
	uint32_t lat = 0, lon = 0, alt = 0;
	/* encoded defaults: version=0 sz=1m hp=10000m vp=10m */
	uint8_t vszhpvp[4] = {0, 0x12, 0x16, 0x13};
	char *start;
	double d;

	for(;;) {
		deg = min = secs = 0;

		/* Degrees */
		if (*str == '\0') {
			zc_error_prev_line("unexpected end of LOC data");
			return 0;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180))
			return 0;
		if (!isspace((unsigned char)*str)) {
			zc_error_prev_line("space expected after degrees");
			return 0;
		}
		++str;

		/* Minutes? */
		if (isdigit((unsigned char)*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60))
				return 0;
			if (!isspace((unsigned char)*str)) {
				zc_error_prev_line("space expected after minutes");
				return 0;
			}
			++str;
		}

		/* Seconds? */
		if (isdigit((unsigned char)*str)) {
			start = str;
			if (!parse_int(str, &str, &i, "seconds", 0, 60)) {
				return 0;
			}

			if (*str == '.' && !parse_int(str + 1, &str, &i, "seconds fraction", 0, 999)) {
				return 0;
			}

			if (!isspace((unsigned char)*str)) {
				zc_error_prev_line("space expected after seconds");
				return 0;
			}
			/* No need for precision specifiers, it's a double */
			if (sscanf(start, "%lf", &d) != 1) {
				zc_error_prev_line("error parsing seconds");
			}

			if (d < 0.0 || d > 60.0) {
				zc_error_prev_line("seconds not in range 0.0 .. 60.0");
			}

			secs = (int) (d * 1000.0 + 0.5);
			++str;
		}

		switch(*str) {
		case 'N':
		case 'n':
			lat = ((uint32_t)1<<31) + (deg * 3600000 + min * 60000 + secs);
			break;
		case 'E':
		case 'e':
			lon = ((uint32_t)1<<31) + (deg * 3600000 + min * 60000 + secs);
			break;
		case 'S':
		case 's':
			lat = ((uint32_t)1<<31) - (deg * 3600000 + min * 60000 + secs);
			break;
		case 'W':
		case 'w':
			lon = ((uint32_t)1<<31) - (deg * 3600000 + min * 60000 + secs);
			break;
		default:
			zc_error_prev_line("invalid latitude/longtitude: '%c'", *str);
			return 0;
		}
		++str;

		if (lat != 0 && lon != 0)
			break;

		if (!isspace((unsigned char)*str)) {
			zc_error_prev_line("space expected after latitude/longitude");
			return 0;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		zc_error_prev_line("unexpected end of LOC data");
		return 0;
	}

	if (!isspace((unsigned char)*str)) {
		zc_error_prev_line("space expected before altitude");
		return 0;
	}
	++str;

	start = str;

	/* Sign */
	if (*str == '+' || *str == '-') {
		++str;
	}

	/* Meters of altitude... */
	if(strtol(str, &str, 10) == LONG_MAX) {
		zc_error_prev_line("altitude too large, number overflow");
		return 0;
	}
	switch(*str) {
	case ' ':
	case '\0':
	case 'm':
		break;
	case '.':
		if (!parse_int(str + 1, &str, &i, "altitude fraction", 0, 99)) {
			return 0;
		}
		if (!isspace((unsigned char)*str) && *str != '\0' && *str != 'm') {
			zc_error_prev_line("altitude fraction must be a number");
			return 0;
		}
		break;
	default:
		zc_error_prev_line("altitude must be expressed in meters");
		return 0;
	}
	if (!isspace((unsigned char)*str) && *str != '\0')
		++str;

	if (sscanf(start, "%lf", &d) != 1) {
		zc_error_prev_line("error parsing altitude");
    return 0;
	}

	alt = (uint32_t) (10000000.0 + d * 100 + 0.5);

	if (!isspace((unsigned char)*str) && *str != '\0') {
		zc_error_prev_line("unexpected character after altitude");
		return 0;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for(i = 1; isspace((unsigned char)*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace((unsigned char)*str) && *str != '\0') {
			zc_error_prev_line("invalid size or precision");
			return 0;
		}
	}

	/* Allocate required space... */
	p = (uint32_t *)parser_rdata(parser);

	memmove(p, vszhpvp, 4);
  memcpy(p+1, &lat, sizeof(lat));
  memcpy(p+2, &lon, sizeof(lon));
  memcpy(p+3, &alt, sizeof(alt));
  parser_rdata_advance(parser, 4 * sizeof(uint32_t));

	return 1;
}

/*
 * Convert an APL RR RDATA element.
 */
int32_t
zadd_rdata_apl_rdata(char *str)
{
	int negated = 0;
	uint16_t address_family;
	uint8_t prefix;
	uint8_t maximum_prefix;
	uint8_t length;
	uint8_t address[IP6ADDRLEN];
	char *colon = strchr(str, ':');
	char *slash = strchr(str, '/');
	int af;
	int rc;
	uint16_t rdlength;
	uint8_t *t;
	char *end;
	long p;

	if (!colon) {
		zc_error("address family separator is missing");
		return 0;
	}
	if (!slash) {
		zc_error("prefix separator is missing");
		return 0;
	}

	*colon = '\0';
	*slash = '\0';

	if (*str == '!') {
		negated = 1;
		++str;
	}

	if (strcmp(str, "1") == 0) {
		address_family = htons(1);
		af = AF_INET;
		length = sizeof(in_addr_t);
		maximum_prefix = length * 8;
	} else if (strcmp(str, "2") == 0) {
		address_family = htons(2);
		af = AF_INET6;
		length = IP6ADDRLEN;
		maximum_prefix = length * 8;
	} else {
		zc_error("invalid address family '%s'", str);
		return 0;
	}

	rc = inet_pton(af, colon + 1, address);
	if (rc == 0) {
		zc_error("invalid address '%s'", colon + 1);
		return 0;
	} else if (rc == -1) {
		zc_error("inet_pton failed: %s", strerror(errno));
		return 0;
	}

	/* Strip trailing zero octets.	*/
	while (length > 0 && address[length - 1] == 0)
		--length;


	p = strtol(slash + 1, &end, 10);
	if (p < 0 || p > maximum_prefix) {
		zc_error("prefix not in the range 0 .. %d", maximum_prefix);
		return 0;
	} else if (*end != '\0') {
		zc_error("invalid prefix '%s'", slash + 1);
		return 0;
	}
	prefix = (uint8_t) p;

	rdlength = (sizeof(address_family) + sizeof(prefix) + sizeof(length)
		    + length);
	t = parser_rdata(parser);

	memcpy(t, &address_family, sizeof(address_family));
	t += sizeof(address_family);
	memcpy(t, &prefix, sizeof(prefix));
	t += sizeof(prefix);
	memcpy(t, &length, sizeof(length));
	if (negated) {
		*t |= APL_NEGATION_MASK;
	}
	t += sizeof(length);
	memcpy(t, address, length);
  parser_rdata_advance(parser, rdlength);

	return 1;
}

/*
 * Below some function that also convert but not to wireformat
 * but to "normal" (int,long,char) types
 */

uint32_t
zparser_ttl2int(const char *ttlstr, int* error)
{
	/* convert a ttl value to a integer
	 * return the ttl in a int
	 * -1 on error
	 */

	uint32_t ttl;
	const char *t;

	ttl = strtottl(ttlstr, &t);
	if (*t != 0) {
		zc_error_prev_line("invalid TTL value: %s",ttlstr);
		*error = 1;
	}

	return ttl;
}

void
zadd_rdata_domain(const struct dname *dname)
{
  uint8_t *p = parser_rdata(parser);
  memcpy(p, dname_name(dname), dname->name_size);
  parser_rdata_advance(parser, dname->name_size);
}

/*
 *
 * Opens a zone file.
 *
 * Returns:
 *
 *	- pointer to the parser structure
 *	- NULL on error and errno set
 *
 */
static int
zone_open(const char *filename, uint32_t ttl, uint16_t klass,
	  const dname_type *origin)
{
	/* Open the zone file... */
	if (strcmp(filename, "-") == 0) {
		yyin = stdin;
		filename = "<stdin>";
//		warn_if_directory("zonefile from stdin", yyin, filename);
	} else {
		if (!(yyin = fopen(filename, "r"))) {
			return 0;
		}
//		warn_if_directory("zonefile", yyin, filename);
	}

	zparser_init(filename, ttl, klass, origin);

	return 1;
}

void
set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
	    uint16_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	uint8_t window = index / 256;
	uint8_t bit = index % 256;

	bits[window][bit / 8] |= (1 << (7 - bit % 8));
}

int
process_rr(void)
{
	if (parser->current_rr.owner == NULL) {
		zc_error_prev_line("invalid owner name");
		return 0;
	}

  if (parser->callback(parser->current_rr.owner,
                       parser->current_rr.type,
                       parser->current_rr.klass,
                       parser->current_rr.ttl,
                       parser->current_rr.rdata.length,
                       parser->current_rr.rdata.octets,
                       parser->user_data) == 0)
  {
    parser->current_rr.rdata.length = 0;
    return 1;
  }
  parser->current_rr.rdata.length = 0;
  return 0;
}

/*
 * Reads the specified zone into the memory
 * nsd_options can be NULL if no config file is passed.
 */
unsigned int
zonec_read(const char* name, const char* zonefile)
{
  assert(parser);
	const dname_type *dname;

	//totalrrs = 0;
	//startzonec = time(NULL);
	parser->errors = 0;

	dname = dname_parse(parser->rr_region, name);
	if (!dname) {
		zc_error("incorrect zone name '%s'", name);
		return 1;
	}

	/* Open the zone file */
	if (!zone_open(zonefile, 3600, CLASS_IN, dname)) {
		zc_error("cannot open '%s': %s", zonefile, strerror(errno));
		return 1;
	}

	/* Parse and process all RRs.  */
	yyparse();

	region_free_all(parser->rr_region);

	parser_flush();
	fclose(yyin);

	parser->filename = NULL;
	return parser->errors;
}

/*
 * setup parse
 */
void
zonec_setup_parser(void)
{
	parser = zparser_create();
	assert(parser);
	/* Open the network database */
	setprotoent(1);
	setservent(1);
}

/** desetup parse */
void
zonec_desetup_parser(void)
{
	if(parser) {
		endservent();
		endprotoent();
    region_destroy(parser->region);
		region_destroy(parser->rr_region);
    free(parser);
		/* removed when parser->region(=db->region) is destroyed:
		 * region_recycle(parser->region, (void*)error_dname, 1);
		 * region_recycle(parser->region, (void*)error_domain, 1); */
		/* clear memory for exit, but this is not portable to
		 * other versions of lex. yylex_destroy(); */
		yylex_destroy();
	}
}
