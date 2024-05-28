/*
 * zonec.h -- zone compiler.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef ZONEC_H
#define ZONEC_H

#include "dname.h"
#include "region-allocator.h"

#define	MAXTOKENSLEN	512		/* Maximum number of tokens per entry */
#define	B64BUFSIZE	65535		/* Buffer size for b64 conversion */
#define	ROOT		(const uint8_t *)"\001"

#define NSEC_WINDOW_COUNT     256
#define NSEC_WINDOW_BITS_COUNT 256
#define NSEC_WINDOW_BITS_SIZE  (NSEC_WINDOW_BITS_COUNT / 8)

#define IPSECKEY_NOGATEWAY      0       /* RFC 4025 */
#define IPSECKEY_IP4            1
#define IPSECKEY_IP6            2
#define IPSECKEY_DNAME          3

#define LINEBUFSZ 1024

struct lex_data {
    size_t   len;		/* holds the label length */
    char    *str;		/* holds the data */
};

#define DEFAULT_TTL 3600

// we need somewhere to store rdata
// we need something to represent the owner

typedef int32_t(*zonec_callback)(
  struct dname *, uint16_t, uint16_t, uint32_t, uint16_t, uint8_t *, void *);

/* administration struct */
struct zparser {
  region_type *region;
	region_type *rr_region;	/* Allocate RR lifetime data.  */

	const char *filename;
	uint32_t default_ttl;
	uint16_t default_class;
  struct dname *origin;

	int error_occurred;
	unsigned int errors;
	unsigned int line;

  struct {
    struct dname *owner;
    uint16_t type;
    uint16_t klass;
    uint32_t ttl;
    struct {
      uint16_t length;
      uint8_t octets[65535];
    } rdata;
  } current_rr;
  void *user_data;
  zonec_callback callback;
};

extern struct zparser *parser;

/* used in zonec.lex */
extern FILE *yyin;

/*
 * Used to mark bad domains and domain names.  Do not dereference
 * these pointers!
 */
extern const dname_type *error_dname;
//extern domain_type *error_domain;

int yyparse(void);
int yylex(void);
int yylex_destroy(void);
/*int yyerror(const char *s);*/
void yyrestart(FILE *);

void zc_warning(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)));
void zc_warning_prev_line(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)));
void zc_error(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)));
void zc_error_prev_line(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)));

void parser_push_stringbuf(char* str);
void parser_pop_stringbuf(void);
void parser_flush(void);

int process_rr(void);
int32_t zadd_rdata_hex(const char *hex, size_t len);
int32_t zadd_rdata_hex_length(const char *hex, size_t len);
int32_t zadd_rdata_time(const char *time);
int32_t zadd_rdata_services(const char *protostr, char *servicestr);
int32_t zadd_rdata_serial(const char *periodstr);
int32_t zadd_rdata_period(const char *periodstr);
int32_t zadd_rdata_short(const char *text);
int32_t zadd_rdata_long(const char *text);
int32_t zadd_rdata_byte(const char *text);
int32_t zadd_rdata_a(const char *text);
int32_t zadd_rdata_aaaa(const char *text);
int32_t zadd_rdata_ilnp64(const char *text);
int32_t zadd_rdata_eui(const char *text, size_t len);
int32_t zadd_rdata_text(const char *text, size_t len);
int32_t zadd_rdata_long_text(const char *text, size_t len);
int32_t zadd_rdata_tag(const char *text, size_t len);
int32_t zadd_rdata_dns_name(const uint8_t* name, size_t len);
int32_t zadd_rdata_b32(const char *b32);
int32_t zadd_rdata_b64(const char *b64);
int32_t zadd_rdata_rrtype(const char *rr);
int32_t zadd_rdata_nxt(uint8_t nxtbits[]);
int32_t zadd_rdata_nsec(uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE]);
int32_t zadd_rdata_loc(char *str);
int32_t zadd_rdata_algorithm(const char *algstr);
int32_t zadd_rdata_certificate_type(const char *typestr);
int32_t zadd_rdata_apl_rdata(char *str);
int32_t zadd_rdata_svcbparam(
	const char *key, size_t key_len, const char *value, size_t value_len);

uint32_t zparser_ttl2int(const char *ttlstr, int* error);
//void zadd_rdata_wireformat(uint16_t *data);
//void zadd_rdata_txt_wireformat(uint16_t *data, int first);
//void zadd_rdata_txt_clean_wireformat(void);
//void zadd_rdata_svcb_check_wireformat(void);
void zadd_rdata_domain(const struct dname *dname);

void set_bitnsec(uint8_t  bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
		 uint16_t index);

/* zparser.y */
struct zparser *zparser_create(void);
void zparser_init(const char *filename, uint32_t ttl, uint16_t klass,
		  const dname_type *origin);

/* parser start and stop to parse a zone */
void zonec_setup_parser(void);
void zonec_desetup_parser(void);
/* parse a zone into memory. name is origin. zonefile is file to read.
 * returns number of errors; failure may have read a partial zone */
unsigned int zonec_read(const char *name, const char *zonefile);
/* parse a string into the region. and with given domaintable. global parser
 * is restored afterwards. zone needs apex set. returns last domain name
 * parsed and the number rrs parse. return number of errors, 0 is success.
 * The string must end with a newline after the RR. */
//int zonec_parse_string(region_type* region, domain_table_type* domains,
//	zone_type* zone, char* str, domain_type** parsed, int* num_rrs);

__attribute__((always_inline))
static inline size_t parser_rdata_left(const struct zparser *parser)
{
  assert(parser->current_rr.rdata.length <= sizeof(parser->current_rr.rdata.octets));
  return sizeof(parser->current_rr.rdata.octets) - parser->current_rr.rdata.length;
}

__attribute__((always_inline))
static inline uint8_t *parser_rdata(struct zparser *parser)
{
  return parser->current_rr.rdata.octets + parser->current_rr.rdata.length;
}

static inline void *parser_rdata_advance(struct zparser *parser, size_t size)
{
  assert(sizeof(parser->current_rr.rdata.octets) - parser->current_rr.rdata.length >= size);
  parser->current_rr.rdata.length += size;
}

#endif /* ZONEC_H */
