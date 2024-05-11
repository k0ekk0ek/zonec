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

/* administration struct */
typedef struct zparser zparser_type;
struct zparser {
	//region_type *region;	/* Allocate for parser lifetime data.  */
	region_type *rr_region;	/* Allocate RR lifetime data.  */
	//namedb_type *db;

	const char *filename;
	uint32_t default_ttl;
	uint16_t default_class;
	//zone_type *current_zone;
  struct dname *origin;
	//domain_type *origin;
	//domain_type *prev_dname;

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
  int32_t (*callback)(struct zparser *parser);
};

extern zparser_type *parser;

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
  //ATTR_FORMAT(printf, 1, 2);
void zc_warning_prev_line(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)));
  // ATTR_FORMAT(printf, 1, 2);
void zc_error(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)));
  // ATTR_FORMAT(printf, 1, 2);
void zc_error_prev_line(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)));
  //ATTR_FORMAT(printf, 1, 2);

void parser_push_stringbuf(char* str);
void parser_pop_stringbuf(void);
void parser_flush(void);

int process_rr(struct zparser *parser);
int32_t zadd_rdata_hex(struct zparser *parser, const char *hex, size_t len);
int32_t zadd_rdata_hex_length(struct zparser *parser, const char *hex, size_t len);
int32_t zadd_rdata_time(struct zparser *parser, const char *time);
int32_t zadd_rdata_services(struct zparser *parser, const char *protostr, char *servicestr);
int32_t zadd_rdata_serial(struct zparser *parser, const char *periodstr);
int32_t zadd_rdata_period(struct zparser *parser, const char *periodstr);
int32_t zadd_rdata_short(struct zparser *parser, const char *text);
int32_t zadd_rdata_long(struct zparser *parser, const char *text);
int32_t zadd_rdata_byte(struct zparser *parser, const char *text);
int32_t zadd_rdata_a(struct zparser *parser, const char *text);
int32_t zadd_rdata_aaaa(struct zparser *parser, const char *text);
int32_t zadd_rdata_ilnp64(struct zparser *parser, const char *text);
int32_t zadd_rdata_eui(struct zparser *parser, const char *text, size_t len);
int32_t zadd_rdata_text(struct zparser *parser, const char *text, size_t len);
int32_t zadd_rdata_long_text(struct zparser *parser, const char *text, size_t len);
int32_t zadd_rdata_tag(struct zparser *parser, const char *text, size_t len);
int32_t zadd_rdata_dns_name(struct zparser *parser, const uint8_t* name, size_t len);
int32_t zadd_rdata_b32(struct zparser *parser, const char *b32);
int32_t zadd_rdata_b64(struct zparser *parser, const char *b64);
int32_t zadd_rdata_rrtype(struct zparser *parser, const char *rr);
int32_t zadd_rdata_nxt(struct zparser *parser, uint8_t nxtbits[]);
int32_t zadd_rdata_nsec(struct zparser *parser, uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE]);
int32_t zadd_rdata_loc(struct zparser *parser, char *str);
int32_t zadd_rdata_algorithm(struct zparser *parser, const char *algstr);
int32_t zadd_rdata_certificate_type(struct zparser *parser,
					const char *typestr);
int32_t zadd_rdata_apl_rdata(struct zparser *parser, char *str);
int32_t zadd_rdata_svcbparam(struct zparser *parser,
	const char *key, size_t key_len, const char *value, size_t value_len);

void parse_unknown_rdata(uint16_t type, uint16_t *wireformat);

uint32_t zparser_ttl2int(const char *ttlstr, int* error);
//void zadd_rdata_wireformat(uint16_t *data);
void zadd_rdata_txt_wireformat(uint16_t *data, int first);
//void zadd_rdata_txt_clean_wireformat(void);
void zadd_rdata_svcb_check_wireformat(void);
void zadd_rdata_domain(struct zparser *parser, const struct dname *dname);

void set_bitnsec(uint8_t  bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
		 uint16_t index);
uint16_t *alloc_rdata_init(region_type *region, const void *data, size_t size);

/* zparser.y */
struct zparser *zparser_create(struct region *rr_region);
//			     namedb_type *db);<< name db is obviously not used!!!!
void zparser_init(const char *filename, uint32_t ttl, uint16_t klass,
		  const dname_type *origin);

/* parser start and stop to parse a zone */
//void zonec_setup_parser(namedb_type* db);
//void zonec_desetup_parser(void);
/* parse a zone into memory. name is origin. zonefile is file to read.
 * returns number of errors; failure may have read a partial zone */
unsigned int zonec_read(struct zparser *parser, const char *name, const char *zonefile);
/* parse a string into the region. and with given domaintable. global parser
 * is restored afterwards. zone needs apex set. returns last domain name
 * parsed and the number rrs parse. return number of errors, 0 is success.
 * The string must end with a newline after the RR. */
//int zonec_parse_string(region_type* region, domain_table_type* domains,
//	zone_type* zone, char* str, domain_type** parsed, int* num_rrs);

#endif /* ZONEC_H */
