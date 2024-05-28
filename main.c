#include <stdio.h>

#include "zonec.h"

static int32_t accept_rr(
  struct dname *owner,
  uint16_t type,
  uint16_t class,
  uint32_t ttl,
  uint16_t rdlength,
  uint8_t *rdata,
  void *user_data)
{
  size_t *count = user_data;
  (*count)++;
  return 0;
}

int main(int argc, char *argv[])
{
  size_t count = 0;
  if (argc != 3) {
    fprintf(stderr, "Usage: %s ORIGIN FILE\n", argv[0]);
    return 1;
  }
  zonec_setup_parser();
  parser->callback = accept_rr;
  parser->user_data = &count;
  zonec_read(argv[1], argv[2]);
  zonec_desetup_parser();
  printf("Parsed %zu records\n", count);
  return 0;
}
