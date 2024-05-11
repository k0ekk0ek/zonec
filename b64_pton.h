#ifndef B64_PTON_H
#define B64_PTON_H

#include <stdint.h>
#include <stddef.h>

int b64_pton(char const *src, uint8_t *target, size_t targsize);

#endif
