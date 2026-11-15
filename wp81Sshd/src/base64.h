#pragma once

/*
 * base64.h  -  RFC 4648 base64 (standard alphabet).
 */

#include <stdint.h>
#include <stddef.h>

/*
 * Decode `in_len` characters.  Stops at the first '=' or non-alphabet char.
 * Returns the number of bytes written, or (size_t)-1 if out is too small
 * or the input is malformed.
 */
size_t base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size);

/*
 * Encode into out (NUL-terminated).  `pad` = 0 omits trailing '='
 * (OpenSSH fingerprint style).  Returns the string length, or (size_t)-1
 * if out is too small.
 */
size_t base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size, int pad);
