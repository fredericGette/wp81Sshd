/*
 * base64.cpp  -  RFC 4648 base64 (standard alphabet).
 */

#include "base64.h"

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size)
{
    uint32_t acc  = 0;
    int      bits = 0;
    size_t   n    = 0;
    size_t   i;

    for (i = 0; i < in_len; i++) {
        int v = b64val(in[i]);
        if (v < 0) break;              /* '=' padding or end of token */
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_size) return (size_t)-1;
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    if (bits >= 6) return (size_t)-1;  /* a lone trailing character is invalid */
    return n;
}

size_t base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size, int pad)
{
    size_t n = 0;
    size_t i;

    for (i = 0; i < in_len; i += 3) {
        uint32_t v      = (uint32_t)in[i] << 16;
        size_t   remain = in_len - i;
        if (remain > 1) v |= (uint32_t)in[i + 1] << 8;
        if (remain > 2) v |= (uint32_t)in[i + 2];

        if (n + 4 >= out_size) return (size_t)-1;
        out[n++] = B64[(v >> 18) & 63];
        out[n++] = B64[(v >> 12) & 63];
        if (remain > 1)      out[n++] = B64[(v >> 6) & 63];
        else if (pad)        out[n++] = '=';
        if (remain > 2)      out[n++] = B64[v & 63];
        else if (pad)        out[n++] = '=';
    }
    if (n >= out_size) return (size_t)-1;
    out[n] = '\0';
    return n;
}
