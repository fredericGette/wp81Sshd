/*
 * ssh_transport.cpp  -  SSH-2 binary packet protocol (RFC 4253), server side.
 *
 * Derived from wp81ssh/src/ssh_transport.cpp.  Changes:
 *   - server banner exchange,
 *   - separate activation of each direction (enc after our NEWKEYS,
 *     dec after the peer's NEWKEYS),
 *   - AES key schedule expanded once per key, not per packet,
 *   - packet length validated against the cipher block size,
 *   - thread-safe send,
 *   - logging through LOGF instead of stderr.
 */

#include "ssh_transport.h"
#include "log.h"
#include "crypto/aes256.h"
#include "crypto/sha256.h"

#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE  16   /* AES block size */
#define MAC_SIZE    32   /* HMAC-SHA-256 */

/* ---- RNG ----------------------------------------------------------------- */

int ssh_random(uint8_t *buf, size_t len)
{
	HCRYPTPROV hProv = 0;
	BOOL       ok;
	if (!api.CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		LOGF(TRACE_LEVEL_ERROR, "CryptAcquireContext failed: %lu", GetLastError());
		return -1;
	}
	ok = api.CryptGenRandom(hProv, (DWORD)len, buf);
	api.CryptReleaseContext(hProv, 0);
	if (!ok) {
		LOGF(TRACE_LEVEL_ERROR, "CryptGenRandom failed: %lu", GetLastError());
		return -1;
	}
	return 0;
}

/* ---- reliable send / recv on a blocking socket --------------------------- */

static int sock_send_all(SOCKET fd, const uint8_t *buf, size_t len)
{
	size_t sent = 0;
	while (sent < len) {
		int n = send(fd, (const char *)(buf + sent), (int)(len - sent), 0);
		if (n == SOCKET_ERROR || n <= 0) return -1;
		sent += (size_t)n;
	}
	return 0;
}

static int sock_recv_all(SOCKET fd, uint8_t *buf, size_t len)
{
	size_t got = 0;
	while (got < len) {
		int n = recv(fd, (char *)(buf + got), (int)(len - got), 0);
		if (n == SOCKET_ERROR || n <= 0) return -1;
		got += (size_t)n;
	}
	return 0;
}

/* ---- Banner exchange ----------------------------------------------------- */

int ssh_banner_exchange_server(SshSession *s)
{
	const char *banner = SSH_ID_STRING "\r\n";
	char        line[SSH_BANNER_MAX];
	int         lines = 0;

	if (sock_send_all(s->sock, (const uint8_t *)banner, strlen(banner)) != 0) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] failed to send banner", s->id);
		return -1;
	}
	strncpy_s(s->own_version, SSH_BANNER_MAX, SSH_ID_STRING, _TRUNCATE);

	/* Clients normally send nothing before their version line, but RFC 4253
	 * §4.2 tolerates other lines: accept a few, then give up. */
	for (;;) {
		size_t pos = 0;
		for (;;) {
			uint8_t c;
			if (sock_recv_all(s->sock, &c, 1) != 0) {
				int err = WSAGetLastError();
				LOGF(TRACE_LEVEL_WARNING, "[%u] %s while reading banner", s->id,
					err == WSAETIMEDOUT ? "timeout" : "connection closed");
				return -1;
			}
			if (c == '\n') break;
			if (c == '\r') continue;
			if (pos >= sizeof(line) - 1) {
				LOGF(TRACE_LEVEL_WARNING, "[%u] client banner too long", s->id);
				return -1;
			}
			line[pos++] = (char)c;
		}
		line[pos] = '\0';
		if (strncmp(line, "SSH-", 4) == 0) break;
		if (++lines > 20) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] no SSH banner from client", s->id);
			return -1;
		}
	}

	if (strncmp(line, "SSH-2.0-", 8) != 0 && strncmp(line, "SSH-1.99-", 9) != 0) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] unsupported protocol version: %s", s->id, line);
		return -1;
	}

	strncpy_s(s->peer_version, SSH_BANNER_MAX, line, _TRUNCATE);
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] client version: %s", s->id, s->peer_version);
	return 0;
}

/* ---- Buffer helpers ------------------------------------------------------ */

void buf_put_u32(uint8_t *b, uint32_t v)
{
	b[0] = (uint8_t)(v >> 24);
	b[1] = (uint8_t)(v >> 16);
	b[2] = (uint8_t)(v >> 8);
	b[3] = (uint8_t)(v);
}

uint32_t buf_get_u32(const uint8_t *b)
{
	return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
		| ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

int buf_put_string(uint8_t *b, size_t b_size, size_t *off,
	const uint8_t *data, size_t data_len)
{
	if (*off > b_size || 4 + data_len > b_size - *off) return -1;
	buf_put_u32(b + *off, (uint32_t)data_len);
	*off += 4;
	if (data_len > 0) memcpy(b + *off, data, data_len);
	*off += data_len;
	return 0;
}

int buf_put_cstring(uint8_t *b, size_t b_size, size_t *off, const char *str)
{
	return buf_put_string(b, b_size, off, (const uint8_t *)str, strlen(str));
}

int buf_put_u32_at(uint8_t *b, size_t b_size, size_t *off, uint32_t v)
{
	if (*off > b_size || b_size - *off < 4) return -1;
	buf_put_u32(b + *off, v);
	*off += 4;
	return 0;
}

int buf_put_byte(uint8_t *b, size_t b_size, size_t *off, uint8_t v)
{
	if (*off >= b_size) return -1;
	b[(*off)++] = v;
	return 0;
}

int buf_get_string(const uint8_t *b, size_t b_size, size_t *off,
	const uint8_t **out_ptr, size_t *out_len)
{
	uint32_t len;
	if (*off > b_size || b_size - *off < 4) return -1;
	len = buf_get_u32(b + *off);
	*off += 4;
	if ((size_t)len > b_size - *off) return -1;
	*out_ptr = b + *off;
	*out_len = (size_t)len;
	*off += (size_t)len;
	return 0;
}

int buf_get_u32_at(const uint8_t *b, size_t b_size, size_t *off, uint32_t *out)
{
	if (*off > b_size || b_size - *off < 4) return -1;
	*out = buf_get_u32(b + *off);
	*off += 4;
	return 0;
}

int buf_get_byte(const uint8_t *b, size_t b_size, size_t *off, uint8_t *out)
{
	if (*off >= b_size) return -1;
	*out = b[(*off)++];
	return 0;
}

int buf_eq(const uint8_t *p, size_t len, const char *str)
{
	size_t n = strlen(str);
	return len == n && memcmp(p, str, n) == 0;
}

/* ---- Packet send --------------------------------------------------------- */

/*
 * SSH binary packet layout (RFC 4253 §6):
 *
 *   uint32  packet_length   (= 1 + payload_len + padding_len)
 *   byte    padding_length
 *   byte[n] payload
 *   byte[p] random_padding  (p = padding_length)
 *   byte[m] mac             (HMAC-SHA-256, not included in packet_length)
 */

int ssh_send_packet(SshSession *s, const uint8_t *payload, size_t payload_len)
{
	uint8_t pkt[SSH_MAX_PACKET + MAC_SIZE];   /* on the stack: threads have 1 MB */
	size_t  overhead = 5 + payload_len;
	size_t  pad = BLOCK_SIZE - (overhead % BLOCK_SIZE);
	size_t  packet_len, total, i;
	int     rc = 0;

	if (pad < 4) pad += BLOCK_SIZE;
	packet_len = 1 + payload_len + pad;
	total = 4 + packet_len;
	if (total + MAC_SIZE > sizeof(pkt)) {
		LOGF(TRACE_LEVEL_ERROR, "[%u] packet too large (%u bytes)", s->id, (unsigned)payload_len);
		return -1;
	}

	EnterCriticalSection(&s->send_lock);

	buf_put_u32(pkt, (uint32_t)packet_len);
	pkt[4] = (uint8_t)pad;
	memcpy(pkt + 5, payload, payload_len);

	/* Padding is encrypted and need not be secret; a per-session xorshift
	 * seeded from the CSPRNG is sufficient. */
	for (i = 0; i < pad; i++) {
		uint32_t x = s->pad_rng;
		x ^= x << 13; x ^= x >> 17; x ^= x << 5;
		s->pad_rng = x;
		pkt[5 + payload_len + i] = (uint8_t)x;
	}

	if (!s->enc_active) {
		if (sock_send_all(s->sock, pkt, total) != 0) rc = -1;
	}
	else {
		uint8_t       seq_be[4];
		HmacSha256Ctx hctx;

		/* MAC over uint32(seq) || plaintext packet, appended after the ciphertext */
		buf_put_u32(seq_be, s->enc.seq);
		hmac_sha256_init(&hctx, s->enc.mac_key, SHA256_LEN);
		hmac_sha256_update(&hctx, seq_be, 4);
		hmac_sha256_update(&hctx, pkt, total);
		hmac_sha256_final(&hctx, pkt + total);

		aes256_ctr_crypt(&s->enc.aes, s->enc.iv, pkt, pkt, total);

		if (sock_send_all(s->sock, pkt, total + MAC_SIZE) != 0) rc = -1;
	}

	if (rc == 0) s->enc.seq++;
	LeaveCriticalSection(&s->send_lock);

	if (rc != 0)
		LOGF(TRACE_LEVEL_VERBOSE, "[%u] send failed: %d", s->id, WSAGetLastError());
	return rc;
}

/* ---- Packet receive ------------------------------------------------------ */

static void log_peer_disconnect(SshSession *s, const uint8_t *buf, size_t len)
{
	size_t         off = 1;
	uint32_t       code = 0;
	const uint8_t *desc = (const uint8_t *)"";
	size_t         desc_len = 0;
	buf_get_u32_at(buf, len, &off, &code);
	buf_get_string(buf, len, &off, &desc, &desc_len);
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] client disconnected (code %u): %.*s",
		s->id, (unsigned)code, (int)(desc_len > 200 ? 200 : desc_len), (const char *)desc);
}

int ssh_recv_packet(SshSession *s, uint8_t *buf, size_t buf_size, size_t *out_len)
{
	for (;;) {   /* loop to skip IGNORE/DEBUG transparently */
		uint32_t pkt_len;
		size_t   total;
		uint8_t  pad_len;
		size_t   pay_len;

		if (!s->dec_active) {
			uint8_t hdr[4];
			if (sock_recv_all(s->sock, hdr, 4) != 0) {
				if (WSAGetLastError() == WSAETIMEDOUT)
					LOGF(TRACE_LEVEL_WARNING, "[%u] timeout waiting for the client", s->id);
				return -1;
			}
			pkt_len = buf_get_u32(hdr);
			total = 4 + (size_t)pkt_len;
			if (pkt_len < 5 || pkt_len > SSH_MAX_PACKET || total > buf_size || (total % 8) != 0) {
				LOGF(TRACE_LEVEL_WARNING, "[%u] bad plaintext packet length %u", s->id, pkt_len);
				return -1;
			}
			memcpy(buf, hdr, 4);
			if (sock_recv_all(s->sock, buf + 4, pkt_len) != 0) return -1;
		}
		else {
			uint8_t       mac_exp[MAC_SIZE];
			uint8_t       mac_got[MAC_SIZE];
			uint8_t       seq_be[4];
			uint8_t       diff = 0;
			HmacSha256Ctx hctx;
			int           i;

			/* First block holds the length */
			if (sock_recv_all(s->sock, buf, BLOCK_SIZE) != 0) {
				if (WSAGetLastError() == WSAETIMEDOUT)
					LOGF(TRACE_LEVEL_WARNING, "[%u] timeout waiting for the client", s->id);
				return -1;
			}
			aes256_ctr_crypt(&s->dec.aes, s->dec.iv, buf, buf, BLOCK_SIZE);

			pkt_len = buf_get_u32(buf);
			total = 4 + (size_t)pkt_len;
			if (pkt_len < 5 || pkt_len > SSH_MAX_PACKET || total > buf_size
				|| total < BLOCK_SIZE || (total % BLOCK_SIZE) != 0) {
				LOGF(TRACE_LEVEL_WARNING, "[%u] bad encrypted packet length %u", s->id, pkt_len);
				return -1;
			}

			if (total > BLOCK_SIZE) {
				if (sock_recv_all(s->sock, buf + BLOCK_SIZE, total - BLOCK_SIZE) != 0) return -1;
				aes256_ctr_crypt(&s->dec.aes, s->dec.iv, buf + BLOCK_SIZE, buf + BLOCK_SIZE, total - BLOCK_SIZE);
			}

			if (sock_recv_all(s->sock, mac_got, MAC_SIZE) != 0) return -1;

			buf_put_u32(seq_be, s->dec.seq);
			hmac_sha256_init(&hctx, s->dec.mac_key, SHA256_LEN);
			hmac_sha256_update(&hctx, seq_be, 4);
			hmac_sha256_update(&hctx, buf, total);
			hmac_sha256_final(&hctx, mac_exp);

			for (i = 0; i < MAC_SIZE; i++) diff |= (uint8_t)(mac_got[i] ^ mac_exp[i]);
			if (diff != 0) {
				LOGF(TRACE_LEVEL_WARNING, "[%u] MAC verification failed (seq=%u)", s->id, s->dec.seq);
				return -1;
			}
		}

		pad_len = buf[4];
		if (pad_len < 4 || (size_t)pad_len + 1 >= pkt_len) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] bad padding length %u", s->id, pad_len);
			return -1;
		}
		pay_len = pkt_len - 1 - pad_len;
		memmove(buf, buf + 5, pay_len);
		*out_len = pay_len;
		s->dec.seq++;

		if (buf[0] == SSH_MSG_DISCONNECT) {
			log_peer_disconnect(s, buf, pay_len);
			return -1;
		}
		if (buf[0] == SSH_MSG_IGNORE || buf[0] == SSH_MSG_DEBUG) {
			if (s->strict_kex && s->in_initial_kex) {
				LOGF(TRACE_LEVEL_WARNING, "[%u] unexpected message %u during strict KEX", s->id, buf[0]);
				return -1;
			}
			continue;
		}
		return 0;
	}
}

/* ---- Disconnect ---------------------------------------------------------- */

void ssh_send_disconnect(SshSession *s, uint32_t reason_code, const char *reason)
{
	uint8_t pkt[512];
	size_t  off = 0;

	buf_put_byte(pkt, sizeof(pkt), &off, SSH_MSG_DISCONNECT);
	buf_put_u32_at(pkt, sizeof(pkt), &off, reason_code);
	buf_put_cstring(pkt, sizeof(pkt), &off, reason ? reason : "");
	buf_put_cstring(pkt, sizeof(pkt), &off, "");   /* language tag */
	ssh_send_packet(s, pkt, off);
}
