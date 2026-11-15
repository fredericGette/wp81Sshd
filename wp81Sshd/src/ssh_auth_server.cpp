/*
 * ssh_auth_server.cpp  -  SSH-2 public key user authentication (RFC 4252 §7).
 */

#include "ssh_auth_server.h"
#include "ssh_transport.h"
#include "base64.h"
#include "log.h"
#include "crypto/ed25519.h"

#include <string.h>

#define MAX_AUTH_REQUESTS     20
#define AUTH_DEADLINE_MS      (60 * 1000)
#define AUTHORIZED_KEYS_MAX   (64 * 1024)

/* ---- authorized_keys ----------------------------------------------------- */

static int is_space(char c) { return c == ' ' || c == '\t'; }

/* Parse one line; returns 1 if it holds an ssh-ed25519 key equal to pub. */
static int line_matches(const char *line, size_t len, const uint8_t pub[32])
{
	size_t i = 0;

	while (i < len && is_space(line[i])) i++;
	if (i >= len || line[i] == '#') return 0;

	/* Walk tokens; OpenSSH allows an options field before the key type,
	 * so look for the "ssh-ed25519" token anywhere and take the next one. */
	while (i < len) {
		size_t start = i;
		while (i < len && !is_space(line[i])) i++;
		if (i - start == 11 && memcmp(line + start, "ssh-ed25519", 11) == 0) {
			uint8_t blob[SSH_ED25519_BLOB_LEN + 8];
			uint8_t expect[SSH_ED25519_BLOB_LEN];
			size_t  bstart, n;

			while (i < len && is_space(line[i])) i++;
			bstart = i;
			while (i < len && !is_space(line[i])) i++;

			n = base64_decode(line + bstart, i - bstart, blob, sizeof(blob));
			if (n != SSH_ED25519_BLOB_LEN) return 0;
			ssh_ed25519_blob(pub, expect);
			return memcmp(blob, expect, SSH_ED25519_BLOB_LEN) == 0;
		}
		while (i < len && is_space(line[i])) i++;
	}
	return 0;
}

int ssh_key_is_authorized(const wchar_t *path, const uint8_t pub[32], unsigned session_id)
{
	HANDLE h;
	char  *data;
	DWORD  got = 0;
	size_t pos = 0;
	int    found = 0;

	h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		LOGF(TRACE_LEVEL_ERROR, "[%u] cannot open authorized_keys '%S': %lu",
			session_id, path, GetLastError());
		return 0;
	}

	data = new char[AUTHORIZED_KEYS_MAX];
	if (!ReadFile(h, data, AUTHORIZED_KEYS_MAX, &got, NULL)) got = 0;
	CloseHandle(h);

	while (pos < got && !found) {
		size_t end = pos;
		while (end < got && data[end] != '\n' && data[end] != '\r') end++;
		found = line_matches(data + pos, end - pos, pub);
		pos = end + 1;
	}

	delete[] data;
	return found;
}

/* ---- protocol ------------------------------------------------------------ */

static int send_failure(SshSession *s)
{
	uint8_t pkt[32];
	size_t  off = 0;
	buf_put_byte(pkt, sizeof(pkt), &off, SSH_MSG_USERAUTH_FAILURE);
	buf_put_cstring(pkt, sizeof(pkt), &off, "publickey");
	buf_put_byte(pkt, sizeof(pkt), &off, 0);   /* partial success: false */
	return ssh_send_packet(s, pkt, off);
}

static int handle_service_request(SshSession *s, uint8_t *buf, size_t buf_size)
{
	size_t         len = 0, off = 1;
	const uint8_t *name;
	size_t         name_len;
	uint8_t        reply[32];
	size_t         roff = 0;

	if (ssh_recv_packet(s, buf, buf_size, &len) != 0) return -1;
	if (len < 1 || buf[0] != SSH_MSG_SERVICE_REQUEST
		|| buf_get_string(buf, len, &off, &name, &name_len) != 0) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] expected SERVICE_REQUEST", s->id);
		return -1;
	}
	if (!buf_eq(name, name_len, "ssh-userauth")) {
		ssh_send_disconnect(s, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "service not available");
		return -1;
	}

	buf_put_byte(reply, sizeof(reply), &roff, SSH_MSG_SERVICE_ACCEPT);
	buf_put_cstring(reply, sizeof(reply), &roff, "ssh-userauth");
	return ssh_send_packet(s, reply, roff);
}

/*
 * Handle one "publickey" request.  off points just after the method name.
 * Returns 1 on successful authentication, 0 to continue, -1 on error.
 */
static int handle_publickey(SshSession *s, const uint8_t *buf, size_t len, size_t off,
	const uint8_t *user, size_t user_len,
	const uint8_t *service, size_t service_len)
{
	uint8_t        has_sig = 0;
	const uint8_t *algo, *blob;
	size_t         algo_len, blob_len;
	size_t         boff = 0;
	const uint8_t *key_type, *pub;
	size_t         key_type_len, pub_len;

	if (buf_get_byte(buf, len, &off, &has_sig) != 0 ||
		buf_get_string(buf, len, &off, &algo, &algo_len) != 0 ||
		buf_get_string(buf, len, &off, &blob, &blob_len) != 0)
		return -1;

	if (!buf_eq(algo, algo_len, "ssh-ed25519")) {
		LOGF(TRACE_LEVEL_INFORMATION, "[%u] rejected key type %.*s (only ssh-ed25519 is supported)", s->id,
			(int)(algo_len > 64 ? 64 : algo_len), (const char *)algo);
		return send_failure(s) == 0 ? 0 : -1;
	}

	if (buf_get_string(blob, blob_len, &boff, &key_type, &key_type_len) != 0 ||
		!buf_eq(key_type, key_type_len, "ssh-ed25519") ||
		buf_get_string(blob, blob_len, &boff, &pub, &pub_len) != 0 ||
		pub_len != ED25519_KEY_LEN || boff != blob_len)
		return send_failure(s) == 0 ? 0 : -1;

	if (!ssh_key_is_authorized(s->authorized_keys_path, pub, s->id)) {
		char fp[64];
		ssh_fingerprint(pub, fp, sizeof(fp));
		LOGF(TRACE_LEVEL_INFORMATION, "[%u] key %s not in authorized_keys", s->id, fp);
		return send_failure(s) == 0 ? 0 : -1;
	}

	if (!has_sig) {
		/* Query: "would this key be acceptable?" */
		uint8_t reply[128];
		size_t  roff = 0;
		buf_put_byte(reply, sizeof(reply), &roff, SSH_MSG_USERAUTH_PK_OK);
		buf_put_string(reply, sizeof(reply), &roff, algo, algo_len);
		buf_put_string(reply, sizeof(reply), &roff, blob, blob_len);
		return ssh_send_packet(s, reply, roff) == 0 ? 0 : -1;
	}

	/* Verify the signature over:
	 *   string session_id || byte 50 || string user || string service ||
	 *   string "publickey" || bool TRUE || string algo || string blob   */
	{
		const uint8_t *sig_blob, *sig_type, *sig;
		size_t         sig_blob_len, sig_type_len, sig_len;
		size_t         soff = 0;
		uint8_t        signed_data[512];
		size_t         doff = 0;
		int            rc = 0;

		if (buf_get_string(buf, len, &off, &sig_blob, &sig_blob_len) != 0) return -1;
		if (buf_get_string(sig_blob, sig_blob_len, &soff, &sig_type, &sig_type_len) != 0 ||
			!buf_eq(sig_type, sig_type_len, "ssh-ed25519") ||
			buf_get_string(sig_blob, sig_blob_len, &soff, &sig, &sig_len) != 0 ||
			sig_len != ED25519_SIG_LEN)
			return send_failure(s) == 0 ? 0 : -1;

		rc |= buf_put_string(signed_data, sizeof(signed_data), &doff, s->session_id, SHA256_LEN);
		rc |= buf_put_byte(signed_data, sizeof(signed_data), &doff, SSH_MSG_USERAUTH_REQUEST);
		rc |= buf_put_string(signed_data, sizeof(signed_data), &doff, user, user_len);
		rc |= buf_put_string(signed_data, sizeof(signed_data), &doff, service, service_len);
		rc |= buf_put_cstring(signed_data, sizeof(signed_data), &doff, "publickey");
		rc |= buf_put_byte(signed_data, sizeof(signed_data), &doff, 1);
		rc |= buf_put_string(signed_data, sizeof(signed_data), &doff, algo, algo_len);
		rc |= buf_put_string(signed_data, sizeof(signed_data), &doff, blob, blob_len);
		if (rc) return send_failure(s) == 0 ? 0 : -1;

		if (ed25519_verify(sig, signed_data, doff, pub) != 0) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] invalid signature", s->id);
			return send_failure(s) == 0 ? 0 : -1;
		}

		{
			char fp[64];
			ssh_fingerprint(pub, fp, sizeof(fp));
			strncpy_s(s->user, sizeof(s->user), (const char *)user,
				user_len < sizeof(s->user) - 1 ? user_len : sizeof(s->user) - 1);
			LOGF(TRACE_LEVEL_INFORMATION, "[%u] user '%s' authenticated with key %s",
				s->id, s->user, fp);
		}

		{
			uint8_t m = SSH_MSG_USERAUTH_SUCCESS;
			return ssh_send_packet(s, &m, 1) == 0 ? 1 : -1;
		}
	}
}

int ssh_auth_server(SshSession *s, uint8_t *buf, size_t buf_size)
{
	ULONGLONG deadline = GetTickCount64() + AUTH_DEADLINE_MS;
	int       requests = 0;

	if (handle_service_request(s, buf, buf_size) != 0) return -1;

	for (;;) {
		size_t         len = 0, off = 1;
		const uint8_t *user, *service, *method;
		size_t         user_len, service_len, method_len;
		int            rc;

		if (GetTickCount64() > deadline) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] authentication timeout", s->id);
			ssh_send_disconnect(s, SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "authentication timeout");
			return -1;
		}
		if (++requests > MAX_AUTH_REQUESTS) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] too many authentication attempts", s->id);
			ssh_send_disconnect(s, SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "too many authentication attempts");
			return -1;
		}

		if (ssh_recv_packet(s, buf, buf_size, &len) != 0) {
			LOGF(TRACE_LEVEL_INFORMATION, "[%u] client left during authentication after %d request(s)%s",
				s->id, requests - 1,
				requests == 1 ? "" : " (no acceptable ssh-ed25519 key was offered)");
			return -1;
		}
		if (len < 1) return -1;
		if (buf[0] != SSH_MSG_USERAUTH_REQUEST) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] unexpected message %u during authentication", s->id, buf[0]);
			return -1;
		}

		if (buf_get_string(buf, len, &off, &user, &user_len) != 0 ||
			buf_get_string(buf, len, &off, &service, &service_len) != 0 ||
			buf_get_string(buf, len, &off, &method, &method_len) != 0)
			return -1;

		if (!buf_eq(service, service_len, "ssh-connection")) {
			ssh_send_disconnect(s, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "service not available");
			return -1;
		}

		if (buf_eq(method, method_len, "publickey")) {
			rc = handle_publickey(s, buf, len, off, user, user_len, service, service_len);
			if (rc < 0) return -1;
			if (rc > 0) return 0;
		}
		else {
			/* "none", "password", "keyboard-interactive", ... */
			LOGF(TRACE_LEVEL_INFORMATION, "[%u] rejected method '%.*s' for user '%.*s' (only publickey is accepted)",
				s->id, (int)(method_len > 32 ? 32 : method_len), (const char *)method,
				(int)(user_len > 32 ? 32 : user_len), (const char *)user);
			if (send_failure(s) != 0) return -1;
		}
	}
}
