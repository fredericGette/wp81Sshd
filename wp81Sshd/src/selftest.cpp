/*
 * selftest.cpp  -  Known-answer tests for the bundled crypto.
 *
 * Vectors:
 *   SHA-256       FIPS 180-2 "abc"
 *   SHA-512       FIPS 180-2 "abc"
 *   HMAC-SHA-256  RFC 4231 test case 2
 *   AES-256-CTR   NIST SP 800-38A F.5.5 (first block)
 *   X25519        RFC 7748 section 6.1
 *   Ed25519       RFC 8032 section 7.1 tests 1, 2 and 3
 */

#include <stdint.h>
#include <stddef.h>

#include "selftest.h"
#include "crypto/sha256.h"
#include "crypto/aes256.h"
#include "crypto/curve25519.h"
#include "crypto/ed25519.h"

static int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decode hex string into out; returns number of bytes. */
static size_t unhex(const char *hex, uint8_t *out, size_t max)
{
	size_t n = 0;
	while (hex[0] && hex[1] && n < max) {
		out[n++] = (uint8_t)((hexval(hex[0]) << 4) | hexval(hex[1]));
		hex += 2;
	}
	return n;
}

static int eq_hex(const uint8_t *got, size_t len, const char *hex)
{
	uint8_t exp[128];
	size_t  n = unhex(hex, exp, sizeof(exp));
	size_t  i;
	if (n != len) return 0;
	for (i = 0; i < len; i++) if (got[i] != exp[i]) return 0;
	return 1;
}

static void report(SelfTestPrintFn print, int *fails, const char *name, int ok)
{
	char   line[96];
	size_t i = 0;
	const char *tag = ok ? "PASS  " : "FAIL  ";
	while (*tag && i < sizeof(line) - 1) line[i++] = *tag++;
	while (*name && i < sizeof(line) - 1) line[i++] = *name++;
	line[i] = '\0';
	print(line);
	if (!ok) (*fails)++;
}

static int test_ed25519(const char *seed_hex, const char *pub_hex,
	const char *msg_hex, const char *sig_hex)
{
	uint8_t seed[32], pub[32], exp_pub[32], sig[64], msg[64];
	size_t  msg_len = unhex(msg_hex, msg, sizeof(msg));

	unhex(seed_hex, seed, 32);
	unhex(pub_hex, exp_pub, 32);

	ed25519_public_from_seed(seed, pub);
	if (!eq_hex(pub, 32, pub_hex)) return 0;

	ed25519_sign(sig, msg, msg_len, seed, pub);
	if (!eq_hex(sig, 64, sig_hex)) return 0;

	if (ed25519_verify(sig, msg, msg_len, exp_pub) != 0) return 0;

	/* A modified message must be rejected */
	msg[0] ^= 1;
	if (ed25519_verify(sig, msg, msg_len ? msg_len : 1, exp_pub) == 0) return 0;
	return 1;
}

int crypto_selftest(SelfTestPrintFn print)
{
	int fails = 0;

	{
		uint8_t d[32];
		sha256((const uint8_t *)"abc", 3, d);
		report(print, &fails, "SHA-256", eq_hex(d, 32,
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
	}
	{
		uint8_t d[64];
		ed25519_sha512((const uint8_t *)"abc", 3, d);
		report(print, &fails, "SHA-512", eq_hex(d, 64,
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
			"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
	}
	{
		uint8_t mac[32];
		hmac_sha256((const uint8_t *)"Jefe", 4,
			(const uint8_t *)"what do ya want for nothing?", 28, mac);
		report(print, &fails, "HMAC-SHA-256", eq_hex(mac, 32,
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
	}
	{
		uint8_t   key[32], iv[16], pt[16], ct[16];
		Aes256Ctx ctx;
		unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, 32);
		unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv, 16);
		unhex("6bc1bee22e409f96e93d7e117393172a", pt, 16);
		aes256_key_expand(&ctx, key);
		aes256_ctr_crypt(&ctx, iv, pt, ct, 16);
		report(print, &fails, "AES-256-CTR", eq_hex(ct, 16,
			"601ec313775789a5b7a7f504bbf3d228"));
	}
	{
		uint8_t a_priv[32], b_priv[32], a_pub[32], b_pub[32], s1[32], s2[32];
		int     ok;
		unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv, 32);
		unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_priv, 32);
		curve25519_scalarmult_base(a_pub, a_priv);
		curve25519_scalarmult_base(b_pub, b_priv);
		ok = eq_hex(a_pub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
		  && eq_hex(b_pub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
		  && curve25519_scalarmult(s1, a_priv, b_pub) == 0
		  && curve25519_scalarmult(s2, b_priv, a_pub) == 0
		  && eq_hex(s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
		  && eq_hex(s2, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
		report(print, &fails, "X25519", ok);
	}

	report(print, &fails, "Ed25519 RFC8032 #1", test_ed25519(
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		"",
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));

	report(print, &fails, "Ed25519 RFC8032 #2", test_ed25519(
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		"72",
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
		"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"));

	report(print, &fails, "Ed25519 RFC8032 #3", test_ed25519(
		"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		"af82",
		"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
		"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"));

	return fails;
}
