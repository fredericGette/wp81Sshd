#pragma once

/*
* ed25519.h  -  Ed25519 signature verification (RFC 8032)
*
* Verification, plus signing / public key derivation (added for wp81Sshd).
* Curve: twisted Edwards curve -x^2 + y^2 = 1 - (121665/121666)*x^2*y^2
* over GF(2^255-19).
*
* No external dependencies.
*/

#include <stdint.h>
#include <stddef.h>

#define ED25519_PUBLIC_KEY_LEN  32
#define ED25519_SIGNATURE_LEN   64

/*
* Verify an Ed25519 signature.
*
*   sig     : 64-byte signature  (R || S)
*   msg     : message bytes
*   msg_len : message length
*   pub     : 32-byte Ed25519 public key
*
* Returns  0 if the signature is valid.
* Returns -1 if the signature is invalid (reject the connection).
*/
int ed25519_verify(const uint8_t sig[ED25519_SIGNATURE_LEN],
	const uint8_t *msg, size_t msg_len,
	const uint8_t pub[ED25519_PUBLIC_KEY_LEN]);

#define ED25519_SEED_LEN        32

/*
* Derive the 32-byte public key from a 32-byte secret seed (RFC 8032 5.1.5).
*/
void ed25519_public_from_seed(const uint8_t seed[ED25519_SEED_LEN],
	uint8_t pub[ED25519_PUBLIC_KEY_LEN]);

/*
* Sign msg with the key (seed, pub) (RFC 8032 5.1.6).
* Writes the 64-byte signature R || S into sig.
* Secret-dependent scalar multiplications are constant-time.
*/
void ed25519_sign(uint8_t sig[ED25519_SIGNATURE_LEN],
	const uint8_t *msg, size_t msg_len,
	const uint8_t seed[ED25519_SEED_LEN],
	const uint8_t pub[ED25519_PUBLIC_KEY_LEN]);

/* SHA-512 single-call helper (used by the self test). */
void ed25519_sha512(const uint8_t *data, size_t len, uint8_t digest[64]);
