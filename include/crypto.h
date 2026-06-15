/**
 * @file crypto.h
 * @brief Cryptographic primitives for PacPlay (AES-256-GCM).
 *
 * Provides low-level AES-256-GCM encrypt/decrypt operations, buffer
 * management helpers, and a secure random byte generator. This module
 * is independent of the PacPlay packet/protocol layer.
 *
 * @date 2026-05-20
 * @copyright GPLv3 License
 * @section LICENSE
 * PacPlay
 * Copyright (C) 2026 Winston Meursault & Kiraterin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

/* ────────────────────────────── return codes ────────────────────────────── */

#define CRYPTO_SUCC (0)
#define CRYPTO_FAIL (-1)
#define CRYPTO_AUTH_FAIL (-2)

/* ───────────────────────── AES-256-GCM constants ────────────────────────── */

/** @brief AES-256 symmetric key size in bytes. */
#define AES_GCM_KEY_LEN 32

/** @brief GCM nonce (IV) size in bytes. */
#define AES_GCM_NONCE_LEN 12

/** @brief GCM authentication tag size in bytes. */
#define AES_GCM_TAG_LEN 16

/* ─────────────────────── Password Hashing constants ─────────────────────── */

/** @brief Salt length in bytes for password hashing (128-bit). */
#define HASH_SALT_LEN 16

/** @brief SHA-256 digest length in bytes. */
#define HASH_SHA256_LEN 32

/* ───────────────────────── ECDH(X25519) constants ───────────────────────── */

#define ECDH_SHARED_SECRET_SIZE 32

#define ECDH_PUBLIC_KEY_SIZE 32

/* ───────────────────────── HKDF-SHA256 constants ────────────────────────── */

#define HKDF_INFO_AES_KEY "PacPlay-AESKey"

/* ───────────────────────────────── types ────────────────────────────────── */

/** @brief AES-256-GCM key material: symmetric key + per-message nonce. */
typedef struct {
    uint8_t key[AES_GCM_KEY_LEN];
    uint8_t nonce[AES_GCM_NONCE_LEN];
} AESGCMKey;

/** @brief General-purpose byte buffer with capacity tracking. */
typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t len;
} AESGCMBuffer;

/** @brief Ciphertext buffer with appended authentication tag. */
typedef struct {
    AESGCMBuffer buffer;
    uint8_t tag[AES_GCM_TAG_LEN];
} AESGCMCipher;

/* ───────────────────────────── buffer helpers ───────────────────────────── */

/**
 * @brief Allocate an AESGCMBuffer with the given capacity.
 *
 * @param buf      Buffer to initialise.
 * @param capacity Number of bytes to allocate.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on allocation failure.
 */
int aesGCMBufferInit(AESGCMBuffer *buf, size_t capacity);

/**
 * @brief Free the memory held by an AESGCMBuffer.
 *
 * @param buf Buffer to deinitialise.
 */
void aesGCMBufferDeinit(AESGCMBuffer *buf);

/* ──────────────────────────── AES-256-GCM API ───────────────────────────── */

/**
 * @brief Encrypt plaintext using AES-256-GCM.
 *
 * @param plaintext Input plaintext buffer.
 * @param aad       Additional authenticated data, or NULL if unused.
 * @param key       Encryption key and nonce.
 * @param output    Output ciphertext and authentication tag.
 *                  Caller must pre-allocate @c output->buffer.data with at
 *                  least @c plaintext->len bytes.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on failure.
 */
int encryptAESGCM(const AESGCMBuffer *plaintext, const AESGCMBuffer *aad,
                  const AESGCMKey *key, AESGCMCipher *output);

/**
 * @brief Decrypt ciphertext using AES-256-GCM.
 *
 * @param cipher    Input ciphertext, length, and authentication tag.
 * @param aad       Additional authenticated data, or NULL if unused.
 *                  Must match the AAD used during encryption.
 * @param key       Decryption key and nonce.
 * @param plaintext Output plaintext buffer. Caller must pre-allocate
 *                  @c plaintext->data with at least @c cipher->buffer.len
 *                  bytes.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on internal failure,
 *         @c CRYPTO_AUTH_FAIL on authentication tag verification failure.
 */
int decryptAESGCM(const AESGCMCipher *cipher, const AESGCMBuffer *aad,
                  const AESGCMKey *key, AESGCMBuffer *plaintext);

/* ─────────────────────────── ECDH (X25519) API ──────────────────────────── */

/**
 * @brief Generate an X25519 ECDH key pair.
 *
 * Creates a new ephemeral X25519 key pair suitable for Elliptic-Curve
 * Diffie-Hellman key agreement.  The caller is responsible for freeing the
 * returned key with @c EVP_PKEY_free() when it is no longer needed.
 *
 * @return A newly allocated @c EVP_PKEY containing the key pair, or @c NULL
 *         on failure (OpenSSL error is logged internally).
 */
EVP_PKEY *genECDHKeypair(void);

/**
 * @brief Export the raw 32-byte public key from an X25519 key pair.
 *
 * Extracts the public component of @p pkey into the caller-supplied buffer.
 * The buffer must be at least @c ECDH_PUBLIC_KEY_SIZE (32) bytes.
 *
 * @param pkey  The X25519 key pair from which to extract the public key.
 *              Must not be NULL.
 * @param pub   Output buffer receiving the 32-byte raw public key.
 *              Must not be NULL.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on failure.
 */
int exportECDHPublicKey(EVP_PKEY *pkey, uint8_t pub[ECDH_PUBLIC_KEY_SIZE]);

/**
 * @brief Import a peer's raw 32-byte X25519 public key into an EVP_PKEY.
 *
 * Constructs an @c EVP_PKEY from a raw public key received over the network.
 * The caller is responsible for freeing the returned key with
 * @c EVP_PKEY_free() when it is no longer needed.
 *
 * @param pub  The 32-byte raw public key of the remote peer.
 *             Must not be NULL.
 * @return A newly allocated @c EVP_PKEY containing the peer's public key,
 *         or @c NULL on failure (OpenSSL error is logged internally).
 */
EVP_PKEY *importECDHPeerPublicKey(const uint8_t pub[ECDH_PUBLIC_KEY_SIZE]);

/**
 * @brief Derive a 32-byte ECDH shared secret using X25519.
 *
 * Performs ECDH key agreement between @p localKey (our private key) and
 * @p peerKey (the remote party's public key).  The resulting 32-byte raw
 * shared secret is suitable for further derivation (e.g., HKDF to produce
 * an AES-256 key).
 *
 * On failure, @p secret is securely zeroed to prevent partial-secret leakage.
 *
 * @param localKey  Our X25519 key pair (must contain the private key).
 *                  Must not be NULL.
 * @param peerKey   The peer's X25519 public key.  Must not be NULL.
 * @param secret    Output buffer receiving the 32-byte shared secret.
 *                  Must not be NULL.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on failure.
 */
int deriveECDHSharedSecret(EVP_PKEY *localKey, EVP_PKEY *peerKey,
                           uint8_t secret[ECDH_SHARED_SECRET_SIZE]);

/* ──────────────────────────── HKDF-SHA256 API ───────────────────────────── */

/** @brief HKDF info string identifying the AES-256 key derivation context. */

/**
 * @brief Derive an AES-256-GCM key from an ECDH shared secret via HKDF-SHA256.
 *
 * Performs HKDF (RFC 5869) with SHA-256 over the raw shared secret to produce
 * a 32-byte AES-256 key stored in @p outKey.  The @c nonce field of @p outKey
 * is zeroed; the caller must set a fresh nonce before each encryption.
 *
 * Uses the fixed info string @c HKDF_INFO_AES_KEY as the HKDF application
 * label, and an empty salt (defaults to HashLen zeros per RFC 5869 Section
 * 2.2).
 *
 * On failure, @p outKey is securely zeroed to prevent partial key leakage.
 *
 * @param sharedSecret  The raw ECDH shared secret (typically 32 bytes from
 *                      X25519).  Must not be NULL.
 * @param secretLen     Length of @p sharedSecret in bytes.  Must be > 0.
 * @param outKey        Output AES-256-GCM key material.  Must not be NULL.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on failure.
 */
int deriveAESKey(const uint8_t *sharedSecret, size_t secretLen,
                 AESGCMKey *outKey);

/* ──────────────────────────── Password Hashing ──────────────────────────── */

/**
 * @brief Hash a password with a randomly generated salt using SHA-256.
 *
 * Generates a cryptographically random salt of @c HASH_SALT_LEN bytes,
 * computes SHA-256(password || salt), and returns the result as a
 * heap-allocated hex string in the format "salt_hex:hash_hex".
 *
 * The caller is responsible for freeing the returned string with @c free().
 * All intermediate sensitive data (salt, digest) is securely wiped before
 * the function returns.
 *
 * @param password  Null-terminated password string. Must not be NULL.
 * @return A newly allocated string "salt_hex:hash_hex" on success,
 *         or @c NULL on failure (invalid input or internal crypto error).
 */
char *hashPassword(const char *password);

/**
 * @brief Verify a password against a stored hash string.
 *
 * Parses the salt from @p storedHash (format "salt_hex:hash_hex"),
 * recomputes SHA-256(password || salt), and compares the result against
 * the stored hash using constant-time comparison to prevent timing attacks.
 *
 * All intermediate sensitive data is securely wiped before the function
 * returns.
 *
 * @param password    Null-terminated password to verify. Must not be NULL.
 * @param storedHash  The stored hash string produced by @c hashPassword().
 *                    Must not be NULL.
 * @return @c CRYPTO_SUCC if the password matches, @c CRYPTO_FAIL otherwise
 *         (mismatch, invalid format, or internal error).
 */
int verifyPassword(const char *password, const char *storedHash);

/* ───────────────────────── Base32 (RFC 4648) API ────────────────────────── */

/**
 * @brief Encode raw binary data to a Base32 (RFC 4648) string.
 *
 * Encodes @p data into a null-terminated Base32 string using the standard
 * alphabet @c ABCDEFGHIJKLMNOPQRSTUVWXYZ234567, without padding characters
 * (@c '=').  The caller is responsible for freeing the returned string with
 * @c free().
 *
 * @param data    Input binary data to encode.  Must not be NULL when
 *                @p len > 0.
 * @param len     Length of @p data in bytes.
 * @param outStr  Output parameter receiving the heap-allocated,
 *                null-terminated Base32 string.  Set to @c NULL on failure.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on invalid input or
 *         allocation failure.
 */
int base32Encode(const uint8_t *data, size_t len, char **outStr);

/**
 * @brief Decode a Base32 (RFC 4648) string back to raw binary data.
 *
 * Decodes a Base32-encoded string into raw bytes.  The input is
 * case-insensitive and whitespace (ASCII space, tab, newline, carriage
 * return) is silently stripped.  Any character outside the Base32 alphabet
 * @c ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 (including the RFC 4648 padding
 * character @c '=') is treated as an error.
 *
 * The caller is responsible for freeing the returned buffer with @c free().
 *
 * @param encoded  Null-terminated Base32 string to decode.  Must not be
 *                 NULL.
 * @param outData  Output parameter receiving the heap-allocated decoded
 *                 bytes.  Set to @c NULL on failure.
 * @param outLen   Output parameter receiving the number of decoded bytes.
 *                 Unchanged on failure.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on invalid input
 *         (invalid character, corrupt padding bits, or encoding too short
 *         to contain a full byte) or allocation failure.
 */
int base32Decode(const char *encoded, uint8_t **outData, size_t *outLen);

/* ─────────────────────── TOTP (RFC 6238) constants ──────────────────────── */

/** @brief TOTP time step in seconds (standard 30 s). */
#define TOTP_STEP_SECONDS 30

/** @brief Number of decimal digits in the generated code. */
#define TOTP_DIGITS 6

/** @brief Allowed time-step window (±1 from current). */
#define TOTP_WINDOW 1

/** @brief SHA-1 digest length used for TOTP HMAC. */
#define TOTP_HMAC_SHA1_LEN 20

/** @brief Modulus for 6-digit code extraction (10^TOTP_DIGITS). */
#define TOTP_CODE_RANGE 1000000

/** @brief Minimum TOTP shared secret length in bytes (RFC 4226: >= 128 bits).
 */
#define TOTP_MIN_KEY_LEN 16

/* ──────────────────────────────── TOTP API ──────────────────────────────── */

/**
 * @brief Verify a user-provided TOTP code against a shared secret.
 *
 * Decodes the Base32-encoded @p secret into raw key material, computes the
 * expected TOTP code for the current 30-second time window (as well as the
 * immediately preceding and succeeding windows to allow for clock skew),
 * and compares the result against the code pointed to by @p code using
 * integer equality.
 *
 * Implements RFC 6238 (TOTP) with HMAC-SHA1 (RFC 2104) and dynamic
 * truncation per RFC 4226.  The decoded key is securely wiped from memory
 * before the function returns.
 *
 * @param secret  Base32-encoded shared secret string (null-terminated).
 *                Must not be NULL.  After decoding, the raw key must be
 *                at least @c TOTP_MIN_KEY_LEN bytes per RFC 4226.
 * @param code    Pointer to the 6-digit TOTP code to verify.  Must not be
 *                NULL.
 * @return @c CRYPTO_SUCC when @p *code matches the expected value for the
 *         current or an adjacent time window, @c CRYPTO_FAIL otherwise
 *         (mismatch, invalid secret, undersized key, or internal error).
 */
int verifyTOTPCode(const char *secret, int *code);

/**
 * @brief Generate a key URI for TOTP enrollment (Google Authenticator format).
 *
 * Produces an @c otpauth://totp/ URI string that encodes the shared TOTP
 * secret together with the account label, issuer, and algorithm parameters.
 * The URI can be embedded in a QR code for import into standard authenticator
 * applications (Google Authenticator, Authy, etc.).
 *
 * The label is constructed as @c PacPlay:@p username.  Both the issuer
 * portion of the label and the @c issuer query parameter are set to
 * @c "PacPlay".  The @p secret is assumed to already be Base32-encoded
 * by the caller and is placed directly in the URI query string.
 *
 * URI path components that may contain special characters (@p issuer and
 * @p username) are percent-encoded per RFC 3986 before insertion.
 *
 * The caller is responsible for freeing the returned string with @c free().
 *
 * @param secret    Base32-encoded TOTP shared secret (null-terminated).
 *                  Must not be NULL or empty.  Placed in the URI as-is.
 * @param username  Human-readable account identifier (null-terminated).
 *                  Must not be NULL or empty.  Percent-encoded if needed.
 * @param outURI    Output parameter receiving the heap-allocated,
 *                  null-terminated URI string.  Set to @c NULL on failure.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on invalid input
 *         or allocation failure.
 */
int generateOTPAuthURI(const char *secret, const char *username, char **outURI, size_t *outURILen);

/* ──────────────────────────────── utility ───────────────────────────────── */

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * @param buf Destination buffer.
 * @param len Number of random bytes to generate.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on failure.
 */
int cryptoRandomBytes(uint8_t *buf, int len);

#endif /* CRYPTO_H */
