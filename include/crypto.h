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

/* ──────────────────────── return codes ──────────────────────────────────── */

#define CRYPTO_SUCC (0)
#define CRYPTO_FAIL (-1)
#define CRYPTO_AUTH_FAIL (-2)

/* ──────────────────────── AES-256-GCM constants ────────────────────────── */

/** @brief AES-256 symmetric key size in bytes. */
#define AES_GCM_KEY_LEN 32

/** @brief GCM nonce (IV) size in bytes. */
#define AES_GCM_NONCE_LEN 12

/** @brief GCM authentication tag size in bytes. */
#define AES_GCM_TAG_LEN 16

/* ──────────────────────── ECDH(X25519) constants ────────────────────────── */

#define ECDH_SHARED_SECRET_SIZE 32

#define ECDH_PUBLIC_KEY_SIZE 32

/* ───────────────────────── HKDF-SHA256 constants ────────────────────────── */

#define HKDF_INFO_AES_KEY "PacPlay-AESKey"

/* ──────────────────────── types ─────────────────────────────────────────── */

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

/* ──────────────────────── buffer helpers ────────────────────────────────── */

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

/* ──────────────────────── AES-256-GCM API ──────────────────────────────── */

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

/* ──────────────────────── ECDH (X25519) API ────────────────────────────── */

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

/* ──────────────────────── HKDF-SHA256 API ──────────────────────────────── */

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

/* ──────────────────────── utility ──────────────────────────────────────── */

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * @param buf Destination buffer.
 * @param len Number of random bytes to generate.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on failure.
 */
int cryptoRandomBytes(uint8_t *buf, int len);

#endif /* CRYPTO_H */
