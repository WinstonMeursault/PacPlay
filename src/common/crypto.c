/**
 * @file crypto.c
 * @brief Cryptographic primitives for PacPlay (AES-256-GCM).
 *
 * Implements low-level AES-256-GCM encryption and decryption using the
 * OpenSSL EVP interface, along with buffer management helpers and a
 * secure random byte generator.
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

#include "crypto.h"
#include "log.h"
#include "utils.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ──────────── OpenSSL error-logging helper ──────────────────────────────── */

#define LOG_ERROR_SSL(msg)                                                     \
    do {                                                                       \
        unsigned long errCode = ERR_get_error();                               \
        const char *reason_ = ERR_reason_error_string(errCode);                \
        LOG_ERROR(msg ": %s (SSLERR:%lu)", reason_ ? reason_ : "(null)",       \
                  errCode);                                                    \
    } while (false)

/* ──────────────────────── AESGCMBuffer helpers ─────────────────────────── */

int aesGCMBufferInit(AESGCMBuffer *buf, size_t capacity) {
    if (buf == NULL) {
        return CRYPTO_FAIL;
    }
    buf->data = malloc(capacity);
    buf->capacity = capacity;
    buf->len = 0;
    if (buf->data == NULL) {
        LOG_ERROR("Failed to allocate memory for AESGCM buffer: %s (%d)",
                  strerror(errno), errno);
        return CRYPTO_FAIL;
    }
    return CRYPTO_SUCC;
}

void aesGCMBufferDeinit(AESGCMBuffer *buf) {
    if (buf == NULL) {
        return;
    }
    free(buf->data);
    buf->data = NULL;
}

/* ───────────────────── AES-256-GCM encrypt / decrypt ───────────────────── */

int encryptAESGCM(const AESGCMBuffer *plaintext, const AESGCMBuffer *aad,
                  const AESGCMKey *key, AESGCMCipher *output) {
    if (plaintext == NULL || plaintext->data == NULL || key == NULL ||
        output == NULL || output->buffer.data == NULL) {
        return CRYPTO_FAIL;
    }

    if (plaintext->len > INT32_MAX) {
        LOG_ERROR("Plaintext length exceeds EVP API limit (%zu > %d)",
                  plaintext->len, INT32_MAX);
        return CRYPTO_FAIL;
    }

    if (aad != NULL && aad->len > INT32_MAX) {
        LOG_ERROR("AAD length exceeds EVP API limit (%zu > %d)", aad->len,
                  INT32_MAX);
        return CRYPTO_FAIL;
    }

    if (output->buffer.capacity < plaintext->len) {
        LOG_ERROR(
            "Output buffer capacity too small (%zu(capacity) < %zu(length))",
            output->buffer.capacity, plaintext->len);
        return CRYPTO_FAIL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR_SSL("Failed to create EVP_CIPHER_CTX");
        return CRYPTO_FAIL;
    }

    int32_t len = 0;
    int ret = CRYPTO_FAIL;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        LOG_ERROR_SSL("Failed to initialize AES-256-GCM encryption");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN,
                            NULL) != 1) {
        LOG_ERROR_SSL("Failed to set GCM nonce length");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key->key, key->nonce) != 1) {
        LOG_ERROR_SSL("Failed to set AES-GCM key and nonce");
        goto cleanup;
    }

    /* Feed AAD (authenticated but not encrypted). */
    if (aad != NULL && aad->len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad->data, (int32_t)aad->len) !=
            1) {
            LOG_ERROR_SSL("Failed to set AAD for AES-GCM encryption");
            goto cleanup;
        }
    }

    if (EVP_EncryptUpdate(ctx, output->buffer.data, &len, plaintext->data,
                          (int32_t)plaintext->len) != 1) {
        LOG_ERROR_SSL("Failed to encrypt plaintext");
        goto cleanup;
    }
    output->buffer.len = (size_t)len;

    if (EVP_EncryptFinal_ex(ctx, output->buffer.data + len, &len) != 1) {
        LOG_ERROR_SSL("Failed to finalize AES-GCM encryption");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN,
                            output->tag) != 1) {
        LOG_ERROR_SSL("Failed to get AES-GCM authentication tag");
        goto cleanup;
    }

    ret = CRYPTO_SUCC;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int decryptAESGCM(const AESGCMCipher *cipher, const AESGCMBuffer *aad,
                  const AESGCMKey *key, AESGCMBuffer *plaintext) {
    if (cipher == NULL || cipher->buffer.data == NULL || key == NULL ||
        plaintext == NULL || plaintext->data == NULL) {
        return CRYPTO_FAIL;
    }

    if (cipher->buffer.len > INT32_MAX) {
        LOG_ERROR("Ciphertext length exceeds EVP API limit (%zu > %d)",
                  cipher->buffer.len, INT32_MAX);
        return CRYPTO_FAIL;
    }

    if (aad != NULL && aad->len > INT32_MAX) {
        LOG_ERROR("AAD length exceeds EVP API limit (%zu > %d)", aad->len,
                  INT32_MAX);
        return CRYPTO_FAIL;
    }

    if (plaintext->capacity < cipher->buffer.len) {
        LOG_ERROR(
            "Output buffer capacity too small (%zu(capacity) < %zu(length))",
            plaintext->capacity, cipher->buffer.len);
        return CRYPTO_FAIL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR_SSL("Failed to create EVP_CIPHER_CTX");
        return CRYPTO_FAIL;
    }

    int32_t len = 0;
    int ret = CRYPTO_FAIL;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        LOG_ERROR_SSL("Failed to initialize AES-256-GCM decryption");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN,
                            NULL) != 1) {
        LOG_ERROR_SSL("Failed to set GCM nonce length");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key->key, key->nonce) != 1) {
        LOG_ERROR_SSL("Failed to set AES-GCM key and nonce");
        goto cleanup;
    }

    /* Feed AAD (must match what was used during encryption). */
    if (aad != NULL && aad->len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad->data, (int32_t)aad->len) !=
            1) {
            LOG_ERROR_SSL("Failed to set AAD for AES-GCM decryption");
            goto cleanup;
        }
    }

    if (EVP_DecryptUpdate(ctx, plaintext->data, &len, cipher->buffer.data,
                          (int32_t)cipher->buffer.len) != 1) {
        LOG_ERROR_SSL("Failed to decrypt ciphertext");
        goto cleanup;
    }
    plaintext->len = (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN,
                            (void *)(uintptr_t)cipher->tag) != 1) {
        LOG_ERROR_SSL("Failed to set AES-GCM authentication tag");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext->data + len, &len) != 1) {
        LOG_ERROR_SSL("AES-GCM tag verification failed");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_AUTH_FAIL;
    }

    ret = CRYPTO_SUCC;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ───────────────────── ECDH (X25519) ───────────────────────────────────── */

EVP_PKEY *genECDHKeypair(void) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (pctx == NULL) {
        LOG_ERROR_SSL("Failed to create EVP_PKEY_CTX for X25519 keygen");
        return NULL;
    }

    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        LOG_ERROR_SSL("Failed to initialize X25519 key generation");
        goto err;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        LOG_ERROR_SSL("Failed to generate X25519 key pair");
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;

err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return NULL;
}

int exportECDHPublicKey(EVP_PKEY *pkey, uint8_t pub[ECDH_PUBLIC_KEY_SIZE]) {
    if (pkey == NULL || pub == NULL) {
        LOG_ERROR("exportECDHPublicKey: NULL argument (pkey=%p, pub=%p)",
                  (void *)pkey, (void *)pub);
        return CRYPTO_FAIL;
    }

    size_t len = ECDH_PUBLIC_KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) <= 0) {
        LOG_ERROR_SSL("Failed to export X25519 public key");
        return CRYPTO_FAIL;
    }

    if (len != ECDH_PUBLIC_KEY_SIZE) {
        LOG_ERROR("Exported public key length mismatch: expected %d, got %zu",
                  ECDH_PUBLIC_KEY_SIZE, len);
        return CRYPTO_FAIL;
    }

    return CRYPTO_SUCC;
}

EVP_PKEY *importECDHPeerPublicKey(const uint8_t pub[ECDH_PUBLIC_KEY_SIZE]) {
    if (pub == NULL) {
        LOG_ERROR("importECDHPeerPublicKey: NULL public key buffer");
        return NULL;
    }

    EVP_PKEY *peerKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub,
                                                    ECDH_PUBLIC_KEY_SIZE);
    if (peerKey == NULL) {
        LOG_ERROR_SSL("Failed to import peer X25519 public key");
        return NULL;
    }

    return peerKey;
}

int deriveECDHSharedSecret(EVP_PKEY *localKey, EVP_PKEY *peerKey,
                           uint8_t secret[ECDH_SHARED_SECRET_SIZE]) {
    if (localKey == NULL || peerKey == NULL || secret == NULL) {
        LOG_ERROR("deriveECDHSharedSecret: NULL argument "
                  "(localKey=%p, peerKey=%p, secret=%p)",
                  (void *)localKey, (void *)peerKey, (void *)secret);
        return CRYPTO_FAIL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(localKey, NULL);
    if (ctx == NULL) {
        LOG_ERROR_SSL("Failed to create EVP_PKEY_CTX for ECDH derivation");
        return CRYPTO_FAIL;
    }

    int ret = CRYPTO_FAIL;
    size_t secretLen = ECDH_SHARED_SECRET_SIZE;

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        LOG_ERROR_SSL("Failed to initialize ECDH key derivation");
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerKey) <= 0) {
        LOG_ERROR_SSL("Failed to set peer key for ECDH derivation");
        goto cleanup;
    }

    if (EVP_PKEY_derive(ctx, secret, &secretLen) <= 0) {
        LOG_ERROR_SSL("Failed to derive ECDH shared secret");
        goto cleanup;
    }

    if (secretLen != ECDH_SHARED_SECRET_SIZE) {
        LOG_ERROR("Derived secret length mismatch: expected %d, got %zu",
                  ECDH_SHARED_SECRET_SIZE, secretLen);
        goto cleanup;
    }

    /* Reject all-zero shared secret (low-order point attack). */
    {
        uint8_t zeroCheck = 0;
        for (size_t i = 0; i < ECDH_SHARED_SECRET_SIZE; i++) {
            zeroCheck |= secret[i];
        }
        if (zeroCheck == 0) {
            LOG_ERROR("deriveECDHSharedSecret: derived secret is all-zero "
                      "(possible low-order point attack)");
            goto cleanup;
        }
    }

    ret = CRYPTO_SUCC;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (ret != CRYPTO_SUCC) {
        OPENSSL_cleanse(secret, ECDH_SHARED_SECRET_SIZE);
    }
    return ret;
}

/* ───────────────────── HKDF-SHA256 Key Derivation ──────────────────────── */

int deriveAESKey(const uint8_t *sharedSecret, size_t secretLen,
                 AESGCMKey *outKey) {
    /* Parameter validation */
    if (sharedSecret == NULL || secretLen == 0 || outKey == NULL) {
        LOG_ERROR("deriveAESKey: invalid argument "
                  "(sharedSecret=%p, secretLen=%zu, outKey=%p)",
                  (const void *)sharedSecret, secretLen, (void *)outKey);
        return CRYPTO_FAIL;
    }

    /* Zero the output structure (nonce stays zero; caller sets per-message) */
    memset(outKey, 0, sizeof(*outKey));

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        LOG_ERROR_SSL("Failed to fetch HKDF algorithm");
        return CRYPTO_FAIL;
    }

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL) {
        LOG_ERROR_SSL("Failed to create HKDF context");
        return CRYPTO_FAIL;
    }

    /*
     * HKDF parameters (RFC 5869):
     *   digest = SHA-256
     *   key    = ECDH shared secret (Input Keying Material)
     *   mode   = EXTRACT_AND_EXPAND (full HKDF: extract then expand)
     *   info   = HKDF_INFO_AES_KEY (application-level domain separation)
     *   salt   = omitted (OpenSSL defaults to HashLen zero bytes per
     *            RFC 5869 Section 2.2)
     */
    enum { HkdfParamCount = 4 };
    OSSL_PARAM params[HkdfParamCount + 1];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(
        "key", (void *)(uintptr_t)sharedSecret, secretLen);
    params[2] =
        OSSL_PARAM_construct_utf8_string("mode", "EXTRACT_AND_EXPAND", 0);
    params[3] = OSSL_PARAM_construct_octet_string(
        "info", (void *)(uintptr_t)HKDF_INFO_AES_KEY,
        sizeof(HKDF_INFO_AES_KEY) - 1);
    params[HkdfParamCount] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, outKey->key, AES_GCM_KEY_LEN, params) <= 0) {
        LOG_ERROR_SSL("HKDF-SHA256 key derivation failed");
        /* Securely wipe partial key material on failure */
        OPENSSL_cleanse(outKey, sizeof(*outKey));
        EVP_KDF_CTX_free(kctx);
        return CRYPTO_FAIL;
    }

    EVP_KDF_CTX_free(kctx);
    return CRYPTO_SUCC;
}

/* ──────────────────────── Password Hashing ─────────────────────────────── */

/**
 * @brief Convert a byte array to a lowercase hex string.
 *
 * Writes (len * 2) hex characters plus a NUL terminator into @p out.
 * The caller must ensure @p out has at least (len * 2 + 1) bytes available.
 */
static void bytesToHex(const uint8_t *bytes, size_t len, char *out) {
    static const char hexDigits[] = "0123456789abcdef";
    enum { NibbleMask = 0x0F, HexShiftBits = 4 };
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hexDigits[(bytes[i] >> HexShiftBits) & NibbleMask];
        out[i * 2 + 1] = hexDigits[bytes[i] & NibbleMask];
    }
    out[len * 2] = '\0';
}

/**
 * @brief Parse a single hex character to its nibble value.
 *
 * @return The 4-bit value (0-15), or -1 if the character is invalid hex.
 */
static int hexCharToNibble(char c) {
    enum { HexBaseValue = 10 };
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + HexBaseValue;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + HexBaseValue;
    }
    return -1;
}

/**
 * @brief Convert a hex string to a byte array.
 *
 * @param hex     Input hex string (must contain exactly len*2 valid hex chars).
 * @param bytes   Output byte buffer.
 * @param len     Expected number of output bytes.
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on invalid hex input.
 */
static int hexToBytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int high = hexCharToNibble(hex[i * 2]);
        int low = hexCharToNibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return CRYPTO_FAIL;
        }
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    return CRYPTO_SUCC;
}

/**
 * @brief Compute SHA-256(password || salt).
 *
 * @param password  Null-terminated password string.
 * @param passLen   Length of password (excluding NUL).
 * @param salt      Salt bytes.
 * @param saltLen   Length of salt.
 * @param digest    Output buffer (must be at least HASH_SHA256_LEN bytes).
 * @return @c CRYPTO_SUCC on success, @c CRYPTO_FAIL on failure.
 */
static int computePasswordHash(const char *password, size_t passLen,
                               const uint8_t *salt, size_t saltLen,
                               uint8_t digest[HASH_SHA256_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR_SSL("Failed to create EVP_MD_CTX for password hashing");
        return CRYPTO_FAIL;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        LOG_ERROR_SSL("EVP_DigestInit_ex failed for SHA-256");
        EVP_MD_CTX_free(ctx);
        return CRYPTO_FAIL;
    }

    if (EVP_DigestUpdate(ctx, password, passLen) != 1) {
        LOG_ERROR_SSL("EVP_DigestUpdate failed (password)");
        EVP_MD_CTX_free(ctx);
        return CRYPTO_FAIL;
    }

    if (EVP_DigestUpdate(ctx, salt, saltLen) != 1) {
        LOG_ERROR_SSL("EVP_DigestUpdate failed (salt)");
        EVP_MD_CTX_free(ctx);
        return CRYPTO_FAIL;
    }

    unsigned int digestLen = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1) {
        LOG_ERROR_SSL("EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(ctx);
        return CRYPTO_FAIL;
    }

    EVP_MD_CTX_free(ctx);
    return CRYPTO_SUCC;
}

char *hashPassword(const char *password) {
    if (password == NULL) {
        LOG_ERROR("hashPassword: password is NULL");
        return NULL;
    }

    size_t passLen = strlen(password);
    if (passLen == 0) {
        LOG_ERROR("hashPassword: password is empty");
        return NULL;
    }

    /* Generate cryptographically random salt */
    uint8_t salt[HASH_SALT_LEN];
    if (RAND_bytes(salt, HASH_SALT_LEN) != 1) {
        LOG_ERROR_SSL("hashPassword: failed to generate random salt");
        return NULL;
    }

    /* Compute SHA-256(password || salt) */
    uint8_t digest[HASH_SHA256_LEN];
    if (computePasswordHash(password, passLen, salt, HASH_SALT_LEN, digest) !=
        CRYPTO_SUCC) {
        OPENSSL_cleanse(salt, sizeof(salt));
        return NULL;
    }

    /*
     * Output format: "<salt_hex>:<hash_hex>\0"
     * Total length: HASH_SALT_LEN*2 + 1 + HASH_SHA256_LEN*2 + 1
     */
    enum { SaltHexLen = HASH_SALT_LEN * 2 };
    enum { HashHexLen = HASH_SHA256_LEN * 2 };
    enum { ResultLen = HASH_SALT_LEN * 2 + 1 + HASH_SHA256_LEN * 2 + 1 };
    char *result = malloc(ResultLen);
    if (result == NULL) {
        LOG_ERROR("hashPassword: malloc failed (errno=%d)", errno);
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(digest, sizeof(digest));
        return NULL;
    }

    bytesToHex(salt, HASH_SALT_LEN, result);
    result[SaltHexLen] = ':';
    bytesToHex(digest, HASH_SHA256_LEN, result + SaltHexLen + 1);

    /* Securely wipe intermediate sensitive data */
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(digest, sizeof(digest));

    return result;
}

int verifyPassword(const char *password, const char *storedHash) {
    if (password == NULL || storedHash == NULL) {
        LOG_ERROR("verifyPassword: NULL argument");
        return CRYPTO_FAIL;
    }

    size_t passLen = strlen(password);
    if (passLen == 0) {
        LOG_ERROR("verifyPassword: password is empty");
        return CRYPTO_FAIL;
    }

    /*
     * Expected format: "<salt_hex>:<hash_hex>"
     * salt_hex = HASH_SALT_LEN * 2 characters
     * separator = ':'
     * hash_hex = HASH_SHA256_LEN * 2 characters
     */
    enum { SaltHexLen = HASH_SALT_LEN * 2 };
    enum { HashHexLen = HASH_SHA256_LEN * 2 };
    enum { ExpectedLen = HASH_SALT_LEN * 2 + 1 + HASH_SHA256_LEN * 2 };

    size_t storedLen = strlen(storedHash);
    if (storedLen != ExpectedLen) {
        LOG_ERROR("verifyPassword: invalid storedHash length");
        return CRYPTO_FAIL;
    }

    if (storedHash[SaltHexLen] != ':') {
        LOG_ERROR("verifyPassword: missing separator in storedHash");
        return CRYPTO_FAIL;
    }

    /* Parse salt from hex */
    uint8_t salt[HASH_SALT_LEN];
    if (hexToBytes(storedHash, salt, HASH_SALT_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("verifyPassword: invalid hex in salt portion");
        return CRYPTO_FAIL;
    }

    /* Parse expected hash from hex */
    uint8_t expectedHash[HASH_SHA256_LEN];
    if (hexToBytes(storedHash + SaltHexLen + 1, expectedHash,
                   HASH_SHA256_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("verifyPassword: invalid hex in hash portion");
        OPENSSL_cleanse(salt, sizeof(salt));
        return CRYPTO_FAIL;
    }

    /* Recompute SHA-256(password || salt) */
    uint8_t computedHash[HASH_SHA256_LEN];
    if (computePasswordHash(password, passLen, salt, HASH_SALT_LEN,
                            computedHash) != CRYPTO_SUCC) {
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(expectedHash, sizeof(expectedHash));
        return CRYPTO_FAIL;
    }

    /* Constant-time comparison to prevent timing attacks */
    int match = CRYPTO_memcmp(computedHash, expectedHash, HASH_SHA256_LEN);

    /* Securely wipe all intermediate sensitive data */
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(expectedHash, sizeof(expectedHash));
    OPENSSL_cleanse(computedHash, sizeof(computedHash));

    return (match == 0) ? CRYPTO_SUCC : CRYPTO_FAIL;
}

/* ──────────────────────── Base32 (RFC 4648) ────────────────────────────── */

/** @brief RFC 4648 Base32 alphabet (uppercase A-Z + digits 2-7). */
static const char base32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

enum {
    B32AlphabetLen = 32,
    B32BitsPerChar = 5,
    B32BitsPerByte = 8,
    B32CharMask = 0x1F,
    B32ByteMask = 0xFF,
    B32DigitOffset = 26
};

/**
 * @brief Map a Base32 character to its 5-bit value (case-insensitive).
 *
 * @param c  Character to map.
 * @return 5-bit value (0-31) on success, -1 for invalid characters.
 */
static int base32CharToValue(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a';
    }
    if (c >= '2' && c <= '7') {
        return (c - '2') + B32DigitOffset;
    }
    return -1;
}

/**
 * @brief Check if a character is an ignorable whitespace character.
 *
 * Whitespace characters (ASCII space, tab, newline, carriage return) are
 * silently stripped during decoding to accommodate human-formatted input.
 *
 * @param c  Character to check.
 * @return Non-zero if @p c is whitespace, zero otherwise.
 */
static int isB32Whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

int base32Encode(const uint8_t *data, size_t len, char **outStr) {
    if (outStr == NULL) {
        return CRYPTO_FAIL;
    }
    *outStr = NULL;

    if (len > 0 && data == NULL) {
        return CRYPTO_FAIL;
    }

    size_t outLen =
        (len * B32BitsPerByte + B32BitsPerChar - 1) / B32BitsPerChar;
    char *output = malloc(outLen + 1);
    if (output == NULL) {
        LOG_ERROR("base32Encode: allocation failed");
        return CRYPTO_FAIL;
    }

    uint64_t acc = 0;
    int bits = 0;
    size_t pos = 0;

    for (size_t i = 0; i < len; i++) {
        acc = (acc << B32BitsPerByte) | data[i];
        bits += B32BitsPerByte;
        while (bits >= B32BitsPerChar) {
            bits -= B32BitsPerChar;
            output[pos++] =
                base32Alphabet[(acc >> bits) & B32CharMask];
        }
    }

    if (bits > 0) {
        output[pos++] =
            base32Alphabet[(acc << (B32BitsPerChar - bits)) & B32CharMask];
    }

    output[pos] = '\0';
    *outStr = output;
    return CRYPTO_SUCC;
}

int base32Decode(const char *encoded, uint8_t **outData, size_t *outLen) {
    if (encoded == NULL || outData == NULL || outLen == NULL) {
        if (outData != NULL) {
            *outData = NULL;
        }
        return CRYPTO_FAIL;
    }

    *outData = NULL;

    size_t charCount = 0;
    for (const char *p = encoded; *p != '\0'; p++) {
        if (isB32Whitespace(*p)) {
            continue;
        }
        if (base32CharToValue(*p) < 0) {
            LOG_ERROR("base32Decode: invalid character 0x%02x '%c'",
                      (unsigned char)*p, *p);
            return CRYPTO_FAIL;
        }
        charCount++;
    }

    if (charCount == 0) {
        *outLen = 0;
        return CRYPTO_SUCC;
    }

    size_t outBytes = (charCount * B32BitsPerChar) / B32BitsPerByte;
    if (outBytes == 0) {
        LOG_ERROR("base32Decode: input too short for one full byte "
                  "(%zu chars)",
                  charCount);
        return CRYPTO_FAIL;
    }

    uint8_t *output = malloc(outBytes);
    if (output == NULL) {
        LOG_ERROR("base32Decode: allocation failed");
        return CRYPTO_FAIL;
    }

    uint64_t acc = 0;
    int bits = 0;
    size_t pos = 0;

    for (const char *p = encoded; *p != '\0'; p++) {
        if (isB32Whitespace(*p)) {
            continue;
        }
        int val = base32CharToValue(*p);
        acc = (acc << B32BitsPerChar) | (uint64_t)val;
        bits += B32BitsPerChar;
        if (bits >= B32BitsPerByte) {
            bits -= B32BitsPerByte;
            output[pos++] = (acc >> bits) & B32ByteMask;
        }
    }

    if (bits > 0) {
        uint64_t mask = ((uint64_t)1 << bits) - 1;
        if ((acc & mask) != 0) {
            LOG_ERROR("base32Decode: non-zero padding bits detected");
            free(output);
            return CRYPTO_FAIL;
        }
    }

    *outData = output;
    *outLen = outBytes;
    return CRYPTO_SUCC;
}

/* ──────────────────────── TOTP (RFC 6238)  ──────────────────────────────── */

int verifyTOTPCode(const char *secret, int *code) {
    if (secret == NULL || code == NULL) {
        LOG_ERROR("verifyTOTPCode: NULL argument (secret=%p, code=%p)",
                  (const void *)secret, (const void *)code);
        return CRYPTO_FAIL;
    }

    uint8_t *key = NULL;
    size_t keyLen = 0;
    if (base32Decode(secret, &key, &keyLen) != CRYPTO_SUCC) {
        LOG_ERROR("verifyTOTPCode: failed to decode Base32 secret");
        return CRYPTO_FAIL;
    }

    if (keyLen < TOTP_MIN_KEY_LEN) {
        LOG_ERROR("verifyTOTPCode: decoded key too short (%zu < %d)",
                  keyLen, TOTP_MIN_KEY_LEN);
        OPENSSL_cleanse(key, keyLen);
        free(key);
        return CRYPTO_FAIL;
    }

    enum {
        CounterSizeBytes = 8,
        CounterByteMask = 0xFF,
        CounterShiftBits = 8,
        DtOffsetMask = 0x0F,
        DtMsbMask = 0x7F,
        DtByteMask = 0xFF,
        DtShift24 = 24,
        DtShift16 = 16,
        DtShift8 = 8
    };

    int64_t baseStep = (int64_t)(getCurrentTimestamp() / TOTP_STEP_SECONDS);
    int result = CRYPTO_FAIL;

    for (int64_t step = baseStep - TOTP_WINDOW;
         step <= baseStep + TOTP_WINDOW; step++) {
        uint8_t counter[CounterSizeBytes];
        uint64_t c = (uint64_t)step;
        for (int i = CounterSizeBytes - 1; i >= 0; i--) {
            counter[i] = (uint8_t)(c & CounterByteMask);
            c >>= CounterShiftBits;
        }

        uint8_t hmac[TOTP_HMAC_SHA1_LEN];
        unsigned int hmacLen = sizeof(hmac);
        if (HMAC(EVP_sha1(), key, (int)keyLen, counter, sizeof(counter), hmac,
                 &hmacLen) == NULL) {
            LOG_ERROR_SSL("verifyTOTPCode: HMAC-SHA1 failed");
            break;
        }

        int dtOffset = hmac[hmacLen - 1] & DtOffsetMask;
        int binary = ((hmac[dtOffset] & DtMsbMask) << DtShift24) |
                     ((hmac[dtOffset + 1] & DtByteMask) << DtShift16) |
                     ((hmac[dtOffset + 2] & DtByteMask) << DtShift8) |
                     (hmac[dtOffset + 3] & DtByteMask);
        if (binary % TOTP_CODE_RANGE == *code) {
            result = CRYPTO_SUCC;
            break;
        }
    }

    OPENSSL_cleanse(key, keyLen);
    free(key);
    return result;
}

/**
 * @brief Determine whether a character belongs to the unreserved set
 *        defined by RFC 3986 Section 2.3.
 *
 * Unreserved characters: A-Z a-z 0-9 - _ . ~
 *
 * @param c  Character to test.
 * @return Non-zero if @p c is unreserved, zero otherwise.
 */
static int isUnreservedURI(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
           c == '~';
}

/**
 * @brief Percent-encode a string per RFC 3986.
 *
 * Any character not in the unreserved set is encoded as @c %XX using
 * uppercase hexadecimal digits.  The caller must free the returned
 * string with @c free().
 *
 * @param str  Null-terminated input string.
 * @return Heap-allocated, null-terminated encoded string, or @c NULL
 *         on allocation failure.
 */
static char *urlEncode(const char *str) {
    static const char hexDigits[] = "0123456789ABCDEF";
    enum { PctEncodedLen = 3, NibbleBits = 4, NibbleMask = 0x0F };

    size_t inLen = strlen(str);
    size_t extra = 0;
    for (size_t i = 0; i < inLen; i++) {
        if (!isUnreservedURI(str[i])) {
            extra++;
        }
    }

    size_t outLen = inLen + extra * (PctEncodedLen - 1) + 1;
    char *out = malloc(outLen);
    if (out == NULL) {
        LOG_ERROR("urlEncode: allocation failed");
        return NULL;
    }

    size_t pos = 0;
    for (size_t i = 0; i < inLen; i++) {
        unsigned char c = (unsigned char)str[i];
        if (isUnreservedURI((char)c)) {
            out[pos++] = (char)c;
        } else {
            out[pos++] = '%';
            out[pos++] = hexDigits[(c >> NibbleBits) & NibbleMask];
            out[pos++] = hexDigits[c & NibbleMask];
        }
    }
    out[pos] = '\0';
    return out;
}

int generateOTPAuthURI(const char *secret, const char *username,
                       char **outURI) {
    if (secret == NULL || username == NULL || outURI == NULL) {
        LOG_ERROR("generateOTPAuthURI: NULL argument "
                  "(secret=%p, username=%p, outURI=%p)",
                  (const void *)secret, (const void *)username,
                  (const void *)outURI);
        return CRYPTO_FAIL;
    }
    *outURI = NULL;

    if (secret[0] == '\0') {
        LOG_ERROR("generateOTPAuthURI: secret is empty");
        return CRYPTO_FAIL;
    }

    for (const char *p = secret; *p != '\0'; p++) {
        if (base32CharToValue(*p) < 0) {
            LOG_ERROR("generateOTPAuthURI: secret contains invalid "
                      "Base32 character 0x%02x '%c'",
                      (unsigned char)*p, *p);
            return CRYPTO_FAIL;
        }
    }

    if (username[0] == '\0') {
        LOG_ERROR("generateOTPAuthURI: username is empty");
        return CRYPTO_FAIL;
    }

    static const char issuer[] = "PacPlay";
    char *encIssuer = urlEncode(issuer);
    if (encIssuer == NULL) {
        return CRYPTO_FAIL;
    }

    char *encUser = urlEncode(username);
    if (encUser == NULL) {
        free(encIssuer);
        return CRYPTO_FAIL;
    }

    /* URI template:
     * otpauth://totp/{issuer}:{user}?secret={secret}&issuer={issuer}
     *   &algorithm=SHA1&digits=6&period=30 */
    size_t uriLen = strlen("otpauth://totp/") + strlen(encIssuer) +
                    (size_t)1 /* ':' */ + strlen(encUser) +
                    strlen("?secret=") + strlen(secret) +
                    strlen("&issuer=") + strlen(encIssuer) +
                    strlen("&algorithm=SHA1") + strlen("&digits=6") +
                    strlen("&period=30") + (size_t)1 /* '\0' */;

    char *uri = malloc(uriLen);
    if (uri == NULL) {
        LOG_ERROR("generateOTPAuthURI: allocation failed");
        free(encIssuer);
        free(encUser);
        return CRYPTO_FAIL;
    }

    snprintf(uri, uriLen,
             "otpauth://totp/%s:%s?secret=%s&issuer=%s"
             "&algorithm=SHA1&digits=6&period=30",
             encIssuer, encUser, secret, encIssuer);

    free(encIssuer);
    free(encUser);

    *outURI = uri;
    return CRYPTO_SUCC;
}

/* ──────────────────────── utility ──────────────────────────────────────── */

int cryptoRandomBytes(uint8_t *buf, int len) {
    if (buf == NULL || len <= 0) {
        return CRYPTO_FAIL;
    }
    if (RAND_bytes(buf, len) != 1) {
        LOG_ERROR_SSL("Failed to generate random bytes");
        return CRYPTO_FAIL;
    }
    return CRYPTO_SUCC;
}
