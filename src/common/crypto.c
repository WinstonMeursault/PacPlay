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
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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
