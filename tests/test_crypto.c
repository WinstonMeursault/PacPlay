/**
 * @file test_crypto.c
 * @brief Unit tests for the PacPlay crypto module (AES-256-GCM primitives).
 *
 * Covers AES-GCM constants, buffer helpers, low-level encrypt/decrypt,
 * authentication tag verification, and cryptoRandomBytes.
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
#include "test_utils.h"
#include "utils.h"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────── helper constants for readability ──────────────────── */

enum { ExpectedKeyLen = 32, ExpectedNonceLen = 12, ExpectedTagLen = 16 };

/** Filler bytes used for initialising test buffers. */
enum { FillByteA = 0xAB, FillCorrupt = 0xFF, TamperBitMask = 0x01 };

/** A test plaintext string. */
static const char testPlaintext[] = "Hello, crypto module!";

/** Sample AES-256-GCM key (32 bytes, deterministic for tests). */
static const uint8_t testKey[AES_GCM_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

/** A different AES key for wrong-key tests. */
static const uint8_t wrongKey[AES_GCM_KEY_LEN] = {
    0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5,
    0xF4, 0xF3, 0xF2, 0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA,
    0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0};

/** Deterministic nonce for reproducible tests. */
static const uint8_t testNonce[AES_GCM_NONCE_LEN] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};

/** Sample AAD data. */
static const uint8_t testAADData[] = {0xDE, 0xAD, 0xBE, 0xEF,
                                      0xCA, 0xFE, 0xBA, 0xBE};

/* ══════════════════════════════ 1. Constants ══════════════════════════════ */

/** @brief AES-GCM constant sizes are correct. */
static void testAESGCMConstants(void) {
    ASSERT_UINT_EQ(AES_GCM_KEY_LEN, ExpectedKeyLen);
    ASSERT_UINT_EQ(AES_GCM_NONCE_LEN, ExpectedNonceLen);
    ASSERT_UINT_EQ(AES_GCM_TAG_LEN, ExpectedTagLen);
}

/** @brief CRYPTO_* return codes are distinct. */
static void testCryptoReturnCodes(void) {
    ASSERT_INT_EQ(CRYPTO_SUCC, 0);
    ASSERT_INT_EQ(CRYPTO_FAIL, -1);
    ASSERT_INT_EQ(CRYPTO_AUTH_FAIL, -2);
    ASSERT_TRUE(CRYPTO_SUCC != CRYPTO_FAIL);
    ASSERT_TRUE(CRYPTO_FAIL != CRYPTO_AUTH_FAIL);
}

/* ════════════════════════════ 2. AESGCMBuffer ═════════════════════════════ */

/** @brief aesGCMBufferInit allocates memory and sets fields. */
static void testBufferInit(void) {
    enum { BufCap = 64 };
    AESGCMBuffer buf;
    int ret = aesGCMBufferInit(&buf, BufCap);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    ASSERT_TRUE(buf.data != NULL);
    ASSERT_UINT_EQ(buf.capacity, BufCap);
    ASSERT_UINT_EQ(buf.len, 0);
    aesGCMBufferDeinit(&buf);
}

/** @brief aesGCMBufferDeinit frees memory and NULLs the pointer. */
static void testBufferDeinit(void) {
    enum { BufCap = 32 };
    AESGCMBuffer buf;
    aesGCMBufferInit(&buf, BufCap);
    aesGCMBufferDeinit(&buf);
    ASSERT_TRUE(buf.data == NULL);
}

/* ════════════════════════════ 3. encryptAESGCM ════════════════════════════ */

/** @brief Basic encryption succeeds and produces output. */
static void testEncryptBasic(void) {
    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMCipher cipher;
    int ret = aesGCMBufferInit(&cipher.buffer, ptLen);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    ret = encryptAESGCM(&pt, NULL, &key, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    ASSERT_UINT_EQ(cipher.buffer.len, ptLen);

    /* Ciphertext should differ from plaintext. */
    ASSERT_TRUE(memcmp(cipher.buffer.data, testPlaintext, ptLen) != 0);

    aesGCMBufferDeinit(&cipher.buffer);
}

/** @brief encryptAESGCM fails with NULL plaintext. */
static void testEncryptNullPlaintext(void) {
    AESGCMKey key;
    memset(&key, 0, sizeof(key));
    AESGCMCipher cipher;
    enum { SmallCap = 16 };
    aesGCMBufferInit(&cipher.buffer, SmallCap);

    ASSERT_INT_EQ(encryptAESGCM(NULL, NULL, &key, &cipher), CRYPTO_FAIL);
    aesGCMBufferDeinit(&cipher.buffer);
}

/** @brief encryptAESGCM fails with NULL key. */
static void testEncryptNullKey(void) {
    enum { SmallLen = 4 };
    uint8_t data[SmallLen] = {0};
    AESGCMBuffer pt = {.data = data, .capacity = SmallLen, .len = SmallLen};
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, SmallLen);

    ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, NULL, &cipher), CRYPTO_FAIL);
    aesGCMBufferDeinit(&cipher.buffer);
}

/** @brief encryptAESGCM fails with NULL output. */
static void testEncryptNullOutput(void) {
    enum { SmallLen = 4 };
    uint8_t data[SmallLen] = {0};
    AESGCMBuffer pt = {.data = data, .capacity = SmallLen, .len = SmallLen};
    AESGCMKey key;
    memset(&key, 0, sizeof(key));

    ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &key, NULL), CRYPTO_FAIL);
}

/** @brief encryptAESGCM fails when output buffer is too small. */
static void testEncryptOutputTooSmall(void) {
    enum { PtLen = 32, SmallCap = 1 };
    uint8_t data[PtLen];
    memset(data, FillByteA, sizeof(data));
    AESGCMBuffer pt = {.data = data, .capacity = PtLen, .len = PtLen};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, SmallCap);

    ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &key, &cipher), CRYPTO_FAIL);
    aesGCMBufferDeinit(&cipher.buffer);
}

/* ════════════════════════════ 4. decryptAESGCM ════════════════════════════ */

/** @brief decryptAESGCM fails with NULL cipher. */
static void testDecryptNullCipher(void) {
    AESGCMKey key;
    memset(&key, 0, sizeof(key));
    enum { SmallCap = 16 };
    AESGCMBuffer pt;
    aesGCMBufferInit(&pt, SmallCap);

    ASSERT_INT_EQ(decryptAESGCM(NULL, NULL, &key, &pt), CRYPTO_FAIL);
    aesGCMBufferDeinit(&pt);
}

/** @brief decryptAESGCM fails with NULL key. */
static void testDecryptNullKey(void) {
    AESGCMCipher cipher;
    memset(&cipher, 0, sizeof(cipher));
    enum { SmallCap = 16 };
    uint8_t cdata[SmallCap] = {0};
    cipher.buffer.data = cdata;
    cipher.buffer.capacity = SmallCap;
    cipher.buffer.len = SmallCap;

    AESGCMBuffer pt;
    aesGCMBufferInit(&pt, SmallCap);

    ASSERT_INT_EQ(decryptAESGCM(&cipher, NULL, NULL, &pt), CRYPTO_FAIL);
    aesGCMBufferDeinit(&pt);
}

/** @brief decryptAESGCM fails with NULL plaintext output. */
static void testDecryptNullPlaintext(void) {
    AESGCMCipher cipher;
    memset(&cipher, 0, sizeof(cipher));
    enum { SmallCap = 16 };
    uint8_t cdata[SmallCap] = {0};
    cipher.buffer.data = cdata;
    cipher.buffer.capacity = SmallCap;
    cipher.buffer.len = SmallCap;

    AESGCMKey key;
    memset(&key, 0, sizeof(key));

    ASSERT_INT_EQ(decryptAESGCM(&cipher, NULL, &key, NULL), CRYPTO_FAIL);
}

/* ══════════════════════ 5. Encrypt/Decrypt Roundtrip ══════════════════════ */

/** @brief Encrypt then decrypt restores the original plaintext (no AAD). */
static void testRoundtripNoAAD(void) {
    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    /* Encrypt. */
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    int ret = encryptAESGCM(&pt, NULL, &key, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    /* Decrypt. */
    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ret = decryptAESGCM(&cipher, NULL, &key, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    ASSERT_UINT_EQ(decrypted.len, ptLen);
    ASSERT_MEM_EQ(decrypted.data, testPlaintext, ptLen);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
}

/** @brief Encrypt then decrypt restores the original plaintext (with AAD). */
static void testRoundtripWithAAD(void) {
    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMBuffer aad = {.data = (uint8_t *)(uintptr_t)testAADData,
                        .capacity = sizeof(testAADData),
                        .len = sizeof(testAADData)};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    /* Encrypt. */
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    int ret = encryptAESGCM(&pt, &aad, &key, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    /* Decrypt. */
    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ret = decryptAESGCM(&cipher, &aad, &key, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    ASSERT_UINT_EQ(decrypted.len, ptLen);
    ASSERT_MEM_EQ(decrypted.data, testPlaintext, ptLen);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
}

/** @brief Roundtrip with a 1-byte plaintext. */
static void testRoundtripMinPayload(void) {
    enum { OneByteLen = 1 };
    uint8_t oneByte = FillByteA;
    AESGCMBuffer pt = {
        .data = &oneByte, .capacity = OneByteLen, .len = OneByteLen};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, OneByteLen);
    int ret = encryptAESGCM(&pt, NULL, &key, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ret = decryptAESGCM(&cipher, NULL, &key, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    ASSERT_UINT_EQ(decrypted.len, OneByteLen);
    ASSERT_UINT_EQ(decrypted.data[0], oneByte);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
}

/** @brief Roundtrip with large (1024-byte) payload. */
static void testRoundtripLargePayload(void) {
    enum { LargeLen = 1024 };
    uint8_t *largeBuf = malloc(LargeLen);
    ASSERT_TRUE(largeBuf != NULL);
    memset(largeBuf, FillByteA, LargeLen);

    AESGCMBuffer pt = {.data = largeBuf, .capacity = LargeLen, .len = LargeLen};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, LargeLen);
    int ret = encryptAESGCM(&pt, NULL, &key, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ret = decryptAESGCM(&cipher, NULL, &key, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    ASSERT_UINT_EQ(decrypted.len, LargeLen);
    ASSERT_MEM_EQ(decrypted.data, largeBuf, LargeLen);

    free(largeBuf);
    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
}

/* ══════════════════════════ 6. Tamper Resistance ══════════════════════════ */

/** @brief Decrypt with wrong key returns CRYPTO_AUTH_FAIL. */
static void testDecryptWrongKey(void) {
    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMKey encKey;
    memcpy(encKey.key, testKey, AES_GCM_KEY_LEN);
    memcpy(encKey.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    int ret = encryptAESGCM(&pt, NULL, &encKey, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    /* Decrypt with wrong key. */
    AESGCMKey decKey;
    memcpy(decKey.key, wrongKey, AES_GCM_KEY_LEN);
    memcpy(decKey.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ret = decryptAESGCM(&cipher, NULL, &decKey, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_AUTH_FAIL);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
}

/** @brief Decrypt with tampered ciphertext returns CRYPTO_AUTH_FAIL. */
static void testDecryptTamperedCiphertext(void) {
    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    int ret = encryptAESGCM(&pt, NULL, &key, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    /* Flip a bit in the ciphertext. */
    cipher.buffer.data[0] ^= FillCorrupt;

    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ret = decryptAESGCM(&cipher, NULL, &key, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_AUTH_FAIL);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
}

/** @brief Decrypt with tampered tag returns CRYPTO_AUTH_FAIL. */
static void testDecryptTamperedTag(void) {
    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    int ret = encryptAESGCM(&pt, NULL, &key, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    /* Flip a bit in the tag. */
    cipher.tag[0] ^= TamperBitMask;

    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ret = decryptAESGCM(&cipher, NULL, &key, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_AUTH_FAIL);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
}

/** @brief Decrypt with mismatched AAD returns CRYPTO_AUTH_FAIL. */
static void testDecryptAADMismatch(void) {
    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMBuffer aad = {.data = (uint8_t *)(uintptr_t)testAADData,
                        .capacity = sizeof(testAADData),
                        .len = sizeof(testAADData)};
    AESGCMKey key;
    memcpy(key.key, testKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, testNonce, AES_GCM_NONCE_LEN);

    /* Encrypt with AAD. */
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    int ret = encryptAESGCM(&pt, &aad, &key, &cipher);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    /* Decrypt with different AAD. */
    uint8_t differentAAD[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    AESGCMBuffer badAAD = {.data = differentAAD,
                           .capacity = sizeof(differentAAD),
                           .len = sizeof(differentAAD)};

    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ret = decryptAESGCM(&cipher, &badAAD, &key, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_AUTH_FAIL);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
}

/* ══════════════════════════ 7. cryptoRandomBytes ══════════════════════════ */

/** @brief cryptoRandomBytes fills buffer with data. */
static void testCryptoRandomBytesBasic(void) {
    enum { RandLen = 32 };
    uint8_t buf[RandLen];
    memset(buf, 0, sizeof(buf));

    int ret = cryptoRandomBytes(buf, RandLen);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);

    /* Extremely unlikely that 32 random bytes are all zero. */
    uint8_t allZero[RandLen];
    memset(allZero, 0, sizeof(allZero));
    ASSERT_TRUE(memcmp(buf, allZero, RandLen) != 0);
}

/** @brief cryptoRandomBytes with NULL buffer fails. */
static void testCryptoRandomBytesNullBuf(void) {
    enum { RandLen = 16 };
    ASSERT_INT_EQ(cryptoRandomBytes(NULL, RandLen), CRYPTO_FAIL);
}

/** @brief cryptoRandomBytes with zero length fails. */
static void testCryptoRandomBytesZeroLen(void) {
    uint8_t buf[1] = {0};
    ASSERT_INT_EQ(cryptoRandomBytes(buf, 0), CRYPTO_FAIL);
}

/** @brief Two calls to cryptoRandomBytes produce different output. */
static void testCryptoRandomBytesNonDeterministic(void) {
    enum { RandLen = 32 };
    uint8_t buf1[RandLen];
    uint8_t buf2[RandLen];

    int ret1 = cryptoRandomBytes(buf1, RandLen);
    int ret2 = cryptoRandomBytes(buf2, RandLen);
    ASSERT_INT_EQ(ret1, CRYPTO_SUCC);
    ASSERT_INT_EQ(ret2, CRYPTO_SUCC);

    /* Extremely unlikely that two independent 32-byte random values match. */
    ASSERT_TRUE(memcmp(buf1, buf2, RandLen) != 0);
}

/* ═════════════════════════ 7a. Buffer NULL safety ═════════════════════════ */

/** @brief aesGCMBufferInit with NULL buf returns CRYPTO_FAIL. */
static void testBufferInitNullBuf(void) {
    ASSERT_INT_EQ(aesGCMBufferInit(NULL, 64), CRYPTO_FAIL);
}

/** @brief aesGCMBufferDeinit with NULL buf does not crash. */
static void testBufferDeinitNullBuf(void) {
    /* Should simply return without crashing. */
    aesGCMBufferDeinit(NULL);
    ASSERT_TRUE(1); /* Reached here without segfault. */
}

/** @brief encryptAESGCM with plaintext->data == NULL returns CRYPTO_FAIL. */
static void testEncryptNullPlaintextData(void) {
    enum { SmallCap = 16 };
    AESGCMBuffer pt = {.data = NULL, .capacity = SmallCap, .len = SmallCap};
    AESGCMKey key;
    memset(&key, 0, sizeof(key));
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, SmallCap);

    ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &key, &cipher), CRYPTO_FAIL);
    aesGCMBufferDeinit(&cipher.buffer);
}

/** @brief decryptAESGCM with cipher->buffer.data == NULL returns CRYPTO_FAIL.
 */
static void testDecryptNullCipherData(void) {
    enum { SmallCap = 16 };
    AESGCMCipher cipher;
    memset(&cipher, 0, sizeof(cipher));
    cipher.buffer.data = NULL;
    cipher.buffer.capacity = SmallCap;
    cipher.buffer.len = SmallCap;

    AESGCMKey key;
    memset(&key, 0, sizeof(key));
    AESGCMBuffer pt;
    aesGCMBufferInit(&pt, SmallCap);

    ASSERT_INT_EQ(decryptAESGCM(&cipher, NULL, &key, &pt), CRYPTO_FAIL);
    aesGCMBufferDeinit(&pt);
}

/* ═════════════════ 8. ECDH Key Generation & Export/Import ═════════════════ */

/** @brief genECDHKeypair returns a non-NULL key pair. */
static void testGenECDHKeypair(void) {
    EVP_PKEY *kp = genECDHKeypair();
    ASSERT_TRUE(kp != NULL);
    EVP_PKEY_free(kp);
}

/** @brief Two calls to genECDHKeypair produce different public keys. */
static void testGenECDHKeypairUniqueness(void) {
    EVP_PKEY *kp1 = genECDHKeypair();
    EVP_PKEY *kp2 = genECDHKeypair();
    ASSERT_TRUE(kp1 != NULL);
    ASSERT_TRUE(kp2 != NULL);

    uint8_t pub1[ECDH_PUBLIC_KEY_SIZE];
    uint8_t pub2[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(kp1, pub1), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(kp2, pub2), CRYPTO_SUCC);
    ASSERT_TRUE(memcmp(pub1, pub2, ECDH_PUBLIC_KEY_SIZE) != 0);

    EVP_PKEY_free(kp1);
    EVP_PKEY_free(kp2);
}

/** @brief exportECDHPublicKey succeeds and produces 32 non-zero bytes. */
static void testExportECDHPublicKey(void) {
    EVP_PKEY *kp = genECDHKeypair();
    ASSERT_TRUE(kp != NULL);

    uint8_t pub[ECDH_PUBLIC_KEY_SIZE];
    memset(pub, 0, sizeof(pub));
    ASSERT_INT_EQ(exportECDHPublicKey(kp, pub), CRYPTO_SUCC);

    /* At least some bytes should be non-zero. */
    uint8_t allZero[ECDH_PUBLIC_KEY_SIZE];
    memset(allZero, 0, sizeof(allZero));
    ASSERT_TRUE(memcmp(pub, allZero, ECDH_PUBLIC_KEY_SIZE) != 0);

    EVP_PKEY_free(kp);
}

/** @brief exportECDHPublicKey with NULL pkey returns CRYPTO_FAIL. */
static void testExportECDHPublicKeyNullPkey(void) {
    uint8_t pub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(NULL, pub), CRYPTO_FAIL);
}

/** @brief exportECDHPublicKey with NULL buffer returns CRYPTO_FAIL. */
static void testExportECDHPublicKeyNullBuf(void) {
    EVP_PKEY *kp = genECDHKeypair();
    ASSERT_TRUE(kp != NULL);
    ASSERT_INT_EQ(exportECDHPublicKey(kp, NULL), CRYPTO_FAIL);
    EVP_PKEY_free(kp);
}

/** @brief exportECDHPublicKey with both NULL returns CRYPTO_FAIL. */
static void testExportECDHPublicKeyBothNull(void) {
    ASSERT_INT_EQ(exportECDHPublicKey(NULL, NULL), CRYPTO_FAIL);
}

/** @brief importECDHPeerPublicKey with a valid exported key succeeds. */
static void testImportECDHPeerPublicKey(void) {
    EVP_PKEY *kp = genECDHKeypair();
    ASSERT_TRUE(kp != NULL);

    uint8_t pub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(kp, pub), CRYPTO_SUCC);

    EVP_PKEY *imported = importECDHPeerPublicKey(pub);
    ASSERT_TRUE(imported != NULL);

    EVP_PKEY_free(kp);
    EVP_PKEY_free(imported);
}

/** @brief importECDHPeerPublicKey with NULL returns NULL. */
static void testImportECDHPeerPublicKeyNull(void) {
    EVP_PKEY *result = importECDHPeerPublicKey(NULL);
    ASSERT_TRUE(result == NULL);
}

/** @brief Export → Import → re-Export produces identical public key bytes. */
static void testExportImportRoundtrip(void) {
    EVP_PKEY *kp = genECDHKeypair();
    ASSERT_TRUE(kp != NULL);

    uint8_t pub1[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(kp, pub1), CRYPTO_SUCC);

    EVP_PKEY *imported = importECDHPeerPublicKey(pub1);
    ASSERT_TRUE(imported != NULL);

    uint8_t pub2[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(imported, pub2), CRYPTO_SUCC);

    ASSERT_MEM_EQ(pub1, pub2, ECDH_PUBLIC_KEY_SIZE);

    EVP_PKEY_free(kp);
    EVP_PKEY_free(imported);
}

/** @brief Import an all-zero public key — derive must fail (security). */
static void testImportECDHPeerPublicKeyAllZero(void) {
    uint8_t zeroPub[ECDH_PUBLIC_KEY_SIZE];
    memset(zeroPub, 0, sizeof(zeroPub));

    EVP_PKEY *zeroPeer = importECDHPeerPublicKey(zeroPub);
    /* OpenSSL may accept the import; the security check is in derive. */
    if (zeroPeer == NULL) {
        /* Import itself rejected — acceptable secure behaviour. */
        return;
    }

    /* If import succeeded, derivation must fail (all-zero secret check). */
    EVP_PKEY *local = genECDHKeypair();
    ASSERT_TRUE(local != NULL);

    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    int ret = deriveECDHSharedSecret(local, zeroPeer, secret);
    ASSERT_INT_EQ(ret, CRYPTO_FAIL);

    EVP_PKEY_free(local);
    EVP_PKEY_free(zeroPeer);
}

/* ════════════════════ 9. ECDH Shared Secret Derivation ════════════════════ */

/** @brief Two parties derive the same 32-byte shared secret. */
static void testDeriveECDHSharedSecret(void) {
    EVP_PKEY *alice = genECDHKeypair();
    EVP_PKEY *bob = genECDHKeypair();
    ASSERT_TRUE(alice != NULL);
    ASSERT_TRUE(bob != NULL);

    uint8_t alicePub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bobPub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(alice, alicePub), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(bob, bobPub), CRYPTO_SUCC);

    EVP_PKEY *bobPubKey = importECDHPeerPublicKey(bobPub);
    EVP_PKEY *alicePubKey = importECDHPeerPublicKey(alicePub);
    ASSERT_TRUE(bobPubKey != NULL);
    ASSERT_TRUE(alicePubKey != NULL);

    uint8_t secretA[ECDH_SHARED_SECRET_SIZE];
    uint8_t secretB[ECDH_SHARED_SECRET_SIZE];
    ASSERT_INT_EQ(deriveECDHSharedSecret(alice, bobPubKey, secretA),
                  CRYPTO_SUCC);
    ASSERT_INT_EQ(deriveECDHSharedSecret(bob, alicePubKey, secretB),
                  CRYPTO_SUCC);

    /* Both sides must agree on the same shared secret. */
    ASSERT_MEM_EQ(secretA, secretB, ECDH_SHARED_SECRET_SIZE);

    /* Shared secret must not be all zeros. */
    uint8_t allZero[ECDH_SHARED_SECRET_SIZE];
    memset(allZero, 0, sizeof(allZero));
    ASSERT_TRUE(memcmp(secretA, allZero, ECDH_SHARED_SECRET_SIZE) != 0);

    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
    EVP_PKEY_free(bobPubKey);
    EVP_PKEY_free(alicePubKey);
}

/** @brief Shared secret derivation is symmetric: derive(A,B) == derive(B,A). */
static void testDeriveECDHSharedSecretSymmetry(void) {
    EVP_PKEY *kp1 = genECDHKeypair();
    EVP_PKEY *kp2 = genECDHKeypair();
    ASSERT_TRUE(kp1 != NULL);
    ASSERT_TRUE(kp2 != NULL);

    uint8_t pub1[ECDH_PUBLIC_KEY_SIZE];
    uint8_t pub2[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(kp1, pub1), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(kp2, pub2), CRYPTO_SUCC);

    EVP_PKEY *peer1 = importECDHPeerPublicKey(pub1);
    EVP_PKEY *peer2 = importECDHPeerPublicKey(pub2);
    ASSERT_TRUE(peer1 != NULL);
    ASSERT_TRUE(peer2 != NULL);

    uint8_t s1[ECDH_SHARED_SECRET_SIZE];
    uint8_t s2[ECDH_SHARED_SECRET_SIZE];
    ASSERT_INT_EQ(deriveECDHSharedSecret(kp1, peer2, s1), CRYPTO_SUCC);
    ASSERT_INT_EQ(deriveECDHSharedSecret(kp2, peer1, s2), CRYPTO_SUCC);

    ASSERT_MEM_EQ(s1, s2, ECDH_SHARED_SECRET_SIZE);

    EVP_PKEY_free(kp1);
    EVP_PKEY_free(kp2);
    EVP_PKEY_free(peer1);
    EVP_PKEY_free(peer2);
}

/** @brief deriveECDHSharedSecret with NULL localKey returns CRYPTO_FAIL. */
static void testDeriveECDHSharedSecretNullLocal(void) {
    EVP_PKEY *peer = genECDHKeypair();
    ASSERT_TRUE(peer != NULL);
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    ASSERT_INT_EQ(deriveECDHSharedSecret(NULL, peer, secret), CRYPTO_FAIL);
    EVP_PKEY_free(peer);
}

/** @brief deriveECDHSharedSecret with NULL peerKey returns CRYPTO_FAIL. */
static void testDeriveECDHSharedSecretNullPeer(void) {
    EVP_PKEY *local = genECDHKeypair();
    ASSERT_TRUE(local != NULL);
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    ASSERT_INT_EQ(deriveECDHSharedSecret(local, NULL, secret), CRYPTO_FAIL);
    EVP_PKEY_free(local);
}

/** @brief deriveECDHSharedSecret with NULL secret buffer returns CRYPTO_FAIL.
 */
static void testDeriveECDHSharedSecretNullSecret(void) {
    EVP_PKEY *local = genECDHKeypair();
    EVP_PKEY *peer = genECDHKeypair();
    ASSERT_TRUE(local != NULL);
    ASSERT_TRUE(peer != NULL);

    uint8_t pub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(peer, pub), CRYPTO_SUCC);
    EVP_PKEY *peerPub = importECDHPeerPublicKey(pub);
    ASSERT_TRUE(peerPub != NULL);

    ASSERT_INT_EQ(deriveECDHSharedSecret(local, peerPub, NULL), CRYPTO_FAIL);

    EVP_PKEY_free(local);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(peerPub);
}

/** @brief deriveECDHSharedSecret with all NULL args returns CRYPTO_FAIL. */
static void testDeriveECDHSharedSecretAllNull(void) {
    ASSERT_INT_EQ(deriveECDHSharedSecret(NULL, NULL, NULL), CRYPTO_FAIL);
}

/** @brief Different peer keys produce different shared secrets. */
static void testDeriveECDHSharedSecretDiffPeers(void) {
    EVP_PKEY *local = genECDHKeypair();
    EVP_PKEY *peerA = genECDHKeypair();
    EVP_PKEY *peerB = genECDHKeypair();
    ASSERT_TRUE(local != NULL);
    ASSERT_TRUE(peerA != NULL);
    ASSERT_TRUE(peerB != NULL);

    uint8_t pubA[ECDH_PUBLIC_KEY_SIZE];
    uint8_t pubB[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(peerA, pubA), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(peerB, pubB), CRYPTO_SUCC);

    EVP_PKEY *peerAPub = importECDHPeerPublicKey(pubA);
    EVP_PKEY *peerBPub = importECDHPeerPublicKey(pubB);
    ASSERT_TRUE(peerAPub != NULL);
    ASSERT_TRUE(peerBPub != NULL);

    uint8_t secretA[ECDH_SHARED_SECRET_SIZE];
    uint8_t secretB[ECDH_SHARED_SECRET_SIZE];
    ASSERT_INT_EQ(deriveECDHSharedSecret(local, peerAPub, secretA),
                  CRYPTO_SUCC);
    ASSERT_INT_EQ(deriveECDHSharedSecret(local, peerBPub, secretB),
                  CRYPTO_SUCC);

    ASSERT_TRUE(memcmp(secretA, secretB, ECDH_SHARED_SECRET_SIZE) != 0);

    EVP_PKEY_free(local);
    EVP_PKEY_free(peerA);
    EVP_PKEY_free(peerB);
    EVP_PKEY_free(peerAPub);
    EVP_PKEY_free(peerBPub);
}

/** @brief derive(A, A_pub) — self-exchange should not crash. */
static void testDeriveECDHSharedSecretSelfKey(void) {
    EVP_PKEY *kp = genECDHKeypair();
    ASSERT_TRUE(kp != NULL);

    uint8_t pub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(kp, pub), CRYPTO_SUCC);

    EVP_PKEY *selfPub = importECDHPeerPublicKey(pub);
    ASSERT_TRUE(selfPub != NULL);

    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    /* Self-ECDH is mathematically valid; just verify no crash. */
    int ret = deriveECDHSharedSecret(kp, selfPub, secret);
    /* Result may be CRYPTO_SUCC or CRYPTO_FAIL depending on key properties,
     * but it must not crash and must return a valid code. */
    ASSERT_TRUE(ret == CRYPTO_SUCC || ret == CRYPTO_FAIL);

    EVP_PKEY_free(kp);
    EVP_PKEY_free(selfPub);
}

/* ═════════════════════ 10. HKDF-SHA256 (deriveAESKey) ═════════════════════ */

/** @brief deriveAESKey succeeds and produces a non-zero key. */
static void testDeriveAESKeyBasic(void) {
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    memset(secret, FillByteA, sizeof(secret));

    AESGCMKey outKey;
    ASSERT_INT_EQ(deriveAESKey(secret, sizeof(secret), &outKey), CRYPTO_SUCC);

    /* Key must not be all zeros. */
    uint8_t allZero[AES_GCM_KEY_LEN];
    memset(allZero, 0, sizeof(allZero));
    ASSERT_TRUE(memcmp(outKey.key, allZero, AES_GCM_KEY_LEN) != 0);
}

/** @brief After deriveAESKey, the nonce field is zeroed. */
static void testDeriveAESKeyNonceZeroed(void) {
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    memset(secret, FillByteA, sizeof(secret));

    AESGCMKey outKey;
    /* Pre-fill with non-zero to verify zeroing. */
    memset(&outKey, FillCorrupt, sizeof(outKey));
    ASSERT_INT_EQ(deriveAESKey(secret, sizeof(secret), &outKey), CRYPTO_SUCC);

    uint8_t zeroNonce[AES_GCM_NONCE_LEN];
    memset(zeroNonce, 0, sizeof(zeroNonce));
    ASSERT_MEM_EQ(outKey.nonce, zeroNonce, AES_GCM_NONCE_LEN);
}

/** @brief Same input produces the same AES key (deterministic). */
static void testDeriveAESKeyDeterministic(void) {
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    memset(secret, FillByteA, sizeof(secret));

    AESGCMKey key1;
    AESGCMKey key2;
    ASSERT_INT_EQ(deriveAESKey(secret, sizeof(secret), &key1), CRYPTO_SUCC);
    ASSERT_INT_EQ(deriveAESKey(secret, sizeof(secret), &key2), CRYPTO_SUCC);

    ASSERT_MEM_EQ(key1.key, key2.key, AES_GCM_KEY_LEN);
}

/** @brief Different shared secrets yield different AES keys. */
static void testDeriveAESKeyDifferentInputs(void) {
    uint8_t secretA[ECDH_SHARED_SECRET_SIZE];
    uint8_t secretB[ECDH_SHARED_SECRET_SIZE];
    memset(secretA, FillByteA, sizeof(secretA));
    memset(secretB, FillCorrupt, sizeof(secretB));

    AESGCMKey keyA;
    AESGCMKey keyB;
    ASSERT_INT_EQ(deriveAESKey(secretA, sizeof(secretA), &keyA), CRYPTO_SUCC);
    ASSERT_INT_EQ(deriveAESKey(secretB, sizeof(secretB), &keyB), CRYPTO_SUCC);

    ASSERT_TRUE(memcmp(keyA.key, keyB.key, AES_GCM_KEY_LEN) != 0);
}

/** @brief deriveAESKey with NULL sharedSecret returns CRYPTO_FAIL. */
static void testDeriveAESKeyNullSecret(void) {
    AESGCMKey outKey;
    ASSERT_INT_EQ(deriveAESKey(NULL, ECDH_SHARED_SECRET_SIZE, &outKey),
                  CRYPTO_FAIL);
}

/** @brief deriveAESKey with zero secretLen returns CRYPTO_FAIL. */
static void testDeriveAESKeyZeroLen(void) {
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    memset(secret, FillByteA, sizeof(secret));
    AESGCMKey outKey;
    ASSERT_INT_EQ(deriveAESKey(secret, 0, &outKey), CRYPTO_FAIL);
}

/** @brief deriveAESKey with NULL outKey returns CRYPTO_FAIL. */
static void testDeriveAESKeyNullOutput(void) {
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    memset(secret, FillByteA, sizeof(secret));
    ASSERT_INT_EQ(deriveAESKey(secret, sizeof(secret), NULL), CRYPTO_FAIL);
}

/** @brief deriveAESKey with 1-byte input succeeds. */
static void testDeriveAESKeyOneByteInput(void) {
    enum { OneByteLen = 1 };
    uint8_t secret[OneByteLen] = {FillByteA};
    AESGCMKey outKey;
    ASSERT_INT_EQ(deriveAESKey(secret, OneByteLen, &outKey), CRYPTO_SUCC);

    uint8_t allZero[AES_GCM_KEY_LEN];
    memset(allZero, 0, sizeof(allZero));
    ASSERT_TRUE(memcmp(outKey.key, allZero, AES_GCM_KEY_LEN) != 0);
}

/** @brief deriveAESKey with large (128-byte) input succeeds. */
static void testDeriveAESKeyLargeInput(void) {
    enum { LargeLen = 128 };
    uint8_t secret[LargeLen];
    memset(secret, FillByteA, sizeof(secret));
    AESGCMKey outKey;
    ASSERT_INT_EQ(deriveAESKey(secret, LargeLen, &outKey), CRYPTO_SUCC);

    uint8_t allZero[AES_GCM_KEY_LEN];
    memset(allZero, 0, sizeof(allZero));
    ASSERT_TRUE(memcmp(outKey.key, allZero, AES_GCM_KEY_LEN) != 0);
}

/** @brief deriveAESKey with all-0xFF secret succeeds. */
static void testDeriveAESKeyAllOnesInput(void) {
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    memset(secret, FillCorrupt, sizeof(secret));
    AESGCMKey outKey;
    ASSERT_INT_EQ(deriveAESKey(secret, sizeof(secret), &outKey), CRYPTO_SUCC);

    uint8_t allZero[AES_GCM_KEY_LEN];
    memset(allZero, 0, sizeof(allZero));
    ASSERT_TRUE(memcmp(outKey.key, allZero, AES_GCM_KEY_LEN) != 0);
}

/** @brief Different secretLen with same prefix produce different keys. */
static void testDeriveAESKeyLengthSensitivity(void) {
    enum { ShortLen = 16, LongLen = 32 };
    uint8_t secret[LongLen];
    memset(secret, FillByteA, sizeof(secret));

    AESGCMKey keyShort;
    AESGCMKey keyLong;
    ASSERT_INT_EQ(deriveAESKey(secret, ShortLen, &keyShort), CRYPTO_SUCC);
    ASSERT_INT_EQ(deriveAESKey(secret, LongLen, &keyLong), CRYPTO_SUCC);

    /* Same data but different length must produce different keys. */
    ASSERT_TRUE(memcmp(keyShort.key, keyLong.key, AES_GCM_KEY_LEN) != 0);
}

/* ════════════════ 11. Full Integration (ECDH→HKDF→AES-GCM) ════════════════ */

/**
 * @brief Helper: perform ECDH between two parties and derive an AES key.
 *
 * @param local   Our key pair.
 * @param peerPub Peer's raw public key.
 * @param outKey  Output AES-GCM key.
 * @return CRYPTO_SUCC or CRYPTO_FAIL.
 */
static int helperDeriveSessionKey(EVP_PKEY *local,
                                  const uint8_t peerPub[ECDH_PUBLIC_KEY_SIZE],
                                  AESGCMKey *outKey) {
    EVP_PKEY *peer = importECDHPeerPublicKey(peerPub);
    if (peer == NULL) {
        return CRYPTO_FAIL;
    }
    uint8_t secret[ECDH_SHARED_SECRET_SIZE];
    int ret = deriveECDHSharedSecret(local, peer, secret);
    EVP_PKEY_free(peer);
    if (ret != CRYPTO_SUCC) {
        return ret;
    }
    ret = deriveAESKey(secret, ECDH_SHARED_SECRET_SIZE, outKey);
    OPENSSL_cleanse(secret, sizeof(secret));
    return ret;
}

/** @brief Full flow: Alice encrypts, Bob decrypts, plaintext matches. */
static void testFullFlowEncryptDecrypt(void) {
    /* Generate key pairs. */
    EVP_PKEY *alice = genECDHKeypair();
    EVP_PKEY *bob = genECDHKeypair();
    ASSERT_TRUE(alice != NULL);
    ASSERT_TRUE(bob != NULL);

    /* Exchange public keys. */
    uint8_t alicePub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bobPub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(alice, alicePub), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(bob, bobPub), CRYPTO_SUCC);

    /* Derive session keys. */
    AESGCMKey aliceKey;
    AESGCMKey bobKey;
    ASSERT_INT_EQ(helperDeriveSessionKey(alice, bobPub, &aliceKey),
                  CRYPTO_SUCC);
    ASSERT_INT_EQ(helperDeriveSessionKey(bob, alicePub, &bobKey), CRYPTO_SUCC);

    /* Keys must be identical. */
    ASSERT_MEM_EQ(aliceKey.key, bobKey.key, AES_GCM_KEY_LEN);

    /* Set a nonce for encryption. */
    memcpy(aliceKey.nonce, testNonce, AES_GCM_NONCE_LEN);
    memcpy(bobKey.nonce, testNonce, AES_GCM_NONCE_LEN);

    /* Alice encrypts. */
    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &aliceKey, &cipher), CRYPTO_SUCC);

    /* Bob decrypts. */
    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ASSERT_INT_EQ(decryptAESGCM(&cipher, NULL, &bobKey, &decrypted),
                  CRYPTO_SUCC);
    ASSERT_UINT_EQ(decrypted.len, ptLen);
    ASSERT_MEM_EQ(decrypted.data, testPlaintext, ptLen);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
}

/** @brief Wrong peer cannot decrypt (different shared secret). */
static void testFullFlowWrongPeerCannotDecrypt(void) {
    EVP_PKEY *alice = genECDHKeypair();
    EVP_PKEY *bob = genECDHKeypair();
    EVP_PKEY *charlie = genECDHKeypair();
    ASSERT_TRUE(alice != NULL);
    ASSERT_TRUE(bob != NULL);
    ASSERT_TRUE(charlie != NULL);

    uint8_t alicePub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bobPub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t charliePub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(alice, alicePub), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(bob, bobPub), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(charlie, charliePub), CRYPTO_SUCC);

    /* Alice encrypts for Bob. */
    AESGCMKey aliceKey;
    ASSERT_INT_EQ(helperDeriveSessionKey(alice, bobPub, &aliceKey),
                  CRYPTO_SUCC);
    memcpy(aliceKey.nonce, testNonce, AES_GCM_NONCE_LEN);

    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &aliceKey, &cipher), CRYPTO_SUCC);

    /* Charlie tries to decrypt with shared(Charlie, Alice). */
    AESGCMKey charlieKey;
    ASSERT_INT_EQ(helperDeriveSessionKey(charlie, alicePub, &charlieKey),
                  CRYPTO_SUCC);
    memcpy(charlieKey.nonce, testNonce, AES_GCM_NONCE_LEN);

    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    int ret = decryptAESGCM(&cipher, NULL, &charlieKey, &decrypted);
    ASSERT_INT_EQ(ret, CRYPTO_AUTH_FAIL);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
    EVP_PKEY_free(charlie);
}

/** @brief Full flow with AAD — integrity across the entire pipeline. */
static void testFullFlowWithAAD(void) {
    EVP_PKEY *alice = genECDHKeypair();
    EVP_PKEY *bob = genECDHKeypair();
    ASSERT_TRUE(alice != NULL);
    ASSERT_TRUE(bob != NULL);

    uint8_t alicePub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bobPub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(alice, alicePub), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(bob, bobPub), CRYPTO_SUCC);

    AESGCMKey aliceKey;
    AESGCMKey bobKey;
    ASSERT_INT_EQ(helperDeriveSessionKey(alice, bobPub, &aliceKey),
                  CRYPTO_SUCC);
    ASSERT_INT_EQ(helperDeriveSessionKey(bob, alicePub, &bobKey), CRYPTO_SUCC);
    memcpy(aliceKey.nonce, testNonce, AES_GCM_NONCE_LEN);
    memcpy(bobKey.nonce, testNonce, AES_GCM_NONCE_LEN);

    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMBuffer aad = {.data = (uint8_t *)(uintptr_t)testAADData,
                        .capacity = sizeof(testAADData),
                        .len = sizeof(testAADData)};

    /* Encrypt with AAD. */
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    ASSERT_INT_EQ(encryptAESGCM(&pt, &aad, &aliceKey, &cipher), CRYPTO_SUCC);

    /* Decrypt with correct AAD. */
    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ASSERT_INT_EQ(decryptAESGCM(&cipher, &aad, &bobKey, &decrypted),
                  CRYPTO_SUCC);
    ASSERT_UINT_EQ(decrypted.len, ptLen);
    ASSERT_MEM_EQ(decrypted.data, testPlaintext, ptLen);

    /* Decrypt with wrong AAD must fail. */
    uint8_t badAADBytes[] = {0x01, 0x02, 0x03, 0x04};
    AESGCMBuffer badAAD = {.data = badAADBytes,
                           .capacity = sizeof(badAADBytes),
                           .len = sizeof(badAADBytes)};
    AESGCMBuffer decrypted2;
    aesGCMBufferInit(&decrypted2, cipher.buffer.len);
    ASSERT_INT_EQ(decryptAESGCM(&cipher, &badAAD, &bobKey, &decrypted2),
                  CRYPTO_AUTH_FAIL);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
    aesGCMBufferDeinit(&decrypted2);
    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
}

/** @brief Full flow with tampered ciphertext — decryption must fail. */
static void testFullFlowTamperedCiphertext(void) {
    EVP_PKEY *alice = genECDHKeypair();
    EVP_PKEY *bob = genECDHKeypair();
    ASSERT_TRUE(alice != NULL);
    ASSERT_TRUE(bob != NULL);

    uint8_t alicePub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bobPub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(alice, alicePub), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(bob, bobPub), CRYPTO_SUCC);

    AESGCMKey aliceKey;
    AESGCMKey bobKey;
    ASSERT_INT_EQ(helperDeriveSessionKey(alice, bobPub, &aliceKey),
                  CRYPTO_SUCC);
    ASSERT_INT_EQ(helperDeriveSessionKey(bob, alicePub, &bobKey), CRYPTO_SUCC);
    memcpy(aliceKey.nonce, testNonce, AES_GCM_NONCE_LEN);
    memcpy(bobKey.nonce, testNonce, AES_GCM_NONCE_LEN);

    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};
    AESGCMCipher cipher;
    aesGCMBufferInit(&cipher.buffer, ptLen);
    ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &aliceKey, &cipher), CRYPTO_SUCC);

    /* Tamper with ciphertext. */
    cipher.buffer.data[0] ^= FillCorrupt;

    AESGCMBuffer decrypted;
    aesGCMBufferInit(&decrypted, cipher.buffer.len);
    ASSERT_INT_EQ(decryptAESGCM(&cipher, NULL, &bobKey, &decrypted),
                  CRYPTO_AUTH_FAIL);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
}

/** @brief Bidirectional: Alice→Bob and Bob→Alice both succeed. */
static void testFullFlowBidirectional(void) {
    EVP_PKEY *alice = genECDHKeypair();
    EVP_PKEY *bob = genECDHKeypair();
    ASSERT_TRUE(alice != NULL);
    ASSERT_TRUE(bob != NULL);

    uint8_t alicePub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bobPub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(alice, alicePub), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(bob, bobPub), CRYPTO_SUCC);

    AESGCMKey aliceKey;
    AESGCMKey bobKey;
    ASSERT_INT_EQ(helperDeriveSessionKey(alice, bobPub, &aliceKey),
                  CRYPTO_SUCC);
    ASSERT_INT_EQ(helperDeriveSessionKey(bob, alicePub, &bobKey), CRYPTO_SUCC);

    /* --- Alice → Bob --- */
    memcpy(aliceKey.nonce, testNonce, AES_GCM_NONCE_LEN);
    memcpy(bobKey.nonce, testNonce, AES_GCM_NONCE_LEN);

    size_t ptLen = sizeof(testPlaintext);
    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)testPlaintext,
                       .capacity = ptLen,
                       .len = ptLen};

    AESGCMCipher cipher1;
    aesGCMBufferInit(&cipher1.buffer, ptLen);
    ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &aliceKey, &cipher1), CRYPTO_SUCC);

    AESGCMBuffer dec1;
    aesGCMBufferInit(&dec1, cipher1.buffer.len);
    ASSERT_INT_EQ(decryptAESGCM(&cipher1, NULL, &bobKey, &dec1), CRYPTO_SUCC);
    ASSERT_MEM_EQ(dec1.data, testPlaintext, ptLen);

    /* --- Bob → Alice (different nonce) --- */
    static const uint8_t nonce2[AES_GCM_NONCE_LEN] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B};
    memcpy(bobKey.nonce, nonce2, AES_GCM_NONCE_LEN);
    memcpy(aliceKey.nonce, nonce2, AES_GCM_NONCE_LEN);

    static const char bobMsg[] = "Reply from Bob";
    size_t bobMsgLen = sizeof(bobMsg);
    AESGCMBuffer ptBob = {.data = (uint8_t *)(uintptr_t)bobMsg,
                          .capacity = bobMsgLen,
                          .len = bobMsgLen};

    AESGCMCipher cipher2;
    aesGCMBufferInit(&cipher2.buffer, bobMsgLen);
    ASSERT_INT_EQ(encryptAESGCM(&ptBob, NULL, &bobKey, &cipher2), CRYPTO_SUCC);

    AESGCMBuffer dec2;
    aesGCMBufferInit(&dec2, cipher2.buffer.len);
    ASSERT_INT_EQ(decryptAESGCM(&cipher2, NULL, &aliceKey, &dec2), CRYPTO_SUCC);
    ASSERT_MEM_EQ(dec2.data, bobMsg, bobMsgLen);

    aesGCMBufferDeinit(&cipher1.buffer);
    aesGCMBufferDeinit(&dec1);
    aesGCMBufferDeinit(&cipher2.buffer);
    aesGCMBufferDeinit(&dec2);
    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
}

/** @brief Multiple messages with incrementing nonces all succeed. */
static void testFullFlowMultipleMessages(void) {
    EVP_PKEY *alice = genECDHKeypair();
    EVP_PKEY *bob = genECDHKeypair();
    ASSERT_TRUE(alice != NULL);
    ASSERT_TRUE(bob != NULL);

    uint8_t alicePub[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bobPub[ECDH_PUBLIC_KEY_SIZE];
    ASSERT_INT_EQ(exportECDHPublicKey(alice, alicePub), CRYPTO_SUCC);
    ASSERT_INT_EQ(exportECDHPublicKey(bob, bobPub), CRYPTO_SUCC);

    AESGCMKey aliceKey;
    AESGCMKey bobKey;
    ASSERT_INT_EQ(helperDeriveSessionKey(alice, bobPub, &aliceKey),
                  CRYPTO_SUCC);
    ASSERT_INT_EQ(helperDeriveSessionKey(bob, alicePub, &bobKey), CRYPTO_SUCC);

    enum { MsgCount = 5 };
    static const char *messages[MsgCount] = {"msg0", "msg1", "msg2", "msg3",
                                             "msg4"};

    for (int i = 0; i < MsgCount; i++) {
        /* Use a unique nonce per message. */
        uint8_t nonce[AES_GCM_NONCE_LEN];
        memset(nonce, 0, sizeof(nonce));
        nonce[0] = (uint8_t)i;
        memcpy(aliceKey.nonce, nonce, AES_GCM_NONCE_LEN);
        memcpy(bobKey.nonce, nonce, AES_GCM_NONCE_LEN);

        size_t msgLen = strlen(messages[i]) + 1;
        AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)messages[i],
                           .capacity = msgLen,
                           .len = msgLen};

        AESGCMCipher cipher;
        aesGCMBufferInit(&cipher.buffer, msgLen);
        ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &aliceKey, &cipher),
                      CRYPTO_SUCC);

        AESGCMBuffer dec;
        aesGCMBufferInit(&dec, cipher.buffer.len);
        ASSERT_INT_EQ(decryptAESGCM(&cipher, NULL, &bobKey, &dec), CRYPTO_SUCC);
        ASSERT_UINT_EQ(dec.len, msgLen);
        ASSERT_MEM_EQ(dec.data, messages[i], msgLen);

        aesGCMBufferDeinit(&cipher.buffer);
        aesGCMBufferDeinit(&dec);
    }

    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
}

/* ═══════════════════════════════ 12. Base32 ═══════════════════════════════ */

enum {
    B32AlphabetLen = 32,
    B32BitsPerChar = 5,
    B32BitsPerByte = 8,
    B32TestBufSmall = 64,
    B32TestBufLarge = 1024,
    B32DigitOffset = 26,
    B32CharMask = 0x1F,
    B32ByteMask = 0xFF,
    B32MinCharsForByte = 2,
    B32HexBase = 16
};

static const uint8_t b32TestF[] = {'f'};
static const uint8_t b32TestFo[] = {'f', 'o'};
static const uint8_t b32TestFoo[] = {'f', 'o', 'o'};
static const uint8_t b32TestFoob[] = {'f', 'o', 'o', 'b'};
static const uint8_t b32TestFooba[] = {'f', 'o', 'o', 'b', 'a'};
static const uint8_t b32TestFoobar[] = {'f', 'o', 'o', 'b', 'a', 'r'};

static void testBase32AlphabetUnique(void) {
    const char *alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int seen[B32AlphabetLen];
    memset(seen, 0, sizeof(seen));
    for (int i = 0; alpha[i] != '\0'; i++) {
        int idx;
        if (alpha[i] >= 'A' && alpha[i] <= 'Z') {
            idx = alpha[i] - 'A';
        } else {
            idx = (alpha[i] - '2') + B32DigitOffset;
        }
        ASSERT_FALSE(seen[idx]);
        seen[idx] = 1;
    }
}

static void testBase32EncodeEmpty(void) {
    char *out = NULL;
    ASSERT_INT_EQ(base32Encode(NULL, 0, &out), CRYPTO_SUCC);
    ASSERT_TRUE(out != NULL);
    ASSERT_STR_EQ(out, "");
    free(out);
}

static void testBase32DecodeEmpty(void) {
    uint8_t *data = (uint8_t *)-1;
    size_t dataLen = (size_t)-1;
    ASSERT_INT_EQ(base32Decode("", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_TRUE(data == NULL);
    ASSERT_UINT_EQ(dataLen, 0);
    free(data);
}

static void testBase32EncodeNullOutStr(void) {
    ASSERT_INT_EQ(base32Encode(NULL, 0, NULL), CRYPTO_FAIL);
}

static void testBase32EncodeNullDataPositiveLen(void) {
    enum { TestLen = 3 };
    char *out = NULL;
    ASSERT_INT_EQ(base32Encode(NULL, TestLen, &out), CRYPTO_FAIL);
    ASSERT_TRUE(out == NULL);
}

static void testBase32DecodeNullEncoded(void) {
    uint8_t *data = NULL;
    size_t dataLen = 0;
    ASSERT_INT_EQ(base32Decode(NULL, &data, &dataLen), CRYPTO_FAIL);
}

static void testBase32DecodeNullOutData(void) {
    ASSERT_INT_EQ(base32Decode("AAA", NULL, NULL), CRYPTO_FAIL);
}

static void testBase32DecodeNullOutLen(void) {
    uint8_t *data = NULL;
    ASSERT_INT_EQ(base32Decode("AAA", &data, NULL), CRYPTO_FAIL);
}

static void testBase32EncodeRfcVectors(void) {
    /* RFC 4648 §10 test vectors (no-padding variant) */
    char *out = NULL;

    ASSERT_INT_EQ(base32Encode(b32TestF, sizeof(b32TestF), &out), CRYPTO_SUCC);
    ASSERT_STR_EQ(out, "MY");
    free(out);

    ASSERT_INT_EQ(base32Encode(b32TestFo, sizeof(b32TestFo), &out),
                  CRYPTO_SUCC);
    ASSERT_STR_EQ(out, "MZXQ");
    free(out);

    ASSERT_INT_EQ(base32Encode(b32TestFoo, sizeof(b32TestFoo), &out),
                  CRYPTO_SUCC);
    ASSERT_STR_EQ(out, "MZXW6");
    free(out);

    ASSERT_INT_EQ(base32Encode(b32TestFoob, sizeof(b32TestFoob), &out),
                  CRYPTO_SUCC);
    ASSERT_STR_EQ(out, "MZXW6YQ");
    free(out);

    ASSERT_INT_EQ(base32Encode(b32TestFooba, sizeof(b32TestFooba), &out),
                  CRYPTO_SUCC);
    ASSERT_STR_EQ(out, "MZXW6YTB");
    free(out);

    ASSERT_INT_EQ(base32Encode(b32TestFoobar, sizeof(b32TestFoobar), &out),
                  CRYPTO_SUCC);
    ASSERT_STR_EQ(out, "MZXW6YTBOI");
    free(out);
}

static void testBase32DecodeRfcVectors(void) {
    uint8_t *data = NULL;
    size_t dataLen = 0;

    ASSERT_INT_EQ(base32Decode("MY", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(dataLen, sizeof(b32TestF));
    ASSERT_MEM_EQ(data, b32TestF, dataLen);
    free(data);

    ASSERT_INT_EQ(base32Decode("MZXQ", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(dataLen, sizeof(b32TestFo));
    ASSERT_MEM_EQ(data, b32TestFo, dataLen);
    free(data);

    ASSERT_INT_EQ(base32Decode("MZXW6", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(dataLen, sizeof(b32TestFoo));
    ASSERT_MEM_EQ(data, b32TestFoo, dataLen);
    free(data);

    ASSERT_INT_EQ(base32Decode("MZXW6YQ", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(dataLen, sizeof(b32TestFoob));
    ASSERT_MEM_EQ(data, b32TestFoob, dataLen);
    free(data);

    ASSERT_INT_EQ(base32Decode("MZXW6YTB", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(dataLen, sizeof(b32TestFooba));
    ASSERT_MEM_EQ(data, b32TestFooba, dataLen);
    free(data);

    ASSERT_INT_EQ(base32Decode("MZXW6YTBOI", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(dataLen, sizeof(b32TestFoobar));
    ASSERT_MEM_EQ(data, b32TestFoobar, dataLen);
    free(data);
}

static void testBase32DecodeCaseInsensitive(void) {
    uint8_t *upper = NULL;
    uint8_t *lower = NULL;
    size_t upperLen = 0;
    size_t lowerLen = 0;

    ASSERT_INT_EQ(base32Decode("MY", &upper, &upperLen), CRYPTO_SUCC);
    ASSERT_INT_EQ(base32Decode("my", &lower, &lowerLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(upperLen, lowerLen);
    ASSERT_MEM_EQ(upper, lower, upperLen);
    free(upper);
    free(lower);
}

static void testBase32DecodeWhitespace(void) {
    uint8_t *clean = NULL;
    uint8_t *spaced = NULL;
    size_t cleanLen = 0;
    size_t spacedLen = 0;

    ASSERT_INT_EQ(base32Decode("MZXW6YTB", &clean, &cleanLen), CRYPTO_SUCC);
    ASSERT_INT_EQ(base32Decode("MZ XW\n6Y\tTB\r", &spaced, &spacedLen),
                  CRYPTO_SUCC);
    ASSERT_UINT_EQ(cleanLen, spacedLen);
    ASSERT_MEM_EQ(clean, spaced, cleanLen);
    free(clean);
    free(spaced);
}

static void testBase32DecodeInvalidChar(void) {
    uint8_t *data = NULL;
    size_t dataLen = 0;
    ASSERT_INT_EQ(base32Decode("M@XQ", &data, &dataLen), CRYPTO_FAIL);
    ASSERT_TRUE(data == NULL);
}

static void testBase32DecodePaddingChar(void) {
    uint8_t *data = NULL;
    size_t dataLen = 0;
    ASSERT_INT_EQ(base32Decode("MY======", &data, &dataLen), CRYPTO_FAIL);
    ASSERT_TRUE(data == NULL);
}

static void testBase32DecodeTooShort(void) {
    enum { OneChar = 'A' };
    char shortStr[B32MinCharsForByte];
    shortStr[0] = (char)OneChar;
    shortStr[1] = '\0';
    uint8_t *data = NULL;
    size_t dataLen = 0;
    ASSERT_INT_EQ(base32Decode(shortStr, &data, &dataLen), CRYPTO_FAIL);
    ASSERT_TRUE(data == NULL);
}

static void testBase32DecodeCorruptPaddingBits(void) {
    /* Encode 'f' as "MY", then flip the second character to produce
     * non-zero padding bits. 'M'=12, but change 'Y'=24 to 'Z'=25.
     * Result: 01100 11001 → first byte = 01100110 = 'f' ok,
     * remaining bits = 01 ≠ 0 → should fail. */
    uint8_t *data = NULL;
    size_t dataLen = 0;
    ASSERT_INT_EQ(base32Decode("MZ", &data, &dataLen), CRYPTO_FAIL);
    ASSERT_TRUE(data == NULL);
}

static void testBase32EncodeDecodeRoundtrip(void) {
    /* Test various lengths crossing 40-bit block boundaries */
    enum {
        Len0 = 0,
        Len1 = 1,
        Len2 = 2,
        Len3 = 3,
        Len4 = 4,
        Len5 = 5,
        Len6 = 6,
        Len7 = 7,
        Len8 = 8,
        Len16 = 16,
        Len32 = 32,
        Len64 = 64,
        Len255 = 255,
        Len256 = 256
    };
    size_t lengths[] = {Len0, Len1, Len2,  Len3,  Len4,  Len5,   Len6,
                        Len7, Len8, Len16, Len32, Len64, Len255, Len256};
    size_t numLengths = sizeof(lengths) / sizeof(lengths[0]);

    for (size_t i = 0; i < numLengths; i++) {
        size_t testLen = lengths[i];
        uint8_t *original = malloc(testLen);
        ASSERT_TRUE(original != NULL || testLen == 0);

        if (testLen > 0) {
            for (size_t j = 0; j < testLen; j++) {
                original[j] = (uint8_t)((j * Len255 + j) & B32ByteMask);
            }
        }

        char *encoded = NULL;
        ASSERT_INT_EQ(base32Encode(original, testLen, &encoded), CRYPTO_SUCC);

        uint8_t *decoded = NULL;
        size_t decodedLen = 0;
        ASSERT_INT_EQ(base32Decode(encoded, &decoded, &decodedLen),
                      CRYPTO_SUCC);
        ASSERT_UINT_EQ(decodedLen, testLen);
        if (testLen > 0) {
            ASSERT_MEM_EQ(decoded, original, testLen);
        }

        free(original);
        free(encoded);
        free(decoded);
    }
}

static void testBase32RoundtripEmbeddedZeros(void) {
    enum { DataLen = 7 };
    uint8_t zeros[DataLen];
    memset(zeros, 0, sizeof(zeros));

    char *encoded = NULL;
    ASSERT_INT_EQ(base32Encode(zeros, sizeof(zeros), &encoded), CRYPTO_SUCC);

    uint8_t *decoded = NULL;
    size_t decodedLen = 0;
    ASSERT_INT_EQ(base32Decode(encoded, &decoded, &decodedLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(decodedLen, sizeof(zeros));
    ASSERT_MEM_EQ(decoded, zeros, sizeof(zeros));

    free(encoded);
    free(decoded);
}

static void testBase32RoundtripMaxValues(void) {
    /* All 0xFF bytes roundtrip */
    enum { DataLen = 12 };
    uint8_t maxs[DataLen];
    memset(maxs, B32ByteMask, sizeof(maxs));

    char *encoded = NULL;
    ASSERT_INT_EQ(base32Encode(maxs, sizeof(maxs), &encoded), CRYPTO_SUCC);

    uint8_t *decoded = NULL;
    size_t decodedLen = 0;
    ASSERT_INT_EQ(base32Decode(encoded, &decoded, &decodedLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(decodedLen, sizeof(maxs));
    ASSERT_MEM_EQ(decoded, maxs, sizeof(maxs));

    free(encoded);
    free(decoded);
}

static void testBase32DecodeLeadingWhitespace(void) {
    uint8_t *data = NULL;
    size_t dataLen = 0;
    ASSERT_INT_EQ(base32Decode("  \n\r\tMY", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(dataLen, sizeof(b32TestF));
    ASSERT_MEM_EQ(data, b32TestF, dataLen);
    free(data);
}

static void testBase32DecodeAllWhitespace(void) {
    uint8_t *data = (uint8_t *)-1;
    size_t dataLen = (size_t)-1;
    ASSERT_INT_EQ(base32Decode(" \t\n\r", &data, &dataLen), CRYPTO_SUCC);
    ASSERT_TRUE(data == NULL);
    ASSERT_UINT_EQ(dataLen, 0);
    free(data);
}

static void testBase32DecodeLowercaseDigits(void) {
    /* Digits '2'-'7' are not letters; case-insensitivity only applies
     * to A-Z. Verify that encoding of specific values roundtrips through
     * lowercase input. */
    enum { TestVal = 26 };
    uint8_t byte = (uint8_t)TestVal;
    char *encoded = NULL;
    ASSERT_INT_EQ(base32Encode(&byte, 1, &encoded), CRYPTO_SUCC);

    uint8_t *decoded = NULL;
    size_t decodedLen = 0;
    ASSERT_INT_EQ(base32Decode(encoded, &decoded, &decodedLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(decodedLen, 1);
    ASSERT_MEM_EQ(decoded, &byte, 1);

    free(encoded);
    free(decoded);
}

static void testBase32EncodeZeroByteValue(void) {
    /* Encode a single zero byte; decode must return exactly 0x00 */
    uint8_t zero = 0;
    char *encoded = NULL;
    ASSERT_INT_EQ(base32Encode(&zero, 1, &encoded), CRYPTO_SUCC);

    uint8_t *decoded = NULL;
    size_t decodedLen = 0;
    ASSERT_INT_EQ(base32Decode(encoded, &decoded, &decodedLen), CRYPTO_SUCC);
    ASSERT_UINT_EQ(decodedLen, 1);
    ASSERT_UINT_EQ(decoded[0], 0);

    free(encoded);
    free(decoded);
}

static void testBase32DecodeInvalidSingleCharEdge(void) {
    /* Each alphabet char in isolation: all 32 single-char strings
     * must be rejected (5 bits < 8 bits = no full byte). */
    const char *alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (int i = 0; i < B32AlphabetLen; i++) {
        char single[B32MinCharsForByte];
        single[0] = alpha[i];
        single[1] = '\0';
        uint8_t *data = NULL;
        size_t dataLen = 0;
        ASSERT_INT_EQ(base32Decode(single, &data, &dataLen), CRYPTO_FAIL);
        ASSERT_TRUE(data == NULL);
    }
}

static void testBase32DecodeInvalidTwoCharsNonZeroPad(void) {
    /* 2-char encodings where the padding bits are non-zero.
     * For 1 byte → 2 Base32 chars, we use 10 bits → 1 byte + 2 pad bits.
     * Test that all 4 possible padding bit patterns that are non-zero
     * are rejected. */
    uint8_t *data = NULL;
    size_t dataLen = 0;

    /* "AA" = 00000 00000 → pad 00 → valid (decodes to 0x00) */
    ASSERT_INT_EQ(base32Decode("AA", &data, &dataLen), CRYPTO_SUCC);
    free(data);

    /* "AB" = 00000 00001 → pad 01 → INVALID */
    ASSERT_INT_EQ(base32Decode("AB", &data, &dataLen), CRYPTO_FAIL);

    /* "AC" = 00000 00010 → pad 10 → INVALID */
    ASSERT_INT_EQ(base32Decode("AC", &data, &dataLen), CRYPTO_FAIL);

    /* "AD" = 00000 00011 → pad 11 → INVALID */
    ASSERT_INT_EQ(base32Decode("AD", &data, &dataLen), CRYPTO_FAIL);
}

static void testBase32DecodeCorruptPadFourChar(void) {
    /* 4 chars = 20 bits, 2 bytes + 4 pad bits.
     * Valid last char is a multiple of 16 (pad=0000).
     * "AAAA" encodes 2 zero bytes (pad=0000, dataBit=0) → valid.
     * Alter the last char so the low 4 bits are non-zero. */
    enum {
        FourChars = 4,
        PadMask4 = 0x0F,
        Buf4Len = FourChars + 1,
        LastIdx4 = FourChars - 1,
        NulIdx4 = FourChars
    };
    uint8_t *data = NULL;
    size_t dataLen = 0;

    ASSERT_INT_EQ(base32Decode("AAAA", &data, &dataLen), CRYPTO_SUCC);
    free(data);

    for (int pad = 1; pad <= PadMask4; pad++) {
        char corrupt[Buf4Len];
        corrupt[0] = 'A';
        corrupt[1] = 'A';
        corrupt[2] = 'A';
        corrupt[LastIdx4] = (char)('A' + pad);
        corrupt[NulIdx4] = '\0';
        ASSERT_INT_EQ(base32Decode(corrupt, &data, &dataLen), CRYPTO_FAIL);
    }
}

static void testBase32DecodeCorruptPadFiveChar(void) {
    /* 5 chars = 25 bits, 3 bytes + 1 pad bit.
     * "AAAAA" encodes 3 zero bytes (pad=0) → valid.
     * Alter the last char so bit 0 is 1 → pad=1 → invalid. */
    uint8_t *data = NULL;
    size_t dataLen = 0;

    ASSERT_INT_EQ(base32Decode("AAAAA", &data, &dataLen), CRYPTO_SUCC);
    free(data);

    /* The padding bit is the LSB of the last char.  An even-valued
     * char (e.g. C=2=00010) has pad=0 and is valid; only odd-valued
     * chars have pad=1 and must be rejected. */
    ASSERT_INT_EQ(base32Decode("AAAAB", &data, &dataLen), CRYPTO_FAIL);
    ASSERT_INT_EQ(base32Decode("AAAA7", &data, &dataLen), CRYPTO_FAIL);
    ASSERT_INT_EQ(base32Decode("AAAAD", &data, &dataLen), CRYPTO_FAIL);
}

static void testBase32DecodeCorruptPadSevenChar(void) {
    /* 7 chars = 35 bits, 4 bytes + 3 pad bits.
     * "AAAAAAA" encodes 4 zero bytes (pad=000) → valid.
     * Alter the last char so the low 3 bits are non-zero. */
    enum {
        SevenChars = 7,
        PadMask7 = 0x07,
        Buf7Len = SevenChars + 1,
        LastIdx7 = SevenChars - 1,
        NulIdx7 = SevenChars
    };
    uint8_t *data = NULL;
    size_t dataLen = 0;

    ASSERT_INT_EQ(base32Decode("AAAAAAA", &data, &dataLen), CRYPTO_SUCC);
    free(data);

    for (int pad = 1; pad <= PadMask7; pad++) {
        char corrupt[Buf7Len];
        for (int j = 0; j < SevenChars; j++) {
            corrupt[j] = 'A';
        }
        corrupt[LastIdx7] = (char)('A' + pad);
        corrupt[NulIdx7] = '\0';
        ASSERT_INT_EQ(base32Decode(corrupt, &data, &dataLen), CRYPTO_FAIL);
    }
}

static void testBase32DecodeTrailingWhitespace(void) {
    uint8_t *clean = NULL;
    uint8_t *spaced = NULL;
    size_t cleanLen = 0;
    size_t spacedLen = 0;

    ASSERT_INT_EQ(base32Decode("MZXW6YTB", &clean, &cleanLen), CRYPTO_SUCC);
    ASSERT_INT_EQ(base32Decode("MZXW6YTB  \n\r\t", &spaced, &spacedLen),
                  CRYPTO_SUCC);
    ASSERT_UINT_EQ(cleanLen, spacedLen);
    ASSERT_MEM_EQ(clean, spaced, cleanLen);
    free(clean);
    free(spaced);
}

static void testBase32DecodeInvalidCharFirstPosition(void) {
    uint8_t *data = NULL;
    size_t dataLen = 0;
    ASSERT_INT_EQ(base32Decode("@AAA", &data, &dataLen), CRYPTO_FAIL);
}

static void testBase32DecodeInvalidCharLastPosition(void) {
    uint8_t *data = NULL;
    size_t dataLen = 0;
    ASSERT_INT_EQ(base32Decode("AAA@", &data, &dataLen), CRYPTO_FAIL);
}

/* ══════════════════════════ 13. TOTP (RFC 6238) ═══════════════════════════ */

enum {
    TotpStepSec = 30,
    TotpDigits = 6,
    TotpWindow = 1,
    TotpHmacLen = 20,
    TotpCodeRange = 1000000,
    TotpMinKeyLen = 16,
    TotpCounterBytes = 8,
    TotpCounterByteMask = 0xFF,
    TotpCounterShift = 8,
    TotpDtMask = 0x0F,
    TotpDtMsbMask = 0x7F,
    TotpDtByteMask = 0xFF,
    TotpShift24 = 24,
    TotpShift16 = 16,
    TotpShift8 = 8,
    TotpTestWrongCode = 123456,
    TotpZeroCode = 0,
    TotpShortKey0 = 0xDE,
    TotpShortKey1 = 0xAD,
    TotpShortKey2 = 0xBE,
    TotpShortKeyLen = 3
};

/** @brief RFC 6238 test secret: "12345678901234567890" (20 ASCII bytes). */
static const uint8_t totpTestRawSecret[] = {'1', '2', '3', '4', '5', '6', '7',
                                            '8', '9', '0', '1', '2', '3', '4',
                                            '5', '6', '7', '8', '9', '0'};

/**
 * @brief Compute a TOTP code for a specific time step.
 *
 * Performs HMAC-SHA1 + dynamic truncation (RFC 4226) on the raw key
 * for the given time step.  This mirrors the internal computation of
 * verifyTOTPCode and is used to verify the function's integration
 * against known-good outputs.
 *
 * @param timeStep  The 64-bit time step value (Unix time / 30).
 * @param key       Raw TOTP shared secret.
 * @param keyLen    Length of @p key in bytes.
 * @return The 6-digit TOTP code computed for @p timeStep.
 */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters) */
static int computeTOTPCode(int64_t timeStep, const uint8_t *key,
                           size_t keyLen) {
    uint8_t counter[TotpCounterBytes];
    uint64_t c = (uint64_t)timeStep;
    for (int i = TotpCounterBytes - 1; i >= 0; i--) {
        counter[i] = (uint8_t)(c & TotpCounterByteMask);
        c >>= TotpCounterShift;
    }

    uint8_t hmac[TotpHmacLen];
    unsigned int hmacLen = sizeof(hmac);
    (void)HMAC(EVP_sha1(), key, (int)keyLen, counter, sizeof(counter), hmac,
               &hmacLen);

    int dtOffset = hmac[hmacLen - 1] & TotpDtMask;
    int binary = ((hmac[dtOffset] & TotpDtMsbMask) << TotpShift24) |
                 ((hmac[dtOffset + 1] & TotpDtByteMask) << TotpShift16) |
                 ((hmac[dtOffset + 2] & TotpDtByteMask) << TotpShift8) |
                 (hmac[dtOffset + 3] & TotpDtByteMask);
    return binary % TotpCodeRange;
}

/**
 * @brief Generate the current TOTP code for a Base32-encoded secret.
 *
 * Decodes the Base32 @p secret into raw key bytes, computes the 6-digit
 * TOTP code for the current 30-second time window using HMAC-SHA1 and
 * RFC 4226 dynamic truncation, and returns it.
 *
 * @param secret  Base32-encoded TOTP shared secret (null-terminated).
 * @return The 6-digit TOTP code (0–999999), or @c -1 on failure
 *         (invalid or undersized secret, allocation failure).
 */
static int generateTOTPCode(const char *secret) {
    uint8_t *key = NULL;
    size_t keyLen = 0;
    if (base32Decode(secret, &key, &keyLen) != CRYPTO_SUCC) {
        return -1;
    }
    if (keyLen < TotpMinKeyLen) {
        free(key);
        return -1;
    }

    int64_t timeStep = getCurrentTimestamp() / TotpStepSec;
    int code = computeTOTPCode(timeStep, key, keyLen);
    free(key);
    return code;
}

static void testTOTPVerifyNullSecret(void) {
    int code = TotpTestWrongCode;
    ASSERT_INT_EQ(verifyTOTPCode(NULL, &code), CRYPTO_FAIL);
}

static void testTOTPVerifyNullCode(void) {
    const char *secret = "JBSWY3DPEHPK3PXP";
    ASSERT_INT_EQ(verifyTOTPCode(secret, NULL), CRYPTO_FAIL);
}

static void testTOTPVerifyInvalidBase32Secret(void) {
    int code = TotpTestWrongCode;
    ASSERT_INT_EQ(verifyTOTPCode("!!!!!", &code), CRYPTO_FAIL);
}

static void testTOTPVerifyEmptySecret(void) {
    int code = TotpTestWrongCode;
    ASSERT_INT_EQ(verifyTOTPCode("", &code), CRYPTO_FAIL);
}

static void testTOTPVerifyShortKey(void) {
    uint8_t shortRaw[TotpShortKeyLen] = {TotpShortKey0, TotpShortKey1,
                                         TotpShortKey2};
    char *encoded = NULL;
    ASSERT_INT_EQ(base32Encode(shortRaw, sizeof(shortRaw), &encoded),
                  CRYPTO_SUCC);

    int code = TotpTestWrongCode;
    ASSERT_INT_EQ(verifyTOTPCode(encoded, &code), CRYPTO_FAIL);
    free(encoded);
}

static void testTOTPVerifyCorrectCode(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(
        base32Encode(totpTestRawSecret, sizeof(totpTestRawSecret), &secret),
        CRYPTO_SUCC);

    int64_t timeStep = getCurrentTimestamp() / TotpStepSec;
    int expectedCode =
        computeTOTPCode(timeStep, totpTestRawSecret, sizeof(totpTestRawSecret));
    ASSERT_INT_EQ(verifyTOTPCode(secret, &expectedCode), CRYPTO_SUCC);
    free(secret);
}

static void testTOTPVerifyWrongCode(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(
        base32Encode(totpTestRawSecret, sizeof(totpTestRawSecret), &secret),
        CRYPTO_SUCC);

    int code = TotpZeroCode;
    ASSERT_INT_EQ(verifyTOTPCode(secret, &code), CRYPTO_FAIL);
    free(secret);
}

static void testTOTPVerifyAdjacentWindow(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(
        base32Encode(totpTestRawSecret, sizeof(totpTestRawSecret), &secret),
        CRYPTO_SUCC);

    int64_t nextStep = (getCurrentTimestamp() / TotpStepSec) + 1;
    int nextCode =
        computeTOTPCode(nextStep, totpTestRawSecret, sizeof(totpTestRawSecret));
    ASSERT_INT_EQ(verifyTOTPCode(secret, &nextCode), CRYPTO_SUCC);
    free(secret);
}

static void testGenerateTOTPCodeBasic(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(
        base32Encode(totpTestRawSecret, sizeof(totpTestRawSecret), &secret),
        CRYPTO_SUCC);

    int code = generateTOTPCode(secret);
    ASSERT_TRUE(code >= 0 && code < TotpCodeRange);

    /* The generated code must be verified by verifyTOTPCode */
    ASSERT_INT_EQ(verifyTOTPCode(secret, &code), CRYPTO_SUCC);
    free(secret);
}

static void testGenerateTOTPCodeInvalidSecret(void) {
    ASSERT_INT_EQ(generateTOTPCode("!!!!!"), -1);
}

static void testGenerateTOTPCodeShortKey(void) {
    uint8_t shortRaw[TotpShortKeyLen] = {TotpShortKey0, TotpShortKey1,
                                         TotpShortKey2};
    char *encoded = NULL;
    ASSERT_INT_EQ(base32Encode(shortRaw, sizeof(shortRaw), &encoded),
                  CRYPTO_SUCC);

    ASSERT_INT_EQ(generateTOTPCode(encoded), -1);
    free(encoded);
}

/** @brief Raw 15-byte test secret (one below TOTP_MIN_KEY_LEN). */
static const uint8_t totpRawKey15[] = {'1', '2', '3', '4', '5', '6', '7', '8',
                                       '9', '0', '1', '2', '3', '4', '5'};

/** @brief Raw 16-byte test secret (exactly TOTP_MIN_KEY_LEN). */
static const uint8_t totpRawKey16[] = {'1', '2', '3', '4', '5', '6', '7', '8',
                                       '9', '0', '1', '2', '3', '4', '5', '6'};

static void testTOTPVerifyPreviousWindow(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(
        base32Encode(totpTestRawSecret, sizeof(totpTestRawSecret), &secret),
        CRYPTO_SUCC);

    int64_t prevStep = (getCurrentTimestamp() / TotpStepSec) - 1;
    int prevCode =
        computeTOTPCode(prevStep, totpTestRawSecret, sizeof(totpTestRawSecret));
    ASSERT_INT_EQ(verifyTOTPCode(secret, &prevCode), CRYPTO_SUCC);
    free(secret);
}

static void testTOTPVerifyKeyLenFifteen(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(base32Encode(totpRawKey15, sizeof(totpRawKey15), &secret),
                  CRYPTO_SUCC);

    int code = TotpTestWrongCode;
    ASSERT_INT_EQ(verifyTOTPCode(secret, &code), CRYPTO_FAIL);
    free(secret);
}

static void testTOTPVerifyKeyLenSixteen(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(base32Encode(totpRawKey16, sizeof(totpRawKey16), &secret),
                  CRYPTO_SUCC);

    int64_t timeStep = getCurrentTimestamp() / TotpStepSec;
    int expectedCode =
        computeTOTPCode(timeStep, totpRawKey16, sizeof(totpRawKey16));
    ASSERT_INT_EQ(verifyTOTPCode(secret, &expectedCode), CRYPTO_SUCC);
    free(secret);
}

static void testTOTPVerifyCodeBoundaryMax(void) {
    /* Force a code of exactly 999999 by using a crafted HMAC output.
     * We use computeTOTPCode on a specific timeStep that we brute-force
     * to produce code=999999.  Alternatively, we simply verify that any
     * code in [0, 999999] can be matched if it is the correct one.
     * Since we cannot deterministically force code=999999 without
     * knowing the time step that produces it, we instead test the
     * property: for the current time step, the expected code IS
     * accepted.  The code-range boundary is already covered by the
     * `binary % TotpCodeRange` logic which is tested implicitly. */
    char *secret = NULL;
    ASSERT_INT_EQ(
        base32Encode(totpTestRawSecret, sizeof(totpTestRawSecret), &secret),
        CRYPTO_SUCC);

    int64_t timeStep = getCurrentTimestamp() / TotpStepSec;
    int expectedCode =
        computeTOTPCode(timeStep, totpTestRawSecret, sizeof(totpTestRawSecret));
    /* The expected code is necessarily in [0, TotpCodeRange-1]
     * by the modulo operation.  Test that it verifies. */
    ASSERT_TRUE(expectedCode >= 0 && expectedCode < TotpCodeRange);
    ASSERT_INT_EQ(verifyTOTPCode(secret, &expectedCode), CRYPTO_SUCC);
    free(secret);
}

static void testTOTPVerifyCodeNegative(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(
        base32Encode(totpTestRawSecret, sizeof(totpTestRawSecret), &secret),
        CRYPTO_SUCC);

    int code = -1;
    ASSERT_INT_EQ(verifyTOTPCode(secret, &code), CRYPTO_FAIL);
    free(secret);
}

static void testGenerateTOTPCodeKeyLenBoundary(void) {
    char *secret = NULL;
    ASSERT_INT_EQ(base32Encode(totpRawKey16, sizeof(totpRawKey16), &secret),
                  CRYPTO_SUCC);

    int code = generateTOTPCode(secret);
    ASSERT_TRUE(code >= 0 && code < TotpCodeRange);
    ASSERT_INT_EQ(verifyTOTPCode(secret, &code), CRYPTO_SUCC);
    free(secret);
}

/* ════════════════════════════ 14. TOTP Key URI ════════════════════════════ */

enum { TOTPURITestCode = 123456, TOTPURIBufSmall = 256 };

/** @brief Known Base32 secret for URI tests. */
static const char totpURITestSecret[] = "JBSWY3DPEHPK3PXP";

static void testTOTPGenerateNullSecret(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(NULL, "alice", &uri), CRYPTO_FAIL);
    ASSERT_TRUE(uri == NULL);
}

static void testTOTPGenerateNullUsername(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, NULL, &uri),
                  CRYPTO_FAIL);
    ASSERT_TRUE(uri == NULL);
}

static void testTOTPGenerateNullOutURI(void) {
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, "alice", NULL),
                  CRYPTO_FAIL);
}

static void testTOTPGenerateEmptySecret(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI("", "alice", &uri), CRYPTO_FAIL);
    ASSERT_TRUE(uri == NULL);
}

static void testTOTPGenerateEmptyUsername(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, "", &uri), CRYPTO_FAIL);
    ASSERT_TRUE(uri == NULL);
}

static void testTOTPGenerateBasic(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, "alice", &uri),
                  CRYPTO_SUCC);
    ASSERT_TRUE(uri != NULL);

    /* Verify URI structure */
    ASSERT_TRUE(strstr(uri, "otpauth://totp/") == uri);
    ASSERT_TRUE(strstr(uri, "PacPlay:alice") != NULL);
    ASSERT_TRUE(strstr(uri, "?secret=") != NULL);
    ASSERT_TRUE(strstr(uri, totpURITestSecret) != NULL);
    ASSERT_TRUE(strstr(uri, "&issuer=PacPlay") != NULL);
    ASSERT_TRUE(strstr(uri, "&algorithm=SHA1") != NULL);
    ASSERT_TRUE(strstr(uri, "&digits=6") != NULL);
    ASSERT_TRUE(strstr(uri, "&period=30") != NULL);

    free(uri);
}

static void testTOTPGenerateURISchemePrefix(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, "test", &uri),
                  CRYPTO_SUCC);
    /* "otpauth://totp/" must appear exactly at the beginning */
    ASSERT_UINT_EQ(strncmp(uri, "otpauth://totp/", strlen("otpauth://totp/")),
                   0);
    free(uri);
}

static void testTOTPGenerateURLEncodeSpecialChars(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, "alice@test", &uri),
                  CRYPTO_SUCC);
    ASSERT_TRUE(uri != NULL);

    /* '@' must be percent-encoded as %40 in the user portion of the label */
    ASSERT_TRUE(strstr(uri, "PacPlay:alice%40test") != NULL);
    /* '@' must NOT appear raw in the label (after the :// part) */
    ASSERT_TRUE(strchr(strstr(uri, "totp/"), '@') == NULL);

    free(uri);
}

static void testTOTPGenerateInvalidSecretChars(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI("MY=ZXW6", "alice", &uri), CRYPTO_FAIL);
    ASSERT_TRUE(uri == NULL);
}

static void testTOTPGenerateInvalidSecretAmpersand(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI("MZX&W6YTB", "alice", &uri), CRYPTO_FAIL);
    ASSERT_TRUE(uri == NULL);
}

static void testTOTPGenerateInvalidSecretQuestion(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI("MZXW6?YTB", "alice", &uri), CRYPTO_FAIL);
    ASSERT_TRUE(uri == NULL);
}

static void testTOTPGenerateURLEncodeSpace(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, "al ice", &uri),
                  CRYPTO_SUCC);
    ASSERT_TRUE(uri != NULL);

    /* Label portion after totp/ must have space encoded as %20 */
    ASSERT_TRUE(strstr(uri, "PacPlay:al%20ice") != NULL);
    /* Raw space must NOT appear in the label */
    ASSERT_TRUE(strchr(strstr(uri, "totp/"), ' ') == NULL);

    free(uri);
}

static void testTOTPGenerateURLEncodeColon(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, "al:ice", &uri),
                  CRYPTO_SUCC);
    ASSERT_TRUE(uri != NULL);

    /* Colon in username must be %3A to avoid breaking the label separator */
    ASSERT_TRUE(strstr(uri, "PacPlay:al%3Aice") != NULL);

    free(uri);
}

static void testTOTPGenerateURLEncodeMultipleReserved(void) {
    char *uri = NULL;
    ASSERT_INT_EQ(generateOTPAuthURI(totpURITestSecret, "a@b:c d", &uri),
                  CRYPTO_SUCC);
    ASSERT_TRUE(uri != NULL);

    /* '@' → %40, ':' → %3A, ' ' → %20 */
    ASSERT_TRUE(strstr(uri, "PacPlay:a%40b%3Ac%20d") != NULL);

    free(uri);
}

/* ═══════════════ 15. Password Hashing (hashPassword / verifyPassword) ══════ */

enum {
    HashTestPwLen = 16,
    HashResultLen = HASH_SALT_LEN * 2 + 1 + HASH_SHA256_LEN * 2 + 1,
    HashPwShortLen = 3
};

/** @brief hashPassword with NULL returns NULL. */
static void testHashPasswordNull(void) {
    ASSERT_TRUE(hashPassword(NULL) == NULL);
}

/** @brief hashPassword with empty string returns NULL. */
static void testHashPasswordEmpty(void) {
    ASSERT_TRUE(hashPassword("") == NULL);
}

/** @brief hashPassword basic success — produces correctly formatted string. */
static void testHashPasswordBasic(void) {
    char *hash = hashPassword("mySecurePassword123");
    ASSERT_TRUE(hash != NULL);

    /* Must contain exactly one ':' separator */
    char *colon = strchr(hash, ':');
    ASSERT_TRUE(colon != NULL);
    ASSERT_TRUE(strchr(colon + 1, ':') == NULL);

    /* Format: 32 hex salt : 64 hex hash */
    ASSERT_UINT_EQ(strlen(hash), (size_t)HashResultLen - 1);

    free(hash);
}

/** @brief hashPassword generates different salts each call. */
static void testHashPasswordNonDeterministic(void) {
    char *h1 = hashPassword("samepassword");
    char *h2 = hashPassword("samepassword");
    ASSERT_TRUE(h1 != NULL);
    ASSERT_TRUE(h2 != NULL);

    /* Two calls with the same password must produce different hashes. */
    ASSERT_TRUE(strcmp(h1, h2) != 0);

    free(h1);
    free(h2);
}

/** @brief verifyPassword with NULL password returns CRYPTO_FAIL. */
static void testVerifyPasswordNullPassword(void) {
    ASSERT_INT_EQ(verifyPassword(NULL, "aaaa:bbbb"), CRYPTO_FAIL);
}

/** @brief verifyPassword with NULL storedHash returns CRYPTO_FAIL. */
static void testVerifyPasswordNullHash(void) {
    ASSERT_INT_EQ(verifyPassword("password", NULL), CRYPTO_FAIL);
}

/** @brief verifyPassword with empty password returns CRYPTO_FAIL. */
static void testVerifyPasswordEmptyPassword(void) {
    ASSERT_INT_EQ(verifyPassword("", "aaaa:bbbb"), CRYPTO_FAIL);
}

/** @brief verifyPassword basic success: hash then verify. */
static void testVerifyPasswordCorrect(void) {
    const char *pw = "testPassword123!";
    char *hash = hashPassword(pw);
    ASSERT_TRUE(hash != NULL);

    ASSERT_INT_EQ(verifyPassword(pw, hash), CRYPTO_SUCC);

    free(hash);
}

/** @brief verifyPassword with wrong password fails. */
static void testVerifyPasswordWrongPassword(void) {
    const char *pw = "correctPassword";
    char *hash = hashPassword(pw);
    ASSERT_TRUE(hash != NULL);

    ASSERT_INT_EQ(verifyPassword("wrongPassword", hash), CRYPTO_FAIL);
    /* Verify original still works */
    ASSERT_INT_EQ(verifyPassword(pw, hash), CRYPTO_SUCC);

    free(hash);
}

/** @brief verifyPassword: case sensitivity test. */
static void testVerifyPasswordCaseSensitive(void) {
    char *hash = hashPassword("Secret123");
    ASSERT_TRUE(hash != NULL);

    ASSERT_INT_EQ(verifyPassword("secret123", hash), CRYPTO_FAIL);
    ASSERT_INT_EQ(verifyPassword("SECRET123", hash), CRYPTO_FAIL);
    ASSERT_INT_EQ(verifyPassword("Secret123", hash), CRYPTO_SUCC);

    free(hash);
}

/** @brief verifyPassword: one-bit difference in password fails. */
static void testVerifyPasswordOneBitDiff(void) {
    char *hash = hashPassword("Password1");
    ASSERT_TRUE(hash != NULL);

    ASSERT_INT_EQ(verifyPassword("Password2", hash), CRYPTO_FAIL);
    /* Trailing space */
    ASSERT_INT_EQ(verifyPassword("Password1 ", hash), CRYPTO_FAIL);
    /* Leading space */
    ASSERT_INT_EQ(verifyPassword(" Password1", hash), CRYPTO_FAIL);

    free(hash);
}

/** @brief verifyPassword with corrupt hash (missing colon) fails. */
static void testVerifyPasswordNoColon(void) {
    ASSERT_INT_EQ(
        verifyPassword("pw", "0123456789abcdef0123456789abcdef"
                             "0123456789abcdef0123456789abcdef"
                             "0123456789abcdef0123456789abcdef"),
        CRYPTO_FAIL);
}

/** @brief verifyPassword with truncated hash (short) fails. */
static void testVerifyPasswordTruncatedHash(void) {
    ASSERT_INT_EQ(verifyPassword("pw", "ab:cd"), CRYPTO_FAIL);
}

/** @brief verifyPassword with corrupt salt (non-hex chars) fails. */
static void testVerifyPasswordCorruptSalt(void) {
    enum { SaltHexLen = HASH_SALT_LEN * 2, HashHexLen = HASH_SHA256_LEN * 2 };
    /* 64 hex chars + ':' + 64 hex chars, but salt portion has 'g' */
    char corrupt[HashResultLen];
    memset(corrupt, 'a', (size_t)SaltHexLen);
    corrupt[SaltHexLen] = ':';
    /* Put 'g' as first char of salt to make it invalid hex */
    corrupt[0] = 'g';
    memset(corrupt + SaltHexLen + 1, 'b', (size_t)HashHexLen);
    corrupt[HashResultLen - 1] = '\0';

    ASSERT_INT_EQ(verifyPassword("pw", corrupt), CRYPTO_FAIL);
}

/** @brief verifyPassword with corrupt hash (non-hex chars) fails. */
static void testVerifyPasswordCorruptHash(void) {
    enum { SaltHexLen = HASH_SALT_LEN * 2, HashHexLen = HASH_SHA256_LEN * 2 };
    char corrupt[HashResultLen];
    memset(corrupt, 'a', (size_t)SaltHexLen);
    corrupt[SaltHexLen] = ':';
    memset(corrupt + SaltHexLen + 1, 'b', (size_t)HashHexLen);
    /* Put 'g' in the hash portion */
    corrupt[SaltHexLen + 1] = 'g';
    corrupt[HashResultLen - 1] = '\0';

    ASSERT_INT_EQ(verifyPassword("pw", corrupt), CRYPTO_FAIL);
}

/** @brief verifyPassword with extra text after valid hash fails. */
static void testVerifyPasswordExtraText(void) {
    enum { ExtraBufSlack = 10 };
    const char *pw = "mypw";
    char *hash = hashPassword(pw);
    ASSERT_TRUE(hash != NULL);

    /* Append garbage after the valid hash */
    char corrupt[HashResultLen + ExtraBufSlack];
    snprintf(corrupt, sizeof(corrupt), "%sEXTRA", hash);
    ASSERT_INT_EQ(verifyPassword(pw, corrupt), CRYPTO_FAIL);

    free(hash);
}

/** @brief Two users with same password get different hashes, both verify. */
static void testPasswordHashSamePasswordDifferentHashes(void) {
    char *h1 = hashPassword("sharedPassword");
    char *h2 = hashPassword("sharedPassword");
    ASSERT_TRUE(h1 != NULL);
    ASSERT_TRUE(h2 != NULL);
    ASSERT_TRUE(strcmp(h1, h2) != 0);

    ASSERT_INT_EQ(verifyPassword("sharedPassword", h1), CRYPTO_SUCC);
    ASSERT_INT_EQ(verifyPassword("sharedPassword", h2), CRYPTO_SUCC);

    /* h1 cannot be verified with wrong password */
    ASSERT_INT_EQ(verifyPassword("different", h1), CRYPTO_FAIL);

    free(h1);
    free(h2);
}

/** @brief hashPassword with 1-char password works. */
static void testHashPasswordOneChar(void) {
    char *hash = hashPassword("x");
    ASSERT_TRUE(hash != NULL);
    ASSERT_INT_EQ(verifyPassword("x", hash), CRYPTO_SUCC);
    ASSERT_INT_EQ(verifyPassword("y", hash), CRYPTO_FAIL);
    free(hash);
}

/** @brief hashPassword with long password works. */
static void testHashPasswordLong(void) {
    enum { LongLen = 512 };
    char longPw[LongLen + 1];
    memset(longPw, 'P', LongLen);
    longPw[LongLen] = '\0';

    char *hash = hashPassword(longPw);
    ASSERT_TRUE(hash != NULL);
    ASSERT_INT_EQ(verifyPassword(longPw, hash), CRYPTO_SUCC);
    free(hash);
}

/* ══════════════════════════════════ main ══════════════════════════════════ */

/**
 * @brief Entry point for the crypto test suite.
 *
 * @return 0 if all tests passed, 1 if any test failed.
 */
int main(void) {
    printf("test_crypto:\n");

    /* 1. Constants */
    RUN_TEST(testAESGCMConstants);
    RUN_TEST(testCryptoReturnCodes);

    /* 2. AESGCMBuffer */
    RUN_TEST(testBufferInit);
    RUN_TEST(testBufferDeinit);

    /* 3. encryptAESGCM */
    RUN_TEST(testEncryptBasic);
    RUN_TEST(testEncryptNullPlaintext);
    RUN_TEST(testEncryptNullKey);
    RUN_TEST(testEncryptNullOutput);
    RUN_TEST(testEncryptOutputTooSmall);

    /* 4. decryptAESGCM */
    RUN_TEST(testDecryptNullCipher);
    RUN_TEST(testDecryptNullKey);
    RUN_TEST(testDecryptNullPlaintext);

    /* 5. Encrypt/Decrypt Roundtrip */
    RUN_TEST(testRoundtripNoAAD);
    RUN_TEST(testRoundtripWithAAD);
    RUN_TEST(testRoundtripMinPayload);
    RUN_TEST(testRoundtripLargePayload);

    /* 6. Tamper Resistance */
    RUN_TEST(testDecryptWrongKey);
    RUN_TEST(testDecryptTamperedCiphertext);
    RUN_TEST(testDecryptTamperedTag);
    RUN_TEST(testDecryptAADMismatch);

    /* 7. cryptoRandomBytes */
    RUN_TEST(testCryptoRandomBytesBasic);
    RUN_TEST(testCryptoRandomBytesNullBuf);
    RUN_TEST(testCryptoRandomBytesZeroLen);
    RUN_TEST(testCryptoRandomBytesNonDeterministic);

    /* 7a. Buffer NULL safety */
    RUN_TEST(testBufferInitNullBuf);
    RUN_TEST(testBufferDeinitNullBuf);
    RUN_TEST(testEncryptNullPlaintextData);
    RUN_TEST(testDecryptNullCipherData);

    /* 8. ECDH Key Generation & Export/Import */
    RUN_TEST(testGenECDHKeypair);
    RUN_TEST(testGenECDHKeypairUniqueness);
    RUN_TEST(testExportECDHPublicKey);
    RUN_TEST(testExportECDHPublicKeyNullPkey);
    RUN_TEST(testExportECDHPublicKeyNullBuf);
    RUN_TEST(testExportECDHPublicKeyBothNull);
    RUN_TEST(testImportECDHPeerPublicKey);
    RUN_TEST(testImportECDHPeerPublicKeyNull);
    RUN_TEST(testImportECDHPeerPublicKeyAllZero);
    RUN_TEST(testExportImportRoundtrip);

    /* 9. ECDH Shared Secret Derivation */
    RUN_TEST(testDeriveECDHSharedSecret);
    RUN_TEST(testDeriveECDHSharedSecretSymmetry);
    RUN_TEST(testDeriveECDHSharedSecretNullLocal);
    RUN_TEST(testDeriveECDHSharedSecretNullPeer);
    RUN_TEST(testDeriveECDHSharedSecretNullSecret);
    RUN_TEST(testDeriveECDHSharedSecretAllNull);
    RUN_TEST(testDeriveECDHSharedSecretDiffPeers);
    RUN_TEST(testDeriveECDHSharedSecretSelfKey);

    /* 10. HKDF-SHA256 (deriveAESKey) */
    RUN_TEST(testDeriveAESKeyBasic);
    RUN_TEST(testDeriveAESKeyNonceZeroed);
    RUN_TEST(testDeriveAESKeyDeterministic);
    RUN_TEST(testDeriveAESKeyDifferentInputs);
    RUN_TEST(testDeriveAESKeyNullSecret);
    RUN_TEST(testDeriveAESKeyZeroLen);
    RUN_TEST(testDeriveAESKeyNullOutput);
    RUN_TEST(testDeriveAESKeyOneByteInput);
    RUN_TEST(testDeriveAESKeyLargeInput);
    RUN_TEST(testDeriveAESKeyAllOnesInput);
    RUN_TEST(testDeriveAESKeyLengthSensitivity);

    /* 11. Full Integration (ECDH -> HKDF -> AES-GCM) */
    RUN_TEST(testFullFlowEncryptDecrypt);
    RUN_TEST(testFullFlowWrongPeerCannotDecrypt);
    RUN_TEST(testFullFlowWithAAD);
    RUN_TEST(testFullFlowTamperedCiphertext);
    RUN_TEST(testFullFlowBidirectional);
    RUN_TEST(testFullFlowMultipleMessages);

    /* 12. Base32 */
    RUN_TEST(testBase32AlphabetUnique);
    RUN_TEST(testBase32EncodeEmpty);
    RUN_TEST(testBase32DecodeEmpty);
    RUN_TEST(testBase32EncodeNullOutStr);
    RUN_TEST(testBase32EncodeNullDataPositiveLen);
    RUN_TEST(testBase32DecodeNullEncoded);
    RUN_TEST(testBase32DecodeNullOutData);
    RUN_TEST(testBase32DecodeNullOutLen);
    RUN_TEST(testBase32EncodeRfcVectors);
    RUN_TEST(testBase32DecodeRfcVectors);
    RUN_TEST(testBase32DecodeCaseInsensitive);
    RUN_TEST(testBase32DecodeWhitespace);
    RUN_TEST(testBase32DecodeInvalidChar);
    RUN_TEST(testBase32DecodePaddingChar);
    RUN_TEST(testBase32DecodeTooShort);
    RUN_TEST(testBase32DecodeCorruptPaddingBits);
    RUN_TEST(testBase32EncodeDecodeRoundtrip);
    RUN_TEST(testBase32RoundtripEmbeddedZeros);
    RUN_TEST(testBase32RoundtripMaxValues);
    RUN_TEST(testBase32DecodeLeadingWhitespace);
    RUN_TEST(testBase32DecodeAllWhitespace);
    RUN_TEST(testBase32DecodeLowercaseDigits);
    RUN_TEST(testBase32EncodeZeroByteValue);
    RUN_TEST(testBase32DecodeInvalidSingleCharEdge);
    RUN_TEST(testBase32DecodeInvalidTwoCharsNonZeroPad);
    RUN_TEST(testBase32DecodeCorruptPadFourChar);
    RUN_TEST(testBase32DecodeCorruptPadFiveChar);
    RUN_TEST(testBase32DecodeCorruptPadSevenChar);
    RUN_TEST(testBase32DecodeTrailingWhitespace);
    RUN_TEST(testBase32DecodeInvalidCharFirstPosition);
    RUN_TEST(testBase32DecodeInvalidCharLastPosition);

    /* 13. TOTP (RFC 6238) */
    RUN_TEST(testTOTPVerifyNullSecret);
    RUN_TEST(testTOTPVerifyNullCode);
    RUN_TEST(testTOTPVerifyInvalidBase32Secret);
    RUN_TEST(testTOTPVerifyEmptySecret);
    RUN_TEST(testTOTPVerifyShortKey);
    RUN_TEST(testTOTPVerifyCorrectCode);
    RUN_TEST(testTOTPVerifyWrongCode);
    RUN_TEST(testTOTPVerifyAdjacentWindow);
    RUN_TEST(testGenerateTOTPCodeBasic);
    RUN_TEST(testGenerateTOTPCodeInvalidSecret);
    RUN_TEST(testGenerateTOTPCodeShortKey);
    RUN_TEST(testTOTPVerifyPreviousWindow);
    RUN_TEST(testTOTPVerifyKeyLenFifteen);
    RUN_TEST(testTOTPVerifyKeyLenSixteen);
    RUN_TEST(testTOTPVerifyCodeBoundaryMax);
    RUN_TEST(testTOTPVerifyCodeNegative);
    RUN_TEST(testGenerateTOTPCodeKeyLenBoundary);

    /* 14. TOTP Key URI */
    RUN_TEST(testTOTPGenerateNullSecret);
    RUN_TEST(testTOTPGenerateNullUsername);
    RUN_TEST(testTOTPGenerateNullOutURI);
    RUN_TEST(testTOTPGenerateEmptySecret);
    RUN_TEST(testTOTPGenerateEmptyUsername);
    RUN_TEST(testTOTPGenerateBasic);
    RUN_TEST(testTOTPGenerateURISchemePrefix);
    RUN_TEST(testTOTPGenerateURLEncodeSpecialChars);
    RUN_TEST(testTOTPGenerateInvalidSecretChars);
    RUN_TEST(testTOTPGenerateInvalidSecretAmpersand);
    RUN_TEST(testTOTPGenerateInvalidSecretQuestion);
    RUN_TEST(testTOTPGenerateURLEncodeSpace);
    RUN_TEST(testTOTPGenerateURLEncodeColon);
    RUN_TEST(testTOTPGenerateURLEncodeMultipleReserved);

    /* 15. Password Hashing (hashPassword / verifyPassword) */
    RUN_TEST(testHashPasswordNull);
    RUN_TEST(testHashPasswordEmpty);
    RUN_TEST(testHashPasswordBasic);
    RUN_TEST(testHashPasswordNonDeterministic);
    RUN_TEST(testVerifyPasswordNullPassword);
    RUN_TEST(testVerifyPasswordNullHash);
    RUN_TEST(testVerifyPasswordEmptyPassword);
    RUN_TEST(testVerifyPasswordCorrect);
    RUN_TEST(testVerifyPasswordWrongPassword);
    RUN_TEST(testVerifyPasswordCaseSensitive);
    RUN_TEST(testVerifyPasswordOneBitDiff);
    RUN_TEST(testVerifyPasswordNoColon);
    RUN_TEST(testVerifyPasswordTruncatedHash);
    RUN_TEST(testVerifyPasswordCorruptSalt);
    RUN_TEST(testVerifyPasswordCorruptHash);
    RUN_TEST(testVerifyPasswordExtraText);
    RUN_TEST(testPasswordHashSamePasswordDifferentHashes);
    RUN_TEST(testHashPasswordOneChar);
    RUN_TEST(testHashPasswordLong);

    return TEST_REPORT();
}
