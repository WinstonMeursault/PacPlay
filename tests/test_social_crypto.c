/**
 * @file test_social_crypto.c
 * @brief Cryptographic security tests for AES-256-GCM packet encryption.
 *
 * Verifies that tampering with nonce, tag, ciphertext, or using wrong keys
 * produces AUTH_FAIL. Also tests replay and truncation behaviour.
 *
 * @date 2026-06-21
 * @copyright GPLv3 License
 */

#include "crypto.h"
#include "protocol.h"
#include "test_utils.h"

#include <stdlib.h>
#include <string.h>

/* ──────────────────────────── named constants ───────────────────────────── */

enum {
    TestPayloadLen = 32,
    TestSeqID = 42,
    TestFlipByte = 0x42,
    TestFlipByte2 = 0x99,
    TestKeyByte = 0xAB
};

/* ──────────────────────────── helper functions ──────────────────────────── */

/**
 * @brief Build an encrypted packet with known plaintext, return copies of
 *        header and encrypted payload for tampering tests.
 */
static int buildEncryptedPacket(uint8_t key[AES_GCM_KEY_LEN], Packet *out) {
    uint8_t plainData[TestPayloadLen];
    memset(plainData, TestKeyByte, TestPayloadLen);

    memset(out, 0, sizeof(*out));
    if (packetInit(out, MsgFriendRequest, TestSeqID, PlaintextPacket, plainData,
                   TestPayloadLen) != PROTOCOL_SUCC) {
        return -1;
    }
    if (packetAESEncrypt(out, key) != PROTOCOL_SUCC) {
        packetClear(out);
        return -1;
    }
    return 0;
}

/**
 * @brief Create a deep copy of the encrypted packet with a mutable payload.
 */
static Packet copyEncryptedPacket(const Packet *src) {
    Packet copy;
    memset(&copy, 0, sizeof(copy));
    copy.header = src->header;
    if (src->header.payloadLength > 0 && src->payload != NULL) {
        copy.payload = malloc(src->header.payloadLength);
        if (copy.payload != NULL) {
            memcpy(copy.payload, src->payload, src->header.payloadLength);
        }
    }
    return copy;
}

/* ═══════════════════════════════ Tests ════════════════════════════════════ */

/* ── testEncryptedSocialPacketTamperedNonce ─────────────────────────────── */

static void testEncryptedSocialPacketTamperedNonce(void) {
    uint8_t key[AES_GCM_KEY_LEN];
    memset(key, TestFlipByte, AES_GCM_KEY_LEN);

    Packet original;
    memset(&original, 0, sizeof(original));
    ASSERT_INT_EQ(buildEncryptedPacket(key, &original), 0);

    ASSERT_UINT_EQ(original.header.packetType, (uint32_t)AES256GCMPacket);

    /* Copy and flip bit 0 of the nonce (byte 0 of encrypted payload). */
    Packet tampered = copyEncryptedPacket(&original);
    ASSERT_NOT_NULL(tampered.payload);
    tampered.payload[0] ^= 0x01;

    int ret = packetAESDecrypt(&tampered, key);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&tampered);

    /* Verify original can still be decrypted (was not modified). */
    ASSERT_INT_EQ(packetAESDecrypt(&original, key), PROTOCOL_SUCC);
    ASSERT_UINT_EQ(original.header.packetType, (uint32_t)PlaintextPacket);
    packetClear(&original);
}

/* ── testEncryptedSocialPacketTamperedTag ───────────────────────────────── */

static void testEncryptedSocialPacketTamperedTag(void) {
    uint8_t key[AES_GCM_KEY_LEN];
    memset(key, TestFlipByte, AES_GCM_KEY_LEN);

    Packet original;
    memset(&original, 0, sizeof(original));
    ASSERT_INT_EQ(buildEncryptedPacket(key, &original), 0);

    Packet tampered = copyEncryptedPacket(&original);
    ASSERT_NOT_NULL(tampered.payload);

    /* Flip bit 0 of the tag (last byte of encrypted payload). */
    size_t lastIdx = tampered.header.payloadLength - 1;
    tampered.payload[lastIdx] ^= 0x01;

    int ret = packetAESDecrypt(&tampered, key);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&tampered);

    ASSERT_INT_EQ(packetAESDecrypt(&original, key), PROTOCOL_SUCC);
    packetClear(&original);
}

/* ── testEncryptedSocialPacketTamperedCiphertext ────────────────────────── */

static void testEncryptedSocialPacketTamperedCiphertext(void) {
    uint8_t key[AES_GCM_KEY_LEN];
    memset(key, TestFlipByte, AES_GCM_KEY_LEN);

    Packet original;
    memset(&original, 0, sizeof(original));
    ASSERT_INT_EQ(buildEncryptedPacket(key, &original), 0);

    Packet tampered = copyEncryptedPacket(&original);
    ASSERT_NOT_NULL(tampered.payload);

    /* Flip bit 0 of the ciphertext (byte at offset AES_GCM_NONCE_LEN). */
    tampered.payload[AES_GCM_NONCE_LEN] ^= 0x01;

    int ret = packetAESDecrypt(&tampered, key);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&tampered);

    ASSERT_INT_EQ(packetAESDecrypt(&original, key), PROTOCOL_SUCC);
    packetClear(&original);
}

/* ── testEncryptedSocialPacketReplay ────────────────────────────────────── */

static void testEncryptedSocialPacketReplay(void) {
    uint8_t key[AES_GCM_KEY_LEN];
    memset(key, TestFlipByte, AES_GCM_KEY_LEN);

    Packet original;
    memset(&original, 0, sizeof(original));
    ASSERT_INT_EQ(buildEncryptedPacket(key, &original), 0);

    /*
     * Decrypt the same encrypted packet twice. The first decryption destroys
     * the packet (replaces payload with plaintext), so we must create
     * independent copies for each decrypt attempt.
     */

    Packet copy1 = copyEncryptedPacket(&original);
    ASSERT_NOT_NULL(copy1.payload);
    ASSERT_INT_EQ(packetAESDecrypt(&copy1, key), PROTOCOL_SUCC);
    packetClear(&copy1);

    Packet copy2 = copyEncryptedPacket(&original);
    ASSERT_NOT_NULL(copy2.payload);
    ASSERT_INT_EQ(packetAESDecrypt(&copy2, key), PROTOCOL_SUCC);
    packetClear(&copy2);

    packetClear(&original);
}

/* ── testEncryptedSocialPacketWrongKey ──────────────────────────────────── */

static void testEncryptedSocialPacketWrongKey(void) {
    uint8_t correctKey[AES_GCM_KEY_LEN];
    uint8_t wrongKey[AES_GCM_KEY_LEN];
    memset(correctKey, TestFlipByte, AES_GCM_KEY_LEN);
    memset(wrongKey, TestFlipByte2, AES_GCM_KEY_LEN);

    Packet original;
    memset(&original, 0, sizeof(original));
    ASSERT_INT_EQ(buildEncryptedPacket(correctKey, &original), 0);

    Packet tampered = copyEncryptedPacket(&original);
    ASSERT_NOT_NULL(tampered.payload);

    int ret = packetAESDecrypt(&tampered, wrongKey);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&tampered);

    /* Verify decrypt with correct key still works. */
    ASSERT_INT_EQ(packetAESDecrypt(&original, correctKey), PROTOCOL_SUCC);
    packetClear(&original);
}

/* ── testEncryptedSocialPacketTruncated ─────────────────────────────────── */

static void testEncryptedSocialPacketTruncated(void) {
    uint8_t key[AES_GCM_KEY_LEN];
    memset(key, TestFlipByte, AES_GCM_KEY_LEN);

    Packet original;
    memset(&original, 0, sizeof(original));
    ASSERT_INT_EQ(buildEncryptedPacket(key, &original), 0);

    /* Copy but reduce payloadLength by 1 (truncate tag). */
    Packet truncated = copyEncryptedPacket(&original);
    ASSERT_NOT_NULL(truncated.payload);
    truncated.header.payloadLength--;

    int ret = packetAESDecrypt(&truncated, key);
    /*
     * Truncation should fail — either AUTH_FAIL (tag mismatch due to
     * incorrect ciphertext length in AAD) or PROTOCOL_FAIL (payload too
     * short for even the nonce+tag).
     */
    ASSERT_TRUE(ret == PROTOCOL_AUTH_FAIL || ret == PROTOCOL_FAIL);

    packetClear(&truncated);

    /* Try a more severe truncation — only nonce, no ciphertext or tag. */
    Packet heavyTrunc = copyEncryptedPacket(&original);
    ASSERT_NOT_NULL(heavyTrunc.payload);
    heavyTrunc.header.payloadLength = AES_GCM_NONCE_LEN;

    ret = packetAESDecrypt(&heavyTrunc, key);
    ASSERT_INT_EQ(ret, PROTOCOL_FAIL);

    packetClear(&heavyTrunc);
    packetClear(&original);
}

/* ══════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    printf("test_social_crypto:\n");

    RUN_TEST(testEncryptedSocialPacketTamperedNonce);
    RUN_TEST(testEncryptedSocialPacketTamperedTag);
    RUN_TEST(testEncryptedSocialPacketTamperedCiphertext);
    RUN_TEST(testEncryptedSocialPacketReplay);
    RUN_TEST(testEncryptedSocialPacketWrongKey);
    RUN_TEST(testEncryptedSocialPacketTruncated);

    return TEST_REPORT();
}
