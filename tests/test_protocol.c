/**
 * @file test_protocol.c
 * @brief Comprehensive unit tests for the PacPlay protocol module.
 *
 * Covers struct layout, constants, enums, packetClear, serialize/deserialize,
 * AES-256-GCM encrypt/decrypt, socket setup/close, and packet send/recv over
 * a real socketpair.
 *
 * @date 2026-05-17
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

#include "protocol.h"
#include "test_utils.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ───────────── helper constants for readability ────────────────────────── */

enum {
    /** Expected PacketHeader total size (packed, fixed-width types). */
    ExpectedHeaderSize = sizeof(uint32_t) * 5,

    /** Individual field sizes for offset computation. */
    MagicFieldSize = sizeof(uint32_t),
    PacketTypeFieldSize = sizeof(uint32_t),
    MessageTypeFieldSize = sizeof(uint32_t),
    PayloadLenFieldSize = sizeof(uint32_t),

    /** Expected field offsets (packed). */
    ExpectedMagicOffset = 0,
    ExpectedPacketTypeOffset = MagicFieldSize,
    ExpectedMessageTypeOffset = MagicFieldSize + PacketTypeFieldSize,
    ExpectedPayloadLenOffset =
        MagicFieldSize + PacketTypeFieldSize + MessageTypeFieldSize,
    ExpectedSeqIDOffset = MagicFieldSize + PacketTypeFieldSize +
                          MessageTypeFieldSize + PayloadLenFieldSize
};

/** Buffer large enough for any serialized packet in the tests. */
enum { TestSerBufSize = 2048 };

/** Filler bytes used for initialising test buffers. */
enum {
    FillByteA = 0xAB,
    FillByteB = 0x42,
    FillByteC = 0xCD,
    FillCorrupt = 0xFF,
    FillTamper = 0x55
};

/** Indices into a socketpair() result array. */
enum { SockPairA = 0, SockPairB = 1, SockPairLen = 2 };

/** Bit flip mask applied when tampering with a single byte. */
enum { TamperBitMask = 0x01 };

/** A clearly-invalid magic value used in negative socket-recv tests. */
enum { InvalidMagicValue = 0xBADBAD00U };

/** A sample payload string used across multiple tests. */
static const char testPayloadStr[] = "Hello, PacPlay!";

/** Sample AES-256-GCM key (32 bytes, deterministic for tests). */
static const uint8_t testAESKey[AES_GCM_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

/** A different AES key for wrong-key tests. */
static const uint8_t wrongAESKey[AES_GCM_KEY_LEN] = {
    0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5,
    0xF4, 0xF3, 0xF2, 0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA,
    0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0};

/* ───────────── helpers ───────────────────────────────────────────────── */

/**
 * @brief Create a heap-allocated plaintext Packet for testing.
 *
 * The caller must call packetClear() when done.
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static Packet makeTestPacket(MessageType msgType, uint32_t seqID,
                             const void *data, size_t dataLen) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = PACKET_MAGIC;
    pkt.header.packetType = PlaintextPacket;
    pkt.header.messageType = msgType;
    pkt.header.payloadLength = dataLen;
    pkt.header.sequenceID = seqID;

    if (dataLen > 0 && data != NULL) {
        pkt.payload = malloc(dataLen);
        memcpy(pkt.payload, data, dataLen);
    } else {
        pkt.payload = NULL;
    }
    return pkt;
}

/**
 * @brief Create a connected pair of local sockets for send/recv tests.
 *
 * @param pair Output: pair[0] and pair[1] are connected to each other.
 * @return 0 on success, -1 on failure.
 */
static int makeSocketPair(SocketFD pair[SockPairLen]) {
    int fds[SockPairLen];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (ret != 0) {
        pair[SockPairA] = NULL_SOCKETFD;
        pair[SockPairB] = NULL_SOCKETFD;
        return -1;
    }
    pair[SockPairA] = fds[SockPairA];
    pair[SockPairB] = fds[SockPairB];
    return 0;
}

/* ═══════════════════════  1. Constants & Enums  ═════════════════════════ */

/** @brief PACKET_MAGIC matches the documented ASCII 'PPPM' value. */
static void testPacketMagicValue(void) {
    ASSERT_UINT_EQ(PACKET_MAGIC, 0x5050504Du);
}

/** @brief MAX_PAYLOAD_LEN is the documented 1024. */
static void testMaxPayloadLen(void) {
    enum { ExpectedMax = 1024 };
    ASSERT_UINT_EQ(MAX_PAYLOAD_LEN, ExpectedMax);
    ASSERT_TRUE(MAX_PAYLOAD_LEN > 0);
}

/** @brief AES_PACKET_EXTRA_LEN is consistent with crypto constants. */
static void testAESPacketExtraLen(void) {
    ASSERT_UINT_EQ(AES_PACKET_EXTRA_LEN, AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN);
}

/** @brief PacketType enum values are stable. */
static void testPacketTypeValues(void) {
    ASSERT_INT_EQ(PlaintextPacket, 1);
    ASSERT_INT_EQ(AES256GCMPacket, 2);
}

/** @brief MessageType enum values are stable and complete. */
static void testMessageTypeValues(void) {
    ASSERT_INT_EQ(MsgKeyExchangeReq, 1);
    ASSERT_INT_EQ(MsgKeyExchangeResp, 2);
    ASSERT_INT_EQ(MsgLoginReq, 3);
    ASSERT_INT_EQ(MsgLoginResp, 4);
    ASSERT_INT_EQ(MsgRegisterReq, 5);
    ASSERT_INT_EQ(MsgRegisterResp, 6);
    ASSERT_INT_EQ(MsgRoomListReq, 7);
    ASSERT_INT_EQ(MsgRoomListResp, 8);
    ASSERT_INT_EQ(MsgCreateRoom, 9);
    ASSERT_INT_EQ(MsgCreateRoomResp, 10);
    ASSERT_INT_EQ(MsgJoinRoom, 11);
    ASSERT_INT_EQ(MsgJoinRoomResp, 12);
    ASSERT_INT_EQ(MsgChat, 13);
    ASSERT_INT_EQ(MsgLogout, 14);
    ASSERT_INT_EQ(MsgHeartbeat, 15);
    ASSERT_INT_EQ(MsgGameStart, 16);
    ASSERT_INT_EQ(MsgGameStop, 17);
}

/** @brief NULL_SOCKETFD sentinel value. */
static void testNullSocketFD(void) { ASSERT_INT_EQ(NULL_SOCKETFD, -1); }

/** @brief PROTOCOL_* return codes are distinct and have stable values. */
static void testProtocolReturnCodes(void) {
    ASSERT_INT_EQ(PROTOCOL_SUCC, 0);
    ASSERT_INT_EQ(PROTOCOL_FAIL, -1);
    ASSERT_INT_EQ(PROTOCOL_AUTH_FAIL, -2);
    ASSERT_TRUE(PROTOCOL_SUCC != PROTOCOL_FAIL);
    ASSERT_TRUE(PROTOCOL_FAIL != PROTOCOL_AUTH_FAIL);
}

/* ═══════════════════════  2. PacketHeader Layout  ══════════════════════ */

/** @brief PacketHeader size matches expected packed size. */
static void testPacketHeaderSize(void) {
    ASSERT_UINT_EQ(sizeof(PacketHeader), ExpectedHeaderSize);
}

/** @brief PacketHeader field offsets are deterministic (packed). */
static void testPacketHeaderFieldOffsets(void) {
    ASSERT_UINT_EQ(offsetof(PacketHeader, magic), ExpectedMagicOffset);
    ASSERT_UINT_EQ(offsetof(PacketHeader, packetType),
                   ExpectedPacketTypeOffset);
    ASSERT_UINT_EQ(offsetof(PacketHeader, messageType),
                   ExpectedMessageTypeOffset);
    ASSERT_UINT_EQ(offsetof(PacketHeader, payloadLength),
                   ExpectedPayloadLenOffset);
    ASSERT_UINT_EQ(offsetof(PacketHeader, sequenceID), ExpectedSeqIDOffset);
}

/** @brief Writing to one header field does not corrupt adjacent fields. */
static void testPacketHeaderFieldValues(void) {
    enum { TestLength = 128, TestSeq = 42 };

    PacketHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = PACKET_MAGIC;
    hdr.packetType = PlaintextPacket;
    hdr.messageType = MsgChat;
    hdr.payloadLength = TestLength;
    hdr.sequenceID = TestSeq;

    ASSERT_UINT_EQ(hdr.magic, PACKET_MAGIC);
    ASSERT_INT_EQ(hdr.packetType, PlaintextPacket);
    ASSERT_INT_EQ(hdr.messageType, MsgChat);
    ASSERT_UINT_EQ(hdr.payloadLength, TestLength);
    ASSERT_UINT_EQ(hdr.sequenceID, TestSeq);
}

/* ─── LoginRequestPayload layout ─────────────────────────────────────── */

/** @brief LoginRequestPayload fixed-header fields are at deterministic offsets. */
static void testLoginRequestPayloadOffsets(void) {
    /* Login payload: username(32B) at offset 0, password(FAM) at offset 32. */
    ASSERT_UINT_EQ(offsetof(LoginRequestPayload, username), (size_t)0);
    ASSERT_UINT_EQ(offsetof(LoginRequestPayload, password),
                   (size_t)LOGIN_USERNAME_LEN);
}

/** @brief sizeof(LoginRequestPayload) equals the fixed part (excludes FAM). */
static void testLoginRequestPayloadSize(void) {
    /* 32B username; FAM password[] adds no sizeof contribution. */
    ASSERT_UINT_EQ(sizeof(LoginRequestPayload), (size_t)LOGIN_USERNAME_LEN);
}

/* ─── RegisterRequestPayload layout ──────────────────────────────────── */

/** @brief RegisterRequestPayload fields are at deterministic offsets. */
static void testRegisterRequestPayloadOffsets(void) {
    ASSERT_UINT_EQ(offsetof(RegisterRequestPayload, username), (size_t)0);
    ASSERT_UINT_EQ(offsetof(RegisterRequestPayload, nickname),
                   (size_t)LOGIN_USERNAME_LEN);
    ASSERT_UINT_EQ(offsetof(RegisterRequestPayload, password),
                   (size_t)(LOGIN_USERNAME_LEN + LOGIN_NICKNAME_LEN));
}

/** @brief sizeof(RegisterRequestPayload) equals the fixed part (excludes FAM). */
static void testRegisterRequestPayloadSize(void) {
    ASSERT_UINT_EQ(sizeof(RegisterRequestPayload),
                   (size_t)(LOGIN_USERNAME_LEN + LOGIN_NICKNAME_LEN));
}

/* ─── LoginResponsePayload layout ────────────────────────────────────── */

/** @brief LoginResponsePayload is 68 bytes (uid + username + nickname). */
static void testLoginResponsePayloadSize(void) {
    ASSERT_UINT_EQ(sizeof(LoginResponsePayload),
                   (size_t)(sizeof(uint32_t) + LOGIN_USERNAME_LEN +
                            LOGIN_NICKNAME_LEN));
}

/** @brief LoginResponsePayload fields are at deterministic offsets. */
static void testLoginResponsePayloadOffsets(void) {
    ASSERT_UINT_EQ(offsetof(LoginResponsePayload, uid), (size_t)0);
    ASSERT_UINT_EQ(offsetof(LoginResponsePayload, username),
                   sizeof(uint32_t));
    ASSERT_UINT_EQ(offsetof(LoginResponsePayload, nickname),
                   sizeof(uint32_t) + LOGIN_USERNAME_LEN);
}

/* ─── ChatPacketPayload layout ───────────────────────────────────────── */

/** @brief ChatPacketPayload timestamp is at offset 0. */
static void testChatPacketPayloadOffsets(void) {
    ASSERT_UINT_EQ(offsetof(ChatPacketPayload, timestamp), 0);
    ASSERT_UINT_EQ(offsetof(ChatPacketPayload, message), sizeof(int64_t));
}

/** @brief sizeof(ChatPacketPayload) == sizeof(timestamp) (FAM excluded). */
static void testChatPacketPayloadSize(void) {
    ASSERT_UINT_EQ(sizeof(ChatPacketPayload), sizeof(int64_t));
}

/* ─── ChatBroadcastPayload layout ────────────────────────────────────── */

/** @brief ChatBroadcastPayload fields are packed in order. */
static void testChatBroadcastPayloadOffsets(void) {
    ASSERT_UINT_EQ(offsetof(ChatBroadcastPayload, uid), 0);
    ASSERT_UINT_EQ(offsetof(ChatBroadcastPayload, msgId), sizeof(uint32_t));
    ASSERT_UINT_EQ(offsetof(ChatBroadcastPayload, timestamp),
                   sizeof(uint32_t) + sizeof(uint64_t));
    ASSERT_UINT_EQ(offsetof(ChatBroadcastPayload, message),
                   sizeof(uint32_t) + sizeof(uint64_t) + sizeof(int64_t));
}

/** @brief sizeof(ChatBroadcastPayload) equals the fixed header (excludes FAM). */
static void testChatBroadcastPayloadSize(void) {
    /* 4B uid + 8B msgId + 8B timestamp = 20B fixed. */
    enum { ExpectedFixedSize = 20 };
    ASSERT_UINT_EQ(sizeof(ChatBroadcastPayload), ExpectedFixedSize);
}

/* ═══════════════════════  3. packetClear  ══════════════════════════════ */

/** @brief packetClear frees payload and sets it to NULL. */
static void testPacketClearFreesPayload(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    ASSERT_TRUE(pkt.payload != NULL);

    packetClear(&pkt);
    ASSERT_TRUE(pkt.payload == NULL);
}

/** @brief packetClear on a packet with NULL payload is safe. */
static void testPacketClearNullPayload(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;

    /* Should not crash. */
    packetClear(&pkt);
    ASSERT_TRUE(pkt.payload == NULL);
}

/** @brief Calling packetClear twice on the same packet is safe (idempotent). */
static void testPacketClearIdempotent(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    packetClear(&pkt);
    /* Second call must be safe: payload is already NULL, free(NULL) is a
     * no-op, and the pointer must remain NULL. */
    packetClear(&pkt);
    ASSERT_TRUE(pkt.payload == NULL);
}

/* ═══════════════════════  4. packetSerialize  ══════════════════════════ */

/** @brief Serialize a normal packet and verify output size. */
static void testSerializeSuccess(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;

    int ret = packetSerialize(&pkt, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(serializedSize,
                   sizeof(PacketHeader) + sizeof(testPayloadStr));

    packetClear(&pkt);
}

/** @brief Serialize preserves header fields in the buffer. */
static void testSerializeHeaderContent(void) {
    enum { TestSeq = 99 };
    Packet pkt = makeTestPacket(MsgLoginReq, TestSeq, testPayloadStr,
                                sizeof(testPayloadStr));
    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;

    int ret = packetSerialize(&pkt, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Header bytes should match the in-memory header. */
    ASSERT_MEM_EQ(buf, &pkt.header, sizeof(PacketHeader));

    /* Payload bytes follow the header. */
    ASSERT_MEM_EQ(buf + sizeof(PacketHeader), testPayloadStr,
                  sizeof(testPayloadStr));

    packetClear(&pkt);
}

/** @brief Serialize fails when packet is NULL. */
static void testSerializeNullPacket(void) {
    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    ASSERT_INT_EQ(packetSerialize(NULL, buf, sizeof(buf), &serializedSize),
                  PROTOCOL_FAIL);
}

/** @brief Serialize fails when buffer is NULL. */
static void testSerializeNullBuffer(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    size_t serializedSize = 0;
    ASSERT_INT_EQ(packetSerialize(&pkt, NULL, 0, &serializedSize),
                  PROTOCOL_FAIL);
    packetClear(&pkt);
}

/** @brief Serialize fails when serializedSize output is NULL. */
static void testSerializeNullSizeOut(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    uint8_t buf[TestSerBufSize];
    ASSERT_INT_EQ(packetSerialize(&pkt, buf, sizeof(buf), NULL), PROTOCOL_FAIL);
    packetClear(&pkt);
}

/** @brief Serialize fails when buffer is too small for header + payload. */
static void testSerializeBufferTooSmall(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    uint8_t buf[1]; /* intentionally tiny */
    size_t serializedSize = 0;
    ASSERT_INT_EQ(packetSerialize(&pkt, buf, sizeof(buf), &serializedSize),
                  PROTOCOL_FAIL);
    packetClear(&pkt);
}

/** @brief Serialize a packet with zero-length payload succeeds. */
static void testSerializeZeroPayload(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = PACKET_MAGIC;
    pkt.header.packetType = PlaintextPacket;
    pkt.header.messageType = MsgHeartbeat;
    pkt.header.payloadLength = 0;
    pkt.header.sequenceID = 0;
    pkt.payload = NULL;

    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    int ret = packetSerialize(&pkt, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(serializedSize, sizeof(PacketHeader));
}

/** @brief Serialize succeeds when buffer size is exactly equal to total. */
static void testSerializeExactBufferSize(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    size_t exactSize = sizeof(PacketHeader) + sizeof(testPayloadStr);
    uint8_t *buf = malloc(exactSize);
    ASSERT_TRUE(buf != NULL);
    size_t serializedSize = 0;

    int ret = packetSerialize(&pkt, buf, exactSize, &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(serializedSize, exactSize);

    free(buf);
    packetClear(&pkt);
}

/** @brief Serialize one byte short of the required size fails. */
static void testSerializeOneByteShort(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    size_t shortSize = sizeof(PacketHeader) + sizeof(testPayloadStr) - 1;
    uint8_t *buf = malloc(shortSize);
    ASSERT_TRUE(buf != NULL);
    size_t serializedSize = 0;

    int ret = packetSerialize(&pkt, buf, shortSize, &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_FAIL);

    free(buf);
    packetClear(&pkt);
}

/** @brief Serialize writes only totalSize bytes when buffer is oversized. */
static void testSerializeOversizedBufferUntouched(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    uint8_t buf[TestSerBufSize];
    memset(buf, FillCorrupt, sizeof(buf)); /* sentinel pattern */

    size_t serializedSize = 0;
    int ret = packetSerialize(&pkt, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Bytes beyond serializedSize must remain untouched (still 0xFF). */
    ASSERT_UINT_EQ(buf[serializedSize], FillCorrupt);
    ASSERT_UINT_EQ(buf[sizeof(buf) - 1], FillCorrupt);

    packetClear(&pkt);
}

/* ═══════════════════════  5. packetDeserialize  ════════════════════════ */

/** @brief Deserialize a valid buffer into a Packet. */
static void testDeserializeSuccess(void) {
    /* First serialize, then deserialize. */
    enum { TestSeq = 7 };
    Packet original = makeTestPacket(MsgChat, TestSeq, testPayloadStr,
                                     sizeof(testPayloadStr));
    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    packetSerialize(&original, buf, sizeof(buf), &serializedSize);

    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;

    int ret = packetDeserialize(buf, serializedSize, &restored);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(restored.header.magic, PACKET_MAGIC);
    ASSERT_INT_EQ(restored.header.messageType, MsgChat);
    ASSERT_UINT_EQ(restored.header.sequenceID, TestSeq);
    ASSERT_UINT_EQ(restored.header.payloadLength, sizeof(testPayloadStr));
    ASSERT_TRUE(restored.payload != NULL);
    ASSERT_MEM_EQ(restored.payload, testPayloadStr, sizeof(testPayloadStr));

    packetClear(&original);
    packetClear(&restored);
}

/** @brief Deserialize fails when buffer is NULL. */
static void testDeserializeNullBuffer(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;
    ASSERT_INT_EQ(packetDeserialize(NULL, 100, &pkt), PROTOCOL_FAIL);
}

/** @brief Deserialize fails when packet is NULL. */
static void testDeserializeNullPacket(void) {
    uint8_t buf[TestSerBufSize];
    ASSERT_INT_EQ(packetDeserialize(buf, sizeof(buf), NULL), PROTOCOL_FAIL);
}

/** @brief Deserialize fails when packet->payload is not NULL. */
static void testDeserializePayloadNotNull(void) {
    uint8_t buf[TestSerBufSize];
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    uint8_t dummy = 0;
    pkt.payload = &dummy;
    ASSERT_INT_EQ(packetDeserialize(buf, sizeof(buf), &pkt), PROTOCOL_FAIL);
}

/** @brief Deserialize fails when buffer is too small for the header. */
static void testDeserializeBufferTooSmallForHeader(void) {
    uint8_t buf[1];
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;
    ASSERT_INT_EQ(packetDeserialize(buf, sizeof(buf), &pkt), PROTOCOL_FAIL);
}

/** @brief Deserialize fails when magic number is wrong. */
static void testDeserializeInvalidMagic(void) {
    Packet original =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    packetSerialize(&original, buf, sizeof(buf), &serializedSize);

    /* Corrupt the magic field (first 4 bytes). */
    buf[0] = FillCorrupt;
    buf[1] = FillCorrupt;
    buf[2] = FillCorrupt;
    buf[3] = FillCorrupt;

    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;
    ASSERT_INT_EQ(packetDeserialize(buf, serializedSize, &restored),
                  PROTOCOL_FAIL);

    packetClear(&original);
}

/** @brief Deserialize fails when buffer is too small for declared payload. */
static void testDeserializeBufferTooSmallForPayload(void) {
    Packet original =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    packetSerialize(&original, buf, sizeof(buf), &serializedSize);

    /* Truncate the buffer to only include the header. */
    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;
    ASSERT_INT_EQ(packetDeserialize(buf, sizeof(PacketHeader), &restored),
                  PROTOCOL_FAIL);

    packetClear(&original);
}

/** @brief Deserialize a packet with payloadLength == 0 does not allocate. */
static void testDeserializeZeroPayload(void) {
    Packet src;
    memset(&src, 0, sizeof(src));
    src.header.magic = PACKET_MAGIC;
    src.header.packetType = PlaintextPacket;
    src.header.messageType = MsgHeartbeat;
    src.header.payloadLength = 0;
    src.header.sequenceID = 1;
    src.payload = NULL;

    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    int ret = packetSerialize(&src, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(serializedSize, sizeof(PacketHeader));

    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;

    ret = packetDeserialize(buf, serializedSize, &restored);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(restored.header.payloadLength, 0);
    ASSERT_INT_EQ(restored.header.messageType, MsgHeartbeat);
    /* payload should remain NULL because no allocation was needed. */
    ASSERT_TRUE(restored.payload == NULL);
}

/** @brief Deserialize succeeds when buffer contains extra trailing bytes. */
static void testDeserializeBufferWithTrailingBytes(void) {
    Packet original =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    uint8_t buf[TestSerBufSize];
    memset(buf, FillTamper, sizeof(buf)); /* trailing bytes are sentinel */
    size_t serializedSize = 0;
    packetSerialize(&original, buf, sizeof(buf), &serializedSize);

    /* Pass the entire buffer (much larger than serializedSize) — extra bytes
     * must be ignored. */
    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;

    int ret = packetDeserialize(buf, sizeof(buf), &restored);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(restored.header.payloadLength, sizeof(testPayloadStr));
    ASSERT_MEM_EQ(restored.payload, testPayloadStr, sizeof(testPayloadStr));

    packetClear(&original);
    packetClear(&restored);
}

/* ══════════════════  6. Serialize / Deserialize Roundtrip  ═════════════ */

/** @brief Serialize then deserialize preserves all fields and payload. */
static void testSerializeDeserializeRoundtrip(void) {
    enum { TestSeq = 12345 };
    const char msg[] = "roundtrip test data 1234567890";
    Packet original = makeTestPacket(MsgJoinRoom, TestSeq, msg, sizeof(msg));

    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    int ret = packetSerialize(&original, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;
    ret = packetDeserialize(buf, serializedSize, &restored);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Verify all header fields. */
    ASSERT_UINT_EQ(restored.header.magic, original.header.magic);
    ASSERT_INT_EQ(restored.header.packetType, original.header.packetType);
    ASSERT_INT_EQ(restored.header.messageType, original.header.messageType);
    ASSERT_UINT_EQ(restored.header.payloadLength,
                   original.header.payloadLength);
    ASSERT_UINT_EQ(restored.header.sequenceID, original.header.sequenceID);

    /* Verify payload content. */
    ASSERT_TRUE(restored.payload != NULL);
    ASSERT_MEM_EQ(restored.payload, original.payload, sizeof(msg));

    packetClear(&original);
    packetClear(&restored);
}

/** @brief Roundtrip with maximum-length payload. */
static void testSerializeDeserializeMaxPayload(void) {
    uint8_t bigPayload[MAX_PAYLOAD_LEN];
    memset(bigPayload, FillByteA, sizeof(bigPayload));

    Packet original =
        makeTestPacket(MsgChat, 0, bigPayload, sizeof(bigPayload));

    size_t bufSize = sizeof(PacketHeader) + MAX_PAYLOAD_LEN;
    uint8_t *buf = malloc(bufSize);
    ASSERT_TRUE(buf != NULL);

    size_t serializedSize = 0;
    int ret = packetSerialize(&original, buf, bufSize, &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(serializedSize, bufSize);

    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;
    ret = packetDeserialize(buf, serializedSize, &restored);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(restored.header.payloadLength, MAX_PAYLOAD_LEN);
    ASSERT_MEM_EQ(restored.payload, bigPayload, MAX_PAYLOAD_LEN);

    packetClear(&original);
    packetClear(&restored);
    free(buf);
}

/** @brief Roundtrip with binary payload containing NUL bytes. */
static void testSerializeDeserializeBinaryPayload(void) {
    /* Payload deliberately contains 0x00 to ensure no implicit string
     * truncation occurs along the serialize/deserialize path. */
    enum { BinLen = 16 };
    const uint8_t binary[BinLen] = {0x00, 0x01, 0x00, 0xFF, 0xAB, 0x00,
                                    0xCD, 0xEF, 0x00, 0x42, 0x00, 0x99,
                                    0x00, 0x00, 0x77, 0x88};
    Packet original = makeTestPacket(MsgChat, 1, binary, sizeof(binary));

    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    int ret = packetSerialize(&original, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;
    ret = packetDeserialize(buf, serializedSize, &restored);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(restored.header.payloadLength, sizeof(binary));
    ASSERT_MEM_EQ(restored.payload, binary, sizeof(binary));

    packetClear(&original);
    packetClear(&restored);
}

/* ═══════════════════════  7. packetAESEncrypt  ═════════════════════════ */

/** @brief Encrypt a plaintext packet and verify state transitions. */
static void testAESEncryptSuccess(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));

    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* packetType must change to AES256GCMPacket. */
    ASSERT_INT_EQ(pkt.header.packetType, AES256GCMPacket);

    /* Payload length must grow by AES_PACKET_EXTRA_LEN (nonce + tag). */
    ASSERT_UINT_EQ(pkt.header.payloadLength,
                   sizeof(testPayloadStr) + AES_PACKET_EXTRA_LEN);

    /* Payload must not be NULL. */
    ASSERT_TRUE(pkt.payload != NULL);

    packetClear(&pkt);
}

/** @brief Encrypt fails with NULL packet. */
static void testAESEncryptNullPacket(void) {
    ASSERT_INT_EQ(packetAESEncrypt(NULL, (uint8_t *)testAESKey), PROTOCOL_FAIL);
}

/** @brief Encrypt fails with NULL key. */
static void testAESEncryptNullKey(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    ASSERT_INT_EQ(packetAESEncrypt(&pkt, NULL), PROTOCOL_FAIL);
    packetClear(&pkt);
}

/** @brief Encrypt fails with NULL payload and positive payloadLength. */
static void testAESEncryptNullPayload(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = PACKET_MAGIC;
    pkt.header.packetType = PlaintextPacket;
    pkt.header.payloadLength = sizeof(testPayloadStr);
    pkt.payload = NULL;

    ASSERT_INT_EQ(packetAESEncrypt(&pkt, (uint8_t *)testAESKey), PROTOCOL_FAIL);
}

/** @brief Encrypt fails when packetType is not PlaintextPacket. */
static void testAESEncryptWrongPacketType(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    pkt.header.packetType = AES256GCMPacket; /* already "encrypted" */

    ASSERT_INT_EQ(packetAESEncrypt(&pkt, (uint8_t *)testAESKey), PROTOCOL_FAIL);
    packetClear(&pkt);
}

/** @brief Encrypt fails when payload exceeds MAX_PAYLOAD_LEN. */
static void testAESEncryptPayloadTooLarge(void) {
    size_t oversized = MAX_PAYLOAD_LEN + 1;
    uint8_t *big = malloc(oversized);
    ASSERT_TRUE(big != NULL);
    memset(big, FillByteB, oversized);

    Packet pkt = makeTestPacket(MsgChat, 1, big, oversized);
    ASSERT_INT_EQ(packetAESEncrypt(&pkt, (uint8_t *)testAESKey), PROTOCOL_FAIL);

    packetClear(&pkt);
    free(big);
}

/** @brief Encrypt at exactly MAX_PAYLOAD_LEN succeeds (boundary case). */
static void testAESEncryptExactlyMaxPayload(void) {
    uint8_t maxBuf[MAX_PAYLOAD_LEN];
    memset(maxBuf, FillByteA, sizeof(maxBuf));

    Packet pkt = makeTestPacket(MsgChat, 1, maxBuf, sizeof(maxBuf));
    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength,
                   (size_t)MAX_PAYLOAD_LEN + AES_PACKET_EXTRA_LEN);

    packetClear(&pkt);
}

/** @brief Encrypt succeeds with zero-length payload (heartbeat case). */
static void testAESEncryptZeroPayload(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = PACKET_MAGIC;
    pkt.header.packetType = PlaintextPacket;
    pkt.header.payloadLength = 0;
    pkt.payload = NULL;

    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength,
                   (size_t)AES_PACKET_EXTRA_LEN);

    packetClear(&pkt);
}

/** @brief Encrypt preserves magic, messageType, and sequenceID. */
static void testAESEncryptPreservesHeaderFields(void) {
    enum { TestSeq = 0xDEADBEEFU };
    Packet pkt = makeTestPacket(MsgJoinRoom, TestSeq, testPayloadStr,
                                sizeof(testPayloadStr));

    uint32_t magicBefore = pkt.header.magic;
    uint32_t msgTypeBefore = pkt.header.messageType;    uint32_t seqBefore = pkt.header.sequenceID;

    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ASSERT_UINT_EQ(pkt.header.magic, magicBefore);
    ASSERT_INT_EQ(pkt.header.messageType, msgTypeBefore);
    ASSERT_UINT_EQ(pkt.header.sequenceID, seqBefore);

    packetClear(&pkt);
}

/* ═══════════════════════  8. packetAESDecrypt  ═════════════════════════ */

/** @brief Decrypt fails with NULL packet. */
static void testAESDecryptNullPacket(void) {
    ASSERT_INT_EQ(packetAESDecrypt(NULL, (uint8_t *)testAESKey), PROTOCOL_FAIL);
}

/** @brief Decrypt fails with NULL key. */
static void testAESDecryptNullKey(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    /* Encrypt first so packetType is correct for decrypt. */
    packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(packetAESDecrypt(&pkt, NULL), PROTOCOL_FAIL);
    packetClear(&pkt);
}

/** @brief Decrypt fails with NULL payload. */
static void testAESDecryptNullPayload(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.packetType = AES256GCMPacket;
    pkt.payload = NULL;

    ASSERT_INT_EQ(packetAESDecrypt(&pkt, (uint8_t *)testAESKey), PROTOCOL_FAIL);
}

/** @brief Decrypt fails when packetType is not AES256GCMPacket. */
static void testAESDecryptWrongPacketType(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    /* Do NOT encrypt; it's still PlaintextPacket. */
    ASSERT_INT_EQ(packetAESDecrypt(&pkt, (uint8_t *)testAESKey), PROTOCOL_FAIL);
    packetClear(&pkt);
}

/** @brief Decrypt fails when encrypted payload is too short. */
static void testAESDecryptPayloadTooShort(void) {
    /* Construct a packet that claims to be encrypted but has a tiny payload. */
    enum { TinyLen = 4 };
    uint8_t tiny[TinyLen];
    memset(tiny, 0, sizeof(tiny));

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = PACKET_MAGIC;
    pkt.header.packetType = AES256GCMPacket;
    pkt.header.payloadLength = TinyLen;
    pkt.payload = malloc(TinyLen);
    memcpy(pkt.payload, tiny, TinyLen);

    ASSERT_INT_EQ(packetAESDecrypt(&pkt, (uint8_t *)testAESKey), PROTOCOL_FAIL);
    packetClear(&pkt);
}

/* ══════════════  9. AES Encrypt / Decrypt Roundtrip  ══════════════════ */

/** @brief Encrypt then decrypt restores the original plaintext. */
static void testAESRoundtrip(void) {
    enum { TestSeq = 77 };
    Packet pkt = makeTestPacket(MsgChat, TestSeq, testPayloadStr,
                                sizeof(testPayloadStr));

    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ(pkt.header.packetType, AES256GCMPacket);

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ(pkt.header.packetType, PlaintextPacket);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(testPayloadStr));
    ASSERT_UINT_EQ(pkt.header.sequenceID, TestSeq);
    ASSERT_MEM_EQ(pkt.payload, testPayloadStr, sizeof(testPayloadStr));

    packetClear(&pkt);
}

/** @brief AES roundtrip with a 1-byte payload (minimum size). */
static void testAESRoundtripMinPayload(void) {
    uint8_t oneByte = FillByteB;
    Packet pkt = makeTestPacket(MsgHeartbeat, 0, &oneByte, 1);

    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, 1);
    ASSERT_UINT_EQ(pkt.payload[0], oneByte);

    packetClear(&pkt);
}

/** @brief AES roundtrip with max-length payload. */
static void testAESRoundtripMaxPayload(void) {
    uint8_t maxBuf[MAX_PAYLOAD_LEN];
    memset(maxBuf, FillByteC, sizeof(maxBuf));

    Packet pkt = makeTestPacket(MsgChat, 1, maxBuf, sizeof(maxBuf));

    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, MAX_PAYLOAD_LEN);
    ASSERT_MEM_EQ(pkt.payload, maxBuf, MAX_PAYLOAD_LEN);

    packetClear(&pkt);
}

/** @brief AES roundtrip with binary payload containing NUL bytes. */
static void testAESRoundtripBinaryPayload(void) {
    enum { BinLen = 12 };
    const uint8_t binary[BinLen] = {0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
                                    0x01, 0x02, 0x03, 0x00, 0x00, 0x00};
    Packet pkt = makeTestPacket(MsgChat, 1, binary, sizeof(binary));

    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(binary));
    ASSERT_MEM_EQ(pkt.payload, binary, sizeof(binary));

    packetClear(&pkt);
}

/** @brief Decrypt with wrong key returns PROTOCOL_AUTH_FAIL. */
static void testAESDecryptWrongKey(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESDecrypt(&pkt, (uint8_t *)wrongAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&pkt);
}

/** @brief Decrypt with tampered ciphertext returns PROTOCOL_AUTH_FAIL. */
static void testAESDecryptTamperedCiphertext(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Flip a bit in the ciphertext area (after the nonce, before the tag). */
    size_t flipOffset = AES_GCM_NONCE_LEN + 1;
    if (pkt.header.payloadLength > flipOffset) {
        pkt.payload[flipOffset] ^= FillCorrupt;
    }

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&pkt);
}

/** @brief Decrypt with tampered tag returns PROTOCOL_AUTH_FAIL. */
static void testAESDecryptTamperedTag(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Flip a bit in the last byte (part of the tag). */
    pkt.payload[pkt.header.payloadLength - 1] ^= TamperBitMask;

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&pkt);
}

/** @brief Decrypt with tampered nonce returns PROTOCOL_AUTH_FAIL. */
static void testAESDecryptTamperedNonce(void) {
    Packet pkt =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Flip a bit in the first byte (part of the nonce). */
    pkt.payload[0] ^= TamperBitMask;

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&pkt);
}

/** @brief Decrypt fails when header.sequenceID is tampered (AAD mismatch). */
static void testAESDecryptTamperedSequenceID(void) {
    enum { OriginalSeq = 100, TamperedSeq = 101 };
    Packet pkt = makeTestPacket(MsgChat, OriginalSeq, testPayloadStr,
                                sizeof(testPayloadStr));
    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Modify sequenceID in the header. AAD = (payloadLen << 32) | seqID, so
     * any change here must invalidate the GCM tag. */
    pkt.header.sequenceID = TamperedSeq;

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&pkt);
}

/** @brief Decrypt preserves magic, messageType, and restores sequenceID. */
static void testAESDecryptPreservesHeaderFields(void) {
    enum { TestSeq = 0xCAFEBABEU };
    Packet pkt = makeTestPacket(MsgCreateRoom, TestSeq, testPayloadStr,
                                sizeof(testPayloadStr));
    uint32_t magicBefore = pkt.header.magic;
    uint32_t msgTypeBefore = pkt.header.messageType;
    int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ASSERT_UINT_EQ(pkt.header.magic, magicBefore);
    ASSERT_INT_EQ(pkt.header.messageType, msgTypeBefore);
    ASSERT_UINT_EQ(pkt.header.sequenceID, TestSeq);

    packetClear(&pkt);
}

/** @brief Encrypting the same plaintext twice produces different ciphertexts.
 */
static void testAESEncryptNonDeterministic(void) {
    Packet pkt1 =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));
    Packet pkt2 =
        makeTestPacket(MsgChat, 1, testPayloadStr, sizeof(testPayloadStr));

    int ret1 = packetAESEncrypt(&pkt1, (uint8_t *)testAESKey);
    int ret2 = packetAESEncrypt(&pkt2, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret1, PROTOCOL_SUCC);
    ASSERT_INT_EQ(ret2, PROTOCOL_SUCC);

    /* Same payload length (deterministic). */
    ASSERT_UINT_EQ(pkt1.header.payloadLength, pkt2.header.payloadLength);

    /* Encrypted payloads should differ (random nonces). */
    ASSERT_FALSE(
        memcmp(pkt1.payload, pkt2.payload, pkt1.header.payloadLength) == 0);

    packetClear(&pkt1);
    packetClear(&pkt2);
}

/** @brief Several distinct sequenceIDs all encrypt/decrypt correctly. */
static void testAESRoundtripMultipleSequenceIDs(void) {
    enum { NumSeq = 4 };
    static const uint32_t seqs[NumSeq] = {0, 1, 0x7FFFFFFFU, 0xFFFFFFFFU};

    for (size_t i = 0; i < NumSeq; ++i) {
        Packet pkt = makeTestPacket(MsgChat, seqs[i], testPayloadStr,
                                    sizeof(testPayloadStr));
        int ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
        ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

        ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
        ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
        ASSERT_UINT_EQ(pkt.header.sequenceID, seqs[i]);
        ASSERT_MEM_EQ(pkt.payload, testPayloadStr, sizeof(testPayloadStr));

        packetClear(&pkt);
    }
}

/* ═══════  10. Full Pipeline: Serialize -> Encrypt -> Decrypt -> Deserialize */

/** @brief Full pipeline roundtrip: serialize, encrypt, decrypt, deserialize. */
static void testFullPipelineRoundtrip(void) {
    enum { TestSeq = 500 };
    const char msg[] = "full pipeline test";
    Packet original = makeTestPacket(MsgCreateRoom, TestSeq, msg, sizeof(msg));

    /* Encrypt. */
    int ret = packetAESEncrypt(&original, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Serialize. */
    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    ret = packetSerialize(&original, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    /* Deserialize. */
    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;
    ret = packetDeserialize(buf, serializedSize, &restored);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ(restored.header.packetType, AES256GCMPacket);

    /* Decrypt. */
    ret = packetAESDecrypt(&restored, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ(restored.header.packetType, PlaintextPacket);
    ASSERT_INT_EQ(restored.header.messageType, MsgCreateRoom);
    ASSERT_UINT_EQ(restored.header.sequenceID, TestSeq);
    ASSERT_UINT_EQ(restored.header.payloadLength, sizeof(msg));
    ASSERT_MEM_EQ(restored.payload, msg, sizeof(msg));

    packetClear(&original);
    packetClear(&restored);
}

/* ═════════════════════  11. packetSend / packetRecv  ════════════════════ */

/** @brief packetSend fails when packet is NULL. */
static void testPacketSendNullPacket(void) {
    ASSERT_INT_EQ(packetSend(NULL, NULL_SOCKETFD), PROTOCOL_FAIL);
}

/** @brief packetSend fails when payload is NULL. */
static void testPacketSendNullPayload(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = PACKET_MAGIC;
    pkt.header.payloadLength = 0;
    pkt.payload = NULL;
    ASSERT_INT_EQ(packetSend(&pkt, NULL_SOCKETFD), PROTOCOL_FAIL);
}

/** @brief packetRecv fails when dest is NULL. */
static void testPacketRecvNullDest(void) {
    ASSERT_INT_EQ(packetRecv(NULL, NULL_SOCKETFD), PROTOCOL_FAIL);
}

/** @brief packetRecv fails when dest->payload is not NULL. */
static void testPacketRecvNonNullPayload(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    uint8_t dummy = 0;
    pkt.payload = &dummy;
    ASSERT_INT_EQ(packetRecv(&pkt, NULL_SOCKETFD), PROTOCOL_FAIL);
}

/** @brief End-to-end send/recv over a socketpair preserves the packet. */
static void testPacketSendRecvRoundtrip(void) {
    SocketFD pair[SockPairLen];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    enum { TestSeq = 0x1234U };
    const char msg[] = "send/recv test payload";
    Packet sent = makeTestPacket(MsgChat, TestSeq, msg, sizeof(msg));

    int ret = packetSend(&sent, pair[SockPairA]);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    Packet recvd;
    memset(&recvd, 0, sizeof(recvd));
    recvd.payload = NULL;
    ret = packetRecv(&recvd, pair[SockPairB]);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ASSERT_UINT_EQ(recvd.header.magic, PACKET_MAGIC);
    ASSERT_INT_EQ(recvd.header.messageType, MsgChat);
    ASSERT_UINT_EQ(recvd.header.sequenceID, TestSeq);
    ASSERT_UINT_EQ(recvd.header.payloadLength, sizeof(msg));
    ASSERT_MEM_EQ(recvd.payload, msg, sizeof(msg));

    packetClear(&sent);
    packetClear(&recvd);
    socketClose(&pair[SockPairA]);
    socketClose(&pair[SockPairB]);
}

/** @brief End-to-end send/recv of an encrypted packet. */
static void testPacketSendRecvEncrypted(void) {
    SocketFD pair[SockPairLen];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    enum { TestSeq = 0xABCDU };
    Packet sent = makeTestPacket(MsgChat, TestSeq, testPayloadStr,
                                 sizeof(testPayloadStr));
    int ret = packetAESEncrypt(&sent, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetSend(&sent, pair[SockPairA]);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    Packet recvd;
    memset(&recvd, 0, sizeof(recvd));
    recvd.payload = NULL;
    ret = packetRecv(&recvd, pair[SockPairB]);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ(recvd.header.packetType, AES256GCMPacket);

    /* Decrypt the received packet and verify the plaintext. */
    ret = packetAESDecrypt(&recvd, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(recvd.header.sequenceID, TestSeq);
    ASSERT_MEM_EQ(recvd.payload, testPayloadStr, sizeof(testPayloadStr));

    packetClear(&sent);
    packetClear(&recvd);
    socketClose(&pair[SockPairA]);
    socketClose(&pair[SockPairB]);
}

/** @brief packetRecv rejects a packet with an invalid magic number. */
static void testPacketRecvInvalidMagic(void) {
    SocketFD pair[SockPairLen];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    /* Craft a header with a wrong magic and send it raw. */
    PacketHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = InvalidMagicValue;
    hdr.packetType = PlaintextPacket;
    hdr.messageType = MsgChat;
    hdr.payloadLength = 0;
    hdr.sequenceID = 0;
    ssize_t sent = send(pair[SockPairA], &hdr, sizeof(hdr), 0);
    ASSERT_INT_EQ((int)sent, (int)sizeof(hdr));

    Packet recvd;
    memset(&recvd, 0, sizeof(recvd));
    recvd.payload = NULL;
    ASSERT_INT_EQ(packetRecv(&recvd, pair[SockPairB]), PROTOCOL_FAIL);

    socketClose(&pair[SockPairA]);
    socketClose(&pair[SockPairB]);
}

/** @brief packetRecv rejects a packet whose payload length exceeds the cap. */
static void testPacketRecvOversizedPayload(void) {
    SocketFD pair[SockPairLen];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    /* Valid magic, but payload length is far above the protocol limit. */
    PacketHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = PACKET_MAGIC;
    hdr.packetType = PlaintextPacket;
    hdr.messageType = MsgChat;
    hdr.payloadLength = (size_t)MAX_PAYLOAD_LEN + 1;
    hdr.sequenceID = 0;
    ssize_t sent = send(pair[SockPairA], &hdr, sizeof(hdr), 0);
    ASSERT_INT_EQ((int)sent, (int)sizeof(hdr));

    Packet recvd;
    memset(&recvd, 0, sizeof(recvd));
    recvd.payload = NULL;
    ASSERT_INT_EQ(packetRecv(&recvd, pair[SockPairB]), PROTOCOL_FAIL);

    socketClose(&pair[SockPairA]);
    socketClose(&pair[SockPairB]);
}

/** @brief packetRecv fails cleanly when the peer closes before sending. */
static void testPacketRecvPeerClosed(void) {
    SocketFD pair[SockPairLen];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    /* Close the sender side immediately; recv must return PROTOCOL_FAIL. */
    socketClose(&pair[SockPairA]);

    Packet recvd;
    memset(&recvd, 0, sizeof(recvd));
    recvd.payload = NULL;
    ASSERT_INT_EQ(packetRecv(&recvd, pair[SockPairB]), PROTOCOL_FAIL);

    socketClose(&pair[SockPairB]);
}

/* ═══════════════════════  12. socket setup / close  ═════════════════════ */

/** @brief socketClose sets the FD to NULL_SOCKETFD. */
static void testSocketCloseSetsSentinel(void) {
    SocketFD fd = NULL_SOCKETFD;
    socketClose(&fd);
    ASSERT_INT_EQ(fd, NULL_SOCKETFD);
}

/** @brief socketClose on an already-closed (negative) FD is safe. */
static void testSocketCloseNegativeFD(void) {
    enum { NegativeFD = -5 };
    SocketFD fd = NegativeFD;
    socketClose(&fd);
    ASSERT_INT_EQ(fd, NULL_SOCKETFD);
}

/** @brief socketClose actually closes a real open file descriptor. */
static void testSocketCloseRealFD(void) {
    SocketFD pair[SockPairLen];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    SocketFD fdA = pair[SockPairA];
    ASSERT_TRUE(fdA >= 0);

    socketClose(&pair[SockPairA]);
    ASSERT_INT_EQ(pair[SockPairA], NULL_SOCKETFD);

    /* The original fd should now be invalid: a second close on the underlying
     * descriptor must fail. */
    ASSERT_INT_EQ(close(fdA), -1);

    socketClose(&pair[SockPairB]);
}

/** @brief serverSetup with port=0 succeeds and the kernel picks a port. */
static void testServerSetupEphemeralPort(void) {
    SocketFD fd = serverSetup(0);
    ASSERT_TRUE(fd != NULL_SOCKETFD);
    ASSERT_TRUE(fd >= 0);
    socketClose(&fd);
}

/** @brief clientSetup fails for a syntactically invalid address. */
static void testClientSetupInvalidAddress(void) {
    enum { ArbitraryPort = 12345 };
    SocketFD fd = clientSetup("not_an_ip_address", ArbitraryPort);
    ASSERT_INT_EQ(fd, NULL_SOCKETFD);
}

/** @brief clientSetup fails when connecting to a closed/unbound endpoint. */
static void testClientSetupConnectionRefused(void) {
    /* 127.0.0.1 on a high arbitrary port that is virtually guaranteed to be
     * unused. connect(2) should fail with ECONNREFUSED. */
    enum { UnboundPort = 1 };
    SocketFD fd = clientSetup("127.0.0.1", UnboundPort);
    ASSERT_INT_EQ(fd, NULL_SOCKETFD);
}

/* ═══════════════ 13. Security Hardening Tests ═════════════════════════ */

/** @brief packetClear(NULL) does not crash. */
static void testPacketClearNull(void) {
    packetClear(NULL);
    ASSERT_TRUE(1); /* Reached here without segfault. */
}

/** @brief socketClose(NULL) does not crash. */
static void testSocketCloseNull(void) {
    socketClose(NULL);
    ASSERT_TRUE(1); /* Reached here without segfault. */
}

/** @brief clientSetup with NULL address returns NULL_SOCKETFD. */
static void testClientSetupNullAddress(void) {
    enum { AnyPort = 8080 };
    SocketFD fd = clientSetup(NULL, AnyPort);
    ASSERT_INT_EQ(fd, NULL_SOCKETFD);
}

/** @brief packetDeserialize rejects payload length exceeding protocol max. */
static void testDeserializePayloadLengthExceedsMax(void) {
    /* Build a raw buffer with a valid magic but payloadLength >
     * MAX_PAYLOAD_LEN.
     */
    Packet src;
    src.header.magic = PACKET_MAGIC;
    src.header.packetType = PlaintextPacket;
    src.header.messageType = MsgChat;
    src.header.payloadLength = MAX_PAYLOAD_LEN + 1;
    src.header.sequenceID = 0;

    /* We only need the header bytes for this test. */
    uint8_t buffer[sizeof(PacketHeader) + MAX_PAYLOAD_LEN + 1];
    memcpy(buffer, &src.header, sizeof(PacketHeader));
    /* Fill fake payload area. */
    memset(buffer + sizeof(PacketHeader), 0, MAX_PAYLOAD_LEN + 1);

    Packet result;
    result.payload = NULL;
    ASSERT_INT_EQ(packetDeserialize(buffer, sizeof(buffer), &result),
                  PROTOCOL_FAIL);
}

/** @brief packetSerialize with payloadLength near SIZE_MAX returns failure. */
static void testSerializePayloadLengthOverflow(void) {
    Packet pkt;
    pkt.header.magic = PACKET_MAGIC;
    pkt.header.packetType = PlaintextPacket;
    pkt.header.messageType = MsgChat;
    pkt.header.payloadLength = UINT32_MAX; /* triggers overflow check */
    pkt.header.sequenceID = 0;
    pkt.payload = NULL;

    enum { BufSize = 128 };
    uint8_t buffer[BufSize];
    size_t serializedSize = 0;

    ASSERT_INT_EQ(packetSerialize(&pkt, buffer, BufSize, &serializedSize),
                  PROTOCOL_FAIL);
}

/** @brief packetDeserialize with payloadLength near SIZE_MAX (overflow). */
static void testDeserializePayloadLengthOverflow(void) {
    /* Craft a header with payloadLength = SIZE_MAX. */
    PacketHeader hdr;
    hdr.magic = PACKET_MAGIC;
    hdr.packetType = PlaintextPacket;
    hdr.messageType = MsgChat;
    hdr.payloadLength = UINT32_MAX;
    hdr.sequenceID = 0;

    uint8_t buffer[sizeof(PacketHeader)];
    memcpy(buffer, &hdr, sizeof(PacketHeader));

    Packet result;
    result.payload = NULL;
    ASSERT_INT_EQ(packetDeserialize(buffer, sizeof(buffer), &result),
                  PROTOCOL_FAIL);
}

/** @brief KeyExchangePacketPayload has correct size and layout. */
static void testKeyExchangePayloadLayout(void) {
    ASSERT_UINT_EQ(offsetof(KeyExchangePacketPayload, publicKey), (size_t)0);
    ASSERT_UINT_EQ(sizeof(KeyExchangePacketPayload),
                   (size_t)ECDH_PUBLIC_KEY_SIZE);
}

/** @brief LoginRequestPayload survives write-then-read roundtrip. */
static void testLoginPayloadRoundtrip(void) {
    enum { PwLen = 5 };
    const char *un = "testuser";
    const char *pw = "hello";
    size_t totalLen = offsetof(LoginRequestPayload, password) + PwLen;
    uint8_t *buf = calloc(1, totalLen);
    ASSERT_TRUE(buf != NULL);

    LoginRequestPayload *wr = (LoginRequestPayload *)buf;
    memcpy(wr->username, un, strlen(un) + 1);
    memcpy(wr->password, pw, PwLen);

    LoginRequestPayload *rd = (LoginRequestPayload *)buf;
    ASSERT_STR_EQ(rd->username, un);
    ASSERT_MEM_EQ(rd->password, pw, PwLen);

    free(buf);
}

/** @brief RegisterRequestPayload survives write-then-read roundtrip. */
static void testRegisterPayloadRoundtrip(void) {
    enum { PwLen = 5 };
    const char *un = "reguser";
    const char *nn = "MyNick";
    const char *pw = "abcde";
    size_t totalLen = offsetof(RegisterRequestPayload, password) + PwLen;
    uint8_t *buf = calloc(1, totalLen);
    ASSERT_TRUE(buf != NULL);

    RegisterRequestPayload *wr = (RegisterRequestPayload *)buf;
    memcpy(wr->username, un, strlen(un) + 1);
    memcpy(wr->nickname, nn, strlen(nn) + 1);
    memcpy(wr->password, pw, PwLen);

    RegisterRequestPayload *rd = (RegisterRequestPayload *)buf;
    ASSERT_STR_EQ(rd->username, un);
    ASSERT_STR_EQ(rd->nickname, nn);
    ASSERT_MEM_EQ(rd->password, pw, PwLen);

    free(buf);
}

/** @brief LoginResponsePayload is 68 bytes with correct field layout. */
static void testLoginResponsePayloadRoundtrip(void) {
    const char *un = "user";
    const char *nn = "tester";
    const uint32_t testUid = 42;
    LoginResponsePayload resp;
    memset(&resp, 0, sizeof(resp));
    resp.uid = testUid;
    memcpy(resp.username, un, strlen(un) + 1);
    memcpy(resp.nickname, nn, strlen(nn) + 1);

    ASSERT_UINT_EQ(resp.uid, testUid);
    ASSERT_STR_EQ(resp.username, un);
    ASSERT_STR_EQ(resp.nickname, nn);
}

/** @brief LoginRequestPayload survives packetInit → serialize → deserialize
 *  protocol roundtrip with all fields intact. */
static void testLoginPayloadProtocolRoundtrip(void) {
    enum { PwLen = 6 };
    const char *un = "proto_user";
    const char *pw = "secret";
    size_t payloadLen = offsetof(LoginRequestPayload, password) + PwLen;
    LoginRequestPayload *pl = calloc(1, payloadLen);
    ASSERT_TRUE(pl != NULL);
    memcpy(pl->username, un, strlen(un) + 1);
    memcpy(pl->password, pw, PwLen);

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    ASSERT_INT_EQ(packetInit(&pkt, MsgLoginReq, 5, PlaintextPacket, pl,
                             payloadLen),
                  PROTOCOL_SUCC);

    /* Serialize to wire format */
    uint8_t buf[TestSerBufSize];
    size_t serLen = 0;
    ASSERT_INT_EQ(packetSerialize(&pkt, buf, sizeof(buf), &serLen),
                  PROTOCOL_SUCC);
    packetClear(&pkt);

    /* Deserialize back — verify header and payload match */
    Packet pkt2;
    memset(&pkt2, 0, sizeof(pkt2));
    ASSERT_INT_EQ(packetDeserialize(buf, serLen, &pkt2), PROTOCOL_SUCC);
    ASSERT_INT_EQ(pkt2.header.messageType, MsgLoginReq);
    ASSERT_UINT_EQ(pkt2.header.payloadLength, (uint32_t)payloadLen);

    LoginRequestPayload *rd = (LoginRequestPayload *)pkt2.payload;
    ASSERT_STR_EQ(rd->username, un);
    ASSERT_MEM_EQ(rd->password, pw, PwLen);

    packetClear(&pkt2);
    free(pl);
}

/** @brief RegisterRequestPayload survives packetInit → serialize → deserialize
 *  protocol roundtrip with all fields intact. */
static void testRegisterPayloadProtocolRoundtrip(void) {
    enum { PwLen = 6 };
    const char *un = "reg_proto";
    const char *nn = "RegNick";
    const char *pw = "abcdef";
    size_t payloadLen = offsetof(RegisterRequestPayload, password) + PwLen;
    RegisterRequestPayload *pl = calloc(1, payloadLen);
    ASSERT_TRUE(pl != NULL);
    memcpy(pl->username, un, strlen(un) + 1);
    memcpy(pl->nickname, nn, strlen(nn) + 1);
    memcpy(pl->password, pw, PwLen);

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    ASSERT_INT_EQ(packetInit(&pkt, MsgRegisterReq, 7, PlaintextPacket, pl,
                             payloadLen),
                  PROTOCOL_SUCC);

    uint8_t buf[TestSerBufSize];
    size_t serLen = 0;
    ASSERT_INT_EQ(packetSerialize(&pkt, buf, sizeof(buf), &serLen),
                  PROTOCOL_SUCC);
    packetClear(&pkt);

    Packet pkt2;
    memset(&pkt2, 0, sizeof(pkt2));
    ASSERT_INT_EQ(packetDeserialize(buf, serLen, &pkt2), PROTOCOL_SUCC);
    ASSERT_INT_EQ(pkt2.header.messageType, MsgRegisterReq);
    ASSERT_UINT_EQ(pkt2.header.payloadLength, (uint32_t)payloadLen);

    RegisterRequestPayload *rd = (RegisterRequestPayload *)pkt2.payload;
    ASSERT_STR_EQ(rd->username, un);
    ASSERT_STR_EQ(rd->nickname, nn);
    ASSERT_MEM_EQ(rd->password, pw, PwLen);

    packetClear(&pkt2);
    free(pl);
}

/** @brief LoginResponsePayload (fixed 68 bytes) survives packetInit →
 *  serialize → deserialize protocol roundtrip. */
static void testLoginResponsePayloadProtocolRoundtrip(void) {
    const char *un = "luser";
    const char *nn = "lnick";
    const uint32_t testUid = 77;
    LoginResponsePayload resp;
    memset(&resp, 0, sizeof(resp));
    resp.uid = testUid;
    memcpy(resp.username, un, strlen(un) + 1);
    memcpy(resp.nickname, nn, strlen(nn) + 1);

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    ASSERT_INT_EQ(packetInit(&pkt, MsgLoginResp, 3, PlaintextPacket, &resp,
                             sizeof(resp)),
                  PROTOCOL_SUCC);

    uint8_t buf[TestSerBufSize];
    size_t serLen = 0;
    ASSERT_INT_EQ(packetSerialize(&pkt, buf, sizeof(buf), &serLen),
                  PROTOCOL_SUCC);
    packetClear(&pkt);

    Packet pkt2;
    memset(&pkt2, 0, sizeof(pkt2));
    ASSERT_INT_EQ(packetDeserialize(buf, serLen, &pkt2), PROTOCOL_SUCC);
    ASSERT_INT_EQ(pkt2.header.messageType, MsgLoginResp);
    ASSERT_UINT_EQ(pkt2.header.payloadLength, sizeof(LoginResponsePayload));

    LoginResponsePayload *rd = (LoginResponsePayload *)pkt2.payload;
    ASSERT_UINT_EQ(rd->uid, testUid);
    ASSERT_STR_EQ(rd->username, un);
    ASSERT_STR_EQ(rd->nickname, nn);

    packetClear(&pkt2);
}

/** @brief MessageType enum has exactly 15 values. */
static void testMessageTypeCount(void) {
    ASSERT_INT_EQ(MsgGameStop, 17);
}

/* ═══════════════════════  main  ════════════════════════════════════════ */

/**
 * @brief Entry point for the protocol test suite.
 *
 * @return 0 if all tests passed, 1 if any test failed.
 */
int main(void) {
    printf("test_protocol:\n");

    /* 1. Constants & Enums */
    RUN_TEST(testPacketMagicValue);
    RUN_TEST(testMaxPayloadLen);
    RUN_TEST(testAESPacketExtraLen);
    RUN_TEST(testPacketTypeValues);
    RUN_TEST(testMessageTypeValues);
    RUN_TEST(testNullSocketFD);
    RUN_TEST(testProtocolReturnCodes);

    /* 2. PacketHeader Layout */
    RUN_TEST(testPacketHeaderSize);
    RUN_TEST(testPacketHeaderFieldOffsets);
    RUN_TEST(testPacketHeaderFieldValues);

    /* 2.5. Application Payload Struct Layouts */
    RUN_TEST(testLoginRequestPayloadOffsets);
    RUN_TEST(testLoginRequestPayloadSize);
    RUN_TEST(testRegisterRequestPayloadOffsets);
    RUN_TEST(testRegisterRequestPayloadSize);
    RUN_TEST(testLoginResponsePayloadSize);
    RUN_TEST(testLoginResponsePayloadOffsets);
    RUN_TEST(testChatPacketPayloadOffsets);
    RUN_TEST(testChatPacketPayloadSize);
    RUN_TEST(testChatBroadcastPayloadOffsets);
    RUN_TEST(testChatBroadcastPayloadSize);

    /* 3. packetClear */
    RUN_TEST(testPacketClearFreesPayload);
    RUN_TEST(testPacketClearNullPayload);
    RUN_TEST(testPacketClearIdempotent);

    /* 4. packetSerialize */
    RUN_TEST(testSerializeSuccess);
    RUN_TEST(testSerializeHeaderContent);
    RUN_TEST(testSerializeNullPacket);
    RUN_TEST(testSerializeNullBuffer);
    RUN_TEST(testSerializeNullSizeOut);
    RUN_TEST(testSerializeBufferTooSmall);
    RUN_TEST(testSerializeZeroPayload);
    RUN_TEST(testSerializeExactBufferSize);
    RUN_TEST(testSerializeOneByteShort);
    RUN_TEST(testSerializeOversizedBufferUntouched);

    /* 5. packetDeserialize */
    RUN_TEST(testDeserializeSuccess);
    RUN_TEST(testDeserializeNullBuffer);
    RUN_TEST(testDeserializeNullPacket);
    RUN_TEST(testDeserializePayloadNotNull);
    RUN_TEST(testDeserializeBufferTooSmallForHeader);
    RUN_TEST(testDeserializeInvalidMagic);
    RUN_TEST(testDeserializeBufferTooSmallForPayload);
    RUN_TEST(testDeserializeZeroPayload);
    RUN_TEST(testDeserializeBufferWithTrailingBytes);

    /* 6. Serialize / Deserialize Roundtrip */
    RUN_TEST(testSerializeDeserializeRoundtrip);
    RUN_TEST(testSerializeDeserializeMaxPayload);
    RUN_TEST(testSerializeDeserializeBinaryPayload);

    /* 7. packetAESEncrypt */
    RUN_TEST(testAESEncryptSuccess);
    RUN_TEST(testAESEncryptNullPacket);
    RUN_TEST(testAESEncryptNullKey);
    RUN_TEST(testAESEncryptNullPayload);
    RUN_TEST(testAESEncryptWrongPacketType);
    RUN_TEST(testAESEncryptPayloadTooLarge);
    RUN_TEST(testAESEncryptExactlyMaxPayload);
    RUN_TEST(testAESEncryptZeroPayload);
    RUN_TEST(testAESEncryptPreservesHeaderFields);

    /* 8. packetAESDecrypt */
    RUN_TEST(testAESDecryptNullPacket);
    RUN_TEST(testAESDecryptNullKey);
    RUN_TEST(testAESDecryptNullPayload);
    RUN_TEST(testAESDecryptWrongPacketType);
    RUN_TEST(testAESDecryptPayloadTooShort);

    /* 9. AES Encrypt / Decrypt Roundtrip & Tamper Resistance */
    RUN_TEST(testAESRoundtrip);
    RUN_TEST(testAESRoundtripMinPayload);
    RUN_TEST(testAESRoundtripMaxPayload);
    RUN_TEST(testAESRoundtripBinaryPayload);
    RUN_TEST(testAESDecryptWrongKey);
    RUN_TEST(testAESDecryptTamperedCiphertext);
    RUN_TEST(testAESDecryptTamperedTag);
    RUN_TEST(testAESDecryptTamperedNonce);
    RUN_TEST(testAESDecryptTamperedSequenceID);
    RUN_TEST(testAESDecryptPreservesHeaderFields);
    RUN_TEST(testAESEncryptNonDeterministic);
    RUN_TEST(testAESRoundtripMultipleSequenceIDs);

    /* 10. Full Pipeline */
    RUN_TEST(testFullPipelineRoundtrip);

    /* 11. packetSend / packetRecv */
    RUN_TEST(testPacketSendNullPacket);
    RUN_TEST(testPacketSendNullPayload);
    RUN_TEST(testPacketRecvNullDest);
    RUN_TEST(testPacketRecvNonNullPayload);
    RUN_TEST(testPacketSendRecvRoundtrip);
    RUN_TEST(testPacketSendRecvEncrypted);
    RUN_TEST(testPacketRecvInvalidMagic);
    RUN_TEST(testPacketRecvOversizedPayload);
    RUN_TEST(testPacketRecvPeerClosed);

    /* 12. socket setup / close */
    RUN_TEST(testSocketCloseSetsSentinel);
    RUN_TEST(testSocketCloseNegativeFD);
    RUN_TEST(testSocketCloseRealFD);
    RUN_TEST(testServerSetupEphemeralPort);
    RUN_TEST(testClientSetupInvalidAddress);
    RUN_TEST(testClientSetupConnectionRefused);

    /* 13. Security Hardening */
    RUN_TEST(testPacketClearNull);
    RUN_TEST(testSocketCloseNull);
    RUN_TEST(testClientSetupNullAddress);
    RUN_TEST(testDeserializePayloadLengthExceedsMax);
    RUN_TEST(testSerializePayloadLengthOverflow);
    RUN_TEST(testDeserializePayloadLengthOverflow);

    /* 14. Additional Layout & Roundtrip */
    RUN_TEST(testKeyExchangePayloadLayout);
    RUN_TEST(testLoginPayloadRoundtrip);
    RUN_TEST(testRegisterPayloadRoundtrip);
    RUN_TEST(testLoginResponsePayloadRoundtrip);
    RUN_TEST(testLoginPayloadProtocolRoundtrip);
    RUN_TEST(testRegisterPayloadProtocolRoundtrip);
    RUN_TEST(testLoginResponsePayloadProtocolRoundtrip);
    RUN_TEST(testMessageTypeCount);

    return TEST_REPORT();
}
