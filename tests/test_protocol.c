/**
 * @file test_protocol.c
 * @brief Unit tests for the PacPlay binary protocol definitions.
 *
 * Validates struct layout, field offsets, magic constant, message type
 * enum values, and payload size — all of which must remain stable to
 * guarantee wire-format compatibility.
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

#include <string.h>

/**
 * @brief Expected PacketHeader layout constants for test assertions.
 *
 * Named constants that mirror the wire-format specification so that
 * test code avoids bare magic numbers.
 */
enum {
    ExpectedHeaderSize = 14,        /**< Total PacketHeader size in bytes. */
    ExpectedMagicFieldOffset = 0,   /**< Byte offset of the magic field. */
    ExpectedLengthFieldOffset = 4,  /**< Byte offset of the length field. */
    ExpectedTypeFieldOffset = 8,    /**< Byte offset of the type field. */
    ExpectedSeqFieldOffset = 10     /**< Byte offset of the seq field. */
};

/**
 * @brief Verify that PacketHeader is exactly 14 bytes.
 *
 * PacketHeader must be exactly 14 bytes with @c #pragma @c pack(push,1).
 * If this breaks, the wire format is incompatible.
 */
static void testPacketHeaderSize(void) {
    ASSERT_UINT_EQ(sizeof(PacketHeader), ExpectedHeaderSize);
}

/**
 * @brief Verify PACKET_MAGIC matches the documented ASCII 'PPPM' value.
 *
 * The magic number is the first four bytes of every packet and is used
 * for frame synchronisation.
 */
static void testPacketMagicValue(void) {
    ASSERT_UINT_EQ(PACKET_MAGIC, 0x5050504DU);
}

/**
 * @brief Verify field offsets inside the packed struct.
 *
 * Serialisation and deserialisation code relies on deterministic field
 * offsets within the packed PacketHeader. Any change here indicates a
 * binary-incompatible layout shift.
 */
static void testPacketHeaderFieldOffsets(void) {
    ASSERT_UINT_EQ(offsetof(PacketHeader, magic), ExpectedMagicFieldOffset);
    ASSERT_UINT_EQ(offsetof(PacketHeader, length), ExpectedLengthFieldOffset);
    ASSERT_UINT_EQ(offsetof(PacketHeader, type), ExpectedTypeFieldOffset);
    ASSERT_UINT_EQ(offsetof(PacketHeader, seq), ExpectedSeqFieldOffset);
}

/**
 * @brief Fill a PacketHeader and verify each field independently.
 *
 * Ensures that writing to one field does not corrupt adjacent fields in
 * the packed structure.
 */
static void testPacketHeaderFieldValues(void) {
    enum { TestLength = 128, TestSeq = 42 };

    PacketHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = PACKET_MAGIC;
    hdr.length = TestLength;
    hdr.type = (uint16_t)MsgChat;
    hdr.seq = TestSeq;

    ASSERT_UINT_EQ(hdr.magic, PACKET_MAGIC);
    ASSERT_UINT_EQ(hdr.length, TestLength);
    ASSERT_UINT_EQ(hdr.type, MsgChat);
    ASSERT_UINT_EQ(hdr.seq, TestSeq);
}

/**
 * @brief Verify that MessageType enum values remain stable.
 *
 * These values define the wire protocol; changing them would break
 * interoperability between different client/server versions.
 */
static void testMessageTypeValues(void) {
    ASSERT_INT_EQ(MsgLoginReq, 1);
    ASSERT_INT_EQ(MsgLoginResp, 2);
    ASSERT_INT_EQ(MsgChat, 3);
    ASSERT_INT_EQ(MsgCreateRoom, 4);
    ASSERT_INT_EQ(MsgJoinRoom, 5);
    ASSERT_INT_EQ(MsgGameStart, 6);
    ASSERT_INT_EQ(MsgHeartbeat, 7);
}

/**
 * @brief Verify MAX_PAYLOAD_SIZE is positive and matches the documented value.
 *
 * The payload size constant determines the maximum user-data length per
 * packet and must not change without a corresponding protocol version bump.
 */
static void testMaxPayloadSize(void) {
    enum { ExpectedMaxPayload = 1024 };
    ASSERT_UINT_EQ(MAX_PAYLOAD_SIZE, ExpectedMaxPayload);
    ASSERT_TRUE(MAX_PAYLOAD_SIZE > 0);
}

/**
 * @brief Entry point for the protocol test suite.
 *
 * @return 0 if all tests passed, 1 if any test failed.
 */
int main(void) {
    printf("test_protocol:\n");

    RUN_TEST(testPacketHeaderSize);
    RUN_TEST(testPacketMagicValue);
    RUN_TEST(testPacketHeaderFieldOffsets);
    RUN_TEST(testPacketHeaderFieldValues);
    RUN_TEST(testMessageTypeValues);
    RUN_TEST(testMaxPayloadSize);

    return TEST_REPORT();
}
