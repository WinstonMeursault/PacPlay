/**
 * @file test_social_protocol.c
 * @brief Unit tests for PacPlay social system protocol types.
 *
 * Covers new MessageType values (Friend/Group range),
 * payload struct layout and serialisation round-trips,
 * and AES-256-GCM encrypt/decrypt for social packets.
 *
 * @date 2026-06-21
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
#include "protocol.h"
#include "test_utils.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────── helper constants for readability ──────────────────── */

enum {
    TestSerBufSize = 4096,
    TestTimestamp1700M = 1700000000,
    TestTimestamp1700050 = 1700000500,
    TestTimestamp1710M = 1710000000ULL,
    TestUid42 = 42,
    TestUid99 = 99,
    TestGroupId500 = 500,
    TestMemberCount10 = 10,
    TestGroupId777 = 777,
    TestGroupId999 = 999,
    TestMsgTypeFriendReq = 55,
    TestMsgTypePrivateChat = 66,
    TestRoomId1234 = 1234,
    TestByteValue = 0xDD
};

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

/* ──────────────────────────────── helpers ───────────────────────────────── */

/**
 * @brief Serialize a struct payload into a Packet, round-trip through
 * serialize/deserialize, and return the deserialized payload pointer.
 *
 * The caller owns both the original Packet *orig and the restored Packet
 * *pkt.  Call packetClear() on both when done.
 */
static int socialRoundtrip(const void *data, size_t dataLen,
                           MessageType msgType, Packet *pkt) {
    memset(pkt, 0, sizeof(*pkt));
    pkt->payload = NULL;

    int ret = packetInit(pkt, msgType, 1, PlaintextPacket, data, dataLen);
    if (ret != PROTOCOL_SUCC) {
        return ret;
    }

    uint8_t buf[TestSerBufSize];
    size_t serializedSize = 0;
    ret = packetSerialize(pkt, buf, sizeof(buf), &serializedSize);
    if (ret != PROTOCOL_SUCC) {
        packetClear(pkt);
        return ret;
    }

    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;
    ret = packetDeserialize(buf, serializedSize, &restored);
    if (ret != PROTOCOL_SUCC) {
        packetClear(pkt);
        return ret;
    }

    /* Steal restored fields into pkt and cleanup the container */
    packetClear(pkt);
    *pkt = restored;
    return PROTOCOL_SUCC;
}

/* ═════════════════════ 1. New MessageType Values ═══════════════════════════
 */

/** @brief Verify new social MessageType enum values are stable. */
static void testNewMessageTypeValues(void) {
    /* Friend system */
    ASSERT_INT_EQ(MsgFriendRequest, TestMsgTypeFriendReq);
    ASSERT_INT_EQ(MsgFriendRequestResp, 56);
    ASSERT_INT_EQ(MsgFriendAccept, 57);
    ASSERT_INT_EQ(MsgFriendAcceptResp, 58);
    ASSERT_INT_EQ(MsgFriendReject, 59);
    ASSERT_INT_EQ(MsgFriendDelete, 60);
    ASSERT_INT_EQ(MsgFriendDeleteResp, 61);
    ASSERT_INT_EQ(MsgFriendListReq, 62);
    ASSERT_INT_EQ(MsgFriendListResp, 63);
    ASSERT_INT_EQ(MsgFriendNotify, 64);

    /* Private chat */
    ASSERT_INT_EQ(MsgPrivateChat, 65);
    ASSERT_INT_EQ(MsgPrivateChatBroadcast, TestMsgTypePrivateChat);
    ASSERT_INT_EQ(MsgPrivateChatHistoryReq, 67);
    ASSERT_INT_EQ(MsgPrivateChatHistoryResp, 68);
    ASSERT_INT_EQ(MsgPrivateChatNotify, 69);

    /* Group chat */
    ASSERT_INT_EQ(MsgGroupCreate, 70);
    ASSERT_INT_EQ(MsgGroupCreateResp, 71);
    ASSERT_INT_EQ(MsgGroupJoin, 72);
    ASSERT_INT_EQ(MsgGroupJoinResp, 73);
    ASSERT_INT_EQ(MsgGroupQuit, 74);
    ASSERT_INT_EQ(MsgGroupQuitResp, 75);
    ASSERT_INT_EQ(MsgGroupListReq, 76);
    ASSERT_INT_EQ(MsgGroupListResp, 77);
    ASSERT_INT_EQ(MsgGroupChat, 78);
    ASSERT_INT_EQ(MsgGroupChatBroadcast, 79);
    ASSERT_INT_EQ(MsgGroupMemberJoin, 80);
    ASSERT_INT_EQ(MsgGroupMemberQuit, 81);
    ASSERT_INT_EQ(MsgGroupKick, 82);
    ASSERT_INT_EQ(MsgGroupKickResp, 83);
    ASSERT_INT_EQ(MsgGroupDisband, 84);
    ASSERT_INT_EQ(MsgGroupDisbandNotify, 85);
}

/* ════════════════ 2. FriendOpPayload Round-Trip ════════════════ */

/** @brief FriendOpPayload serializes and deserializes byte-identically. */
static void testFriendOpPayloadRoundTrip(void) {
    enum { TestTargetUid = 12345U };
    FriendOpPayload orig;
    memset(&orig, 0, sizeof(orig));
    orig.targetUid = TestTargetUid;

    Packet pkt;
    int ret = socialRoundtrip(&orig, sizeof(orig), MsgFriendRequest, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(FriendOpPayload));

    const FriendOpPayload *restored = (const FriendOpPayload *)pkt.payload;
    ASSERT_UINT_EQ(restored->targetUid, TestTargetUid);

    packetClear(&pkt);
}

/* ════════════════ 3. FriendInfo Round-Trip ════════════════ */

/** @brief FriendInfo with all fields set round-trips byte-identically. */
static void testFriendInfoRoundTrip(void) {
    enum { TestUid = 200U };
    FriendInfo orig;
    memset(&orig, 0, sizeof(orig));
    orig.uid = TestUid;
    strcpy(orig.username, "friend_user");
    strcpy(orig.nickname, "FriendNick");
    orig.online = 1;

    Packet pkt;
    int ret = socialRoundtrip(&orig, sizeof(orig), MsgFriendListResp, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(FriendInfo));

    const FriendInfo *restored = (const FriendInfo *)pkt.payload;
    ASSERT_UINT_EQ(restored->uid, TestUid);
    ASSERT_STR_EQ(restored->username, "friend_user");
    ASSERT_STR_EQ(restored->nickname, "FriendNick");
    ASSERT_UINT_EQ(restored->online, 1);
    ASSERT_MEM_EQ(restored, &orig, sizeof(FriendInfo));

    packetClear(&pkt);
}

/** @brief Zeroed FriendInfo round-trips correctly (all fields zero). */
static void testFriendInfoZeroRoundTrip(void) {
    FriendInfo orig;
    memset(&orig, 0, sizeof(orig));

    Packet pkt;
    int ret = socialRoundtrip(&orig, sizeof(orig), MsgFriendListResp, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(FriendInfo));

    const FriendInfo *restored = (const FriendInfo *)pkt.payload;
    ASSERT_UINT_EQ(restored->uid, 0);
    ASSERT_UINT_EQ(restored->online, 0);
    ASSERT_STR_EQ(restored->username, "");
    ASSERT_STR_EQ(restored->nickname, "");
    ASSERT_MEM_EQ(restored, &orig, sizeof(FriendInfo));

    packetClear(&pkt);
}

/* ════════════════ 4. PrivateChatPayload Round-Trip ════════════════ */

/** @brief PrivateChatPayload with message "hello" round-trips correctly. */
static void testPrivateChatPayloadRoundTrip(void) {
    enum { TestFromUid = 100U, TestToUid = 200U, TestMsgId = 1U };
    const char testMsg[] = "hello";
    size_t payloadSize = sizeof(PrivateChatPayload) + sizeof(testMsg);
    uint8_t *buf = calloc(1, payloadSize);
    ASSERT_NOT_NULL(buf);

    PrivateChatPayload *orig = (PrivateChatPayload *)buf;
    orig->fromUid = TestFromUid;
    orig->toUid = TestToUid;
    orig->msgId = TestMsgId;
    orig->timestamp = TestTimestamp1700M;
    memcpy(orig->message, testMsg, sizeof(testMsg));

    Packet pkt;
    int ret = socialRoundtrip(orig, payloadSize, MsgPrivateChat, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    const PrivateChatPayload *restored =
        (const PrivateChatPayload *)pkt.payload;
    ASSERT_UINT_EQ(restored->fromUid, TestFromUid);
    ASSERT_UINT_EQ(restored->toUid, TestToUid);
    ASSERT_UINT_EQ(restored->msgId, TestMsgId);
    ASSERT_INT_EQ((int)restored->timestamp, TestTimestamp1700M);
    ASSERT_STR_EQ((const char *)restored->message, "hello");
    ASSERT_MEM_EQ(restored, orig, payloadSize);

    packetClear(&pkt);
    free(buf);
}

/** @brief PrivateChatPayload with minimum payload (just NUL terminator). */
static void testPrivateChatPayloadEmpty(void) {
    const char testMsg[] = "";
    size_t payloadSize = sizeof(PrivateChatPayload) + sizeof(testMsg);
    uint8_t *buf = calloc(1, payloadSize);
    ASSERT_NOT_NULL(buf);

    PrivateChatPayload *orig = (PrivateChatPayload *)buf;
    orig->fromUid = TestUid42;
    orig->toUid = TestUid99;
    orig->msgId = 0;
    orig->timestamp = 0;
    orig->message[0] = '\0';

    Packet pkt;
    int ret = socialRoundtrip(orig, payloadSize, MsgPrivateChat, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    const PrivateChatPayload *restored =
        (const PrivateChatPayload *)pkt.payload;
    ASSERT_UINT_EQ(restored->fromUid, TestUid42);
    ASSERT_UINT_EQ(restored->toUid, TestUid99);
    ASSERT_UINT_EQ(restored->msgId, 0);
    ASSERT_STR_EQ((const char *)restored->message, "");

    packetClear(&pkt);
    free(buf);
}

/* ════════════════ 5. GroupCreatePayload Round-Trip ════════════════ */

/** @brief GroupCreatePayload with name "TestGroup" round-trips. */
static void testGroupCreatePayloadRoundTrip(void) {
    GroupCreatePayload orig;
    memset(&orig, 0, sizeof(orig));
    strcpy(orig.groupName, "TestGroup");

    Packet pkt;
    int ret = socialRoundtrip(&orig, sizeof(orig), MsgGroupCreate, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(GroupCreatePayload));

    const GroupCreatePayload *restored =
        (const GroupCreatePayload *)pkt.payload;
    ASSERT_STR_EQ(restored->groupName, "TestGroup");
    ASSERT_MEM_EQ(restored, &orig, sizeof(GroupCreatePayload));

    packetClear(&pkt);
}

/* ════════════════ 6. GroupInfo Round-Trip ════════════════ */

/** @brief GroupInfo with all fields set round-trips byte-identically. */
static void testGroupInfoRoundTrip(void) {
    GroupInfo orig;
    memset(&orig, 0, sizeof(orig));
    orig.groupId = TestGroupId500;
    strcpy(orig.groupName, "AlphaGroup");
    orig.ownerUid = TestMemberCount10;
    orig.memberCount = 3;
    orig.createdAt = TestTimestamp1710M;

    Packet pkt;
    int ret = socialRoundtrip(&orig, sizeof(orig), MsgGroupListResp, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(GroupInfo));

    const GroupInfo *restored = (const GroupInfo *)pkt.payload;
    ASSERT_UINT_EQ(restored->groupId, TestGroupId500);
    ASSERT_STR_EQ(restored->groupName, "AlphaGroup");
    ASSERT_UINT_EQ(restored->ownerUid, TestMemberCount10);
    ASSERT_UINT_EQ(restored->memberCount, 3);
    ASSERT_UINT_EQ(restored->createdAt, TestTimestamp1710M);
    ASSERT_MEM_EQ(restored, &orig, sizeof(GroupInfo));

    packetClear(&pkt);
}

/* ═══════════════ 7. GroupChatBroadcastPayload Round-Trip ═══════════════ */

/** @brief GroupChatBroadcastPayload with message round-trips. */
static void testGroupChatBroadcastPayloadRoundTrip(void) {
    enum { TestGroupId = 100U, TestUid = 200U, TestMsgId = 7U };
    const char testMsg[] = "Hello group!";
    size_t payloadSize = sizeof(GroupChatBroadcastPayload) + sizeof(testMsg);
    uint8_t *buf = calloc(1, payloadSize);
    ASSERT_NOT_NULL(buf);

    GroupChatBroadcastPayload *orig = (GroupChatBroadcastPayload *)buf;
    orig->groupId = TestGroupId;
    orig->uid = TestUid;
    orig->msgId = TestMsgId;
    orig->timestamp = TestTimestamp1700050;
    memcpy(orig->message, testMsg, sizeof(testMsg));

    Packet pkt;
    int ret = socialRoundtrip(orig, payloadSize, MsgGroupChatBroadcast, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    const GroupChatBroadcastPayload *restored =
        (const GroupChatBroadcastPayload *)pkt.payload;
    ASSERT_UINT_EQ(restored->groupId, TestGroupId);
    ASSERT_UINT_EQ(restored->uid, TestUid);
    ASSERT_UINT_EQ(restored->msgId, TestMsgId);
    ASSERT_INT_EQ((int)restored->timestamp, TestTimestamp1700050);
    ASSERT_STR_EQ((const char *)restored->message, "Hello group!");
    ASSERT_MEM_EQ(restored, orig, payloadSize);

    packetClear(&pkt);
    free(buf);
}

/* ════════════════ 8. GroupKickPayload Round-Trip ════════════════ */

/** @brief GroupKickPayload with groupId and targetUid round-trips. */
static void testKickPayloadRoundTrip(void) {
    GroupKickPayload orig;
    memset(&orig, 0, sizeof(orig));
    orig.groupId = TestUid42;
    orig.targetUid = TestGroupId777;

    Packet pkt;
    int ret = socialRoundtrip(&orig, sizeof(orig), MsgGroupKick, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(GroupKickPayload));

    const GroupKickPayload *restored = (const GroupKickPayload *)pkt.payload;
    ASSERT_UINT_EQ(restored->groupId, TestUid42);
    ASSERT_UINT_EQ(restored->targetUid, TestGroupId777);
    ASSERT_MEM_EQ(restored, &orig, sizeof(GroupKickPayload));

    packetClear(&pkt);
}

/* ═════════════ 9. GroupDisbandNotifyPayload Round-Trip ═════════════ */

/** @brief GroupDisbandNotifyPayload round-trips correctly. */
static void testDisbandNotifyPayloadRoundTrip(void) {
    GroupDisbandNotifyPayload orig;
    memset(&orig, 0, sizeof(orig));
    orig.groupId = TestGroupId999;

    Packet pkt;
    int ret = socialRoundtrip(&orig, sizeof(orig), MsgGroupDisbandNotify, &pkt);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(GroupDisbandNotifyPayload));

    const GroupDisbandNotifyPayload *restored =
        (const GroupDisbandNotifyPayload *)pkt.payload;
    ASSERT_UINT_EQ(restored->groupId, TestGroupId999);
    ASSERT_MEM_EQ(restored, &orig, sizeof(GroupDisbandNotifyPayload));

    packetClear(&pkt);
}

/* ═══════════════ 10. Encrypted Social Packet Round-Trip ═══════════════ */

/** @brief Encrypt/decrypt round-trip with a social protocol payload. */
static void testEncryptedSocialPacketRoundTrip(void) {
    GroupKickPayload orig;
    memset(&orig, 0, sizeof(orig));
    orig.groupId = TestMsgTypeFriendReq;
    orig.targetUid = TestMsgTypePrivateChat;

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;
    int ret =
        packetInit(&pkt, MsgGroupKick, 1, PlaintextPacket, &orig, sizeof(orig));
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ(pkt.header.packetType, AES256GCMPacket);

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ(pkt.header.packetType, PlaintextPacket);
    ASSERT_UINT_EQ(pkt.header.payloadLength, sizeof(GroupKickPayload));

    const GroupKickPayload *restored = (const GroupKickPayload *)pkt.payload;
    ASSERT_UINT_EQ(restored->groupId, TestMsgTypeFriendReq);
    ASSERT_UINT_EQ(restored->targetUid, TestMsgTypePrivateChat);
    ASSERT_MEM_EQ(restored, &orig, sizeof(GroupKickPayload));

    packetClear(&pkt);
}

/* ════════════════ 11. Social Packet Wrong Key ════════════════ */

/** @brief Decrypting a social packet with the wrong key returns AUTH_FAIL. */
static void testSocialPacketWrongKey(void) {
    FriendOpPayload orig;
    memset(&orig, 0, sizeof(orig));
    orig.targetUid = TestRoomId1234;

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;
    int ret = packetInit(&pkt, MsgFriendRequest, 1, PlaintextPacket, &orig,
                         sizeof(orig));
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESDecrypt(&pkt, (uint8_t *)wrongAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_AUTH_FAIL);

    packetClear(&pkt);
}

/* ════════════════ 12. Social Packet MaxPayload ════════════════ */

/** @brief Social packet at MAX_PAYLOAD_LEN boundary encrypts/decrypts. */
static void testSocialPacketMaxPayload(void) {
    uint8_t *bigPayload = malloc(MAX_PAYLOAD_LEN);
    ASSERT_NOT_NULL(bigPayload);
    memset(bigPayload, TestByteValue, MAX_PAYLOAD_LEN);

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;
    int ret = packetInit(&pkt, MsgGroupChat, 1, PlaintextPacket, bigPayload,
                         MAX_PAYLOAD_LEN);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESEncrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESDecrypt(&pkt, (uint8_t *)testAESKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.payloadLength, MAX_PAYLOAD_LEN);
    ASSERT_MEM_EQ(pkt.payload, bigPayload, MAX_PAYLOAD_LEN);

    packetClear(&pkt);
    free(bigPayload);
}

/* ═══════════════════════════════ main ══════════════════════════════════════
 */

int main(void) {
    printf("\n=== Social Protocol Tests ===\n\n");

    RUN_TEST(testNewMessageTypeValues);

    RUN_TEST(testFriendOpPayloadRoundTrip);

    RUN_TEST(testFriendInfoRoundTrip);
    RUN_TEST(testFriendInfoZeroRoundTrip);

    RUN_TEST(testPrivateChatPayloadRoundTrip);
    RUN_TEST(testPrivateChatPayloadEmpty);

    RUN_TEST(testGroupCreatePayloadRoundTrip);
    RUN_TEST(testGroupInfoRoundTrip);
    RUN_TEST(testGroupChatBroadcastPayloadRoundTrip);
    RUN_TEST(testKickPayloadRoundTrip);
    RUN_TEST(testDisbandNotifyPayloadRoundTrip);

    RUN_TEST(testEncryptedSocialPacketRoundTrip);
    RUN_TEST(testSocialPacketWrongKey);
    RUN_TEST(testSocialPacketMaxPayload);

    return TEST_REPORT();
}
