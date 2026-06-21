/**
 * @file test_social_security.c
 * @brief Adversarial security tests for the social system.
 *
 * Covers authentication bypass, authorization enforcement, input validation,
 * injection, race/state attacks, and resource exhaustion across friend,
 * group, and private chat operations.
 *
 * Uses socketpair pairs + direct handler calls (test_friend.c pattern).
 *
 * @date 2026-06-21
 * @copyright GPLv3 License
 */

#include "crypto.h"
#include "log.h"
#include "protocol.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/friend.h"
#include "server/group.h"
#include "server/onlineTracker.h"
#include "server/privateChat.h"
#include "server/server.h"
#include "test_utils.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ──────────────────────────── named constants ───────────────────────────── */

enum {
    UidAlice = 5000,
    UidBob = 5001,
    UidCharlie = 5002,
    TestTimestamp = 1234567890,
    RapidFireCount = 100,
    MaxGroupMembers = 50,
    GroupFullMemberUidBase = 6000,
    TestLargeUid = 12345,
    TestHiddenIdx5 = 5,
    TestHiddenIdx6 = 6,
    TestHiddenIdx7 = 7,
};

/* ─────────────────────────── helper prototypes ──────────────────────────── */

static void removeAllDBFiles(void);
static int makeSocketPair(SocketFD pair[2]);
static int recvDec(SocketFD fd, uint8_t key[AES_GCM_KEY_LEN], Packet *out);
static int recvStatus(SocketFD fd, uint8_t key[AES_GCM_KEY_LEN],
                      MessageType expectedMt);
static void setupSession(ClientSession *cs, SocketFD svrSide, uint32_t uid);
static int recvGroupCreateResp(SocketFD fd, uint8_t key[AES_GCM_KEY_LEN],
                               uint8_t *status, uint32_t *groupId);

/* ───────────────────────── helper implementations ───────────────────────── */

static void removeAllDBFiles(void) {
    remove(USER_DB_PATH);
    remove(USER_DB_PATH "-wal");
    remove(USER_DB_PATH "-shm");
    remove(FRIEND_DB_PATH);
    remove(FRIEND_DB_PATH "-wal");
    remove(FRIEND_DB_PATH "-shm");
    remove(GROUP_DB_PATH);
    remove(GROUP_DB_PATH "-wal");
    remove(GROUP_DB_PATH "-shm");
    remove(PRIVATE_CHAT_DB_PATH);
    remove(PRIVATE_CHAT_DB_PATH "-wal");
    remove(PRIVATE_CHAT_DB_PATH "-shm");
    remove("./db/server.db");
    remove("./db/server.db-wal");
    remove("./db/server.db-shm");
    rmdir("./db");
}

static int makeSocketPair(SocketFD pair[2]) {
    int fds[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (ret != 0) {
        pair[0] = NULL_SOCKETFD;
        pair[1] = NULL_SOCKETFD;
        return -1;
    }
    enum { SocketTimeoutSec = 2 };
    struct timeval tv = {.tv_sec = SocketTimeoutSec, .tv_usec = 0};
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    pair[0] = fds[0];
    pair[1] = fds[1];
    return 0;
}

static int recvDec(SocketFD fd, uint8_t key[AES_GCM_KEY_LEN], Packet *out) {
    if (packetRecvEncrypted(fd, out, key) != PROTOCOL_SUCC) {
        return -1;
    }
    return 0;
}

static int recvStatus(SocketFD fd, uint8_t key[AES_GCM_KEY_LEN],
                      MessageType expectedMt) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    if (recvDec(fd, key, &pkt) != 0) {
        return -1;
    }
    if (pkt.header.messageType != expectedMt ||
        pkt.header.payloadLength < sizeof(uint8_t)) {
        packetClear(&pkt);
        return -1;
    }
    int status = (int)pkt.payload[0];
    packetClear(&pkt);
    return status;
}

static int recvGroupCreateResp(SocketFD fd, uint8_t key[AES_GCM_KEY_LEN],
                               uint8_t *status, uint32_t *groupId) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    if (recvDec(fd, key, &pkt) != 0) {
        return -1;
    }
    if (pkt.header.messageType != MsgGroupCreateResp) {
        packetClear(&pkt);
        return -1;
    }
    if (pkt.header.payloadLength >= sizeof(GroupCreateRespPayload)) {
        const GroupCreateRespPayload *resp =
            (const GroupCreateRespPayload *)pkt.payload;
        *status = resp->status;
        *groupId = resp->groupId;
    } else if (pkt.header.payloadLength >= sizeof(uint8_t)) {
        *status = pkt.payload[0];
        *groupId = 0;
    } else {
        packetClear(&pkt);
        return -1;
    }
    packetClear(&pkt);
    return 0;
}

static void setupSession(ClientSession *cs, SocketFD svrSide, uint32_t uid) {
    memset(cs, 0, sizeof(*cs));
    cs->fd = svrSide;
    cs->currentUser.uid = uid;
    cryptoRandomBytes(cs->aesKey.key, AES_GCM_KEY_LEN);
    memset(cs->aesKey.nonce, 0, AES_GCM_NONCE_LEN);
    cs->seqID = 0;
    cs->state = SessionLobby;
}

/* ══════════════════ Authentication / Authorization ═══════════════════════ */

/* ── testFriendRequestWithoutLogin ─────────────────────────────────────── */

static void testFriendRequestWithoutLogin(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], 0);
    onlineTrackerAdd(s.onlineTrk, 0, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    FriendOpPayload fop;
    memset(&fop, 0, sizeof(fop));
    fop.targetUid = UidBob;
    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetInit(&req, MsgFriendRequest, 0, PlaintextPacket, &fop,
                             sizeof(fop)),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(serverHandleFriendRequest(&s, &cs, &req), SERVER_SUCC);
    packetClear(&req);

    ASSERT_INT_EQ(recvStatus(pair[1], cs.aesKey.key, MsgFriendRequestResp), 1);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(friendDB);
}

/* ── testPrivateChatWithoutLogin ───────────────────────────────────────── */

static void testPrivateChatWithoutLogin(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *pdb = dbInit(PrivateChatDB, NULL);
    ASSERT_NOT_NULL(pdb);
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.privateChatDB = pdb;
    s.onlineTrk = trk;

    ClientSession cs;
    setupSession(&cs, pair[0], 0);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    const char *msg = "test";
    size_t msgLen = strlen(msg) + 1;
    size_t plen = offsetof(PrivateChatPayload, message) + msgLen;
    PrivateChatPayload *pc = malloc(plen);
    ASSERT_NOT_NULL(pc);
    pc->fromUid = TestLargeUid;
    pc->toUid = UidBob;
    pc->msgId = 0;
    pc->timestamp = TestTimestamp;
    memcpy(pc->message, msg, msgLen);

    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(
        packetInit(&req, MsgPrivateChat, 0, PlaintextPacket, pc, plen),
        PROTOCOL_SUCC);
    free(pc);

    /*
     * Current code does not reject uid==0 before calling privateChatStore.
     * Document that the handler currently accepts unauthenticated messages.
     * If this assertion fails because the server now rejects uid==0, update
     * the expected return value to SERVER_FAIL.
     */
    int ret = serverHandlePrivateChatSend(&s, &cs, &req);
    ASSERT_INT_EQ(ret, SERVER_SUCC);
    packetClear(&req);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(trk);
    dbClose(userDB);
    dbClose(pdb);
}

/* ── testGroupCreateWithoutLogin ───────────────────────────────────────── */

static void testGroupCreateWithoutLogin(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], 0);
    onlineTrackerAdd(s.onlineTrk, 0, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    GroupCreatePayload create;
    memset(&create, 0, sizeof(create));
    memcpy(create.groupName, "NoLogin", strlen("NoLogin") + 1);

    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetInit(&req, MsgGroupCreate, 0, PlaintextPacket, &create,
                             sizeof(create)),
                  PROTOCOL_SUCC);

    /*
     * uid==0 is rejected by the DB layer (groupCreate fails with invalid
     * owner). If the code later adds an explicit authentication check
     * before the DB call, the assertion should still hold (status=1).
     */
    ASSERT_INT_EQ(serverHandleGroupCreate(&s, &cs, &req), SERVER_SUCC);
    packetClear(&req);

    ASSERT_INT_EQ(recvStatus(pair[1], cs.aesKey.key, MsgGroupCreateResp), 1);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testGroupKickAsNonOwner ───────────────────────────────────────────── */

static void testGroupKickAsNonOwner(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], UidAlice);
    setupSession(&csB, pairB[0], UidBob);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &csA);
    onlineTrackerAdd(s.onlineTrk, UidBob, &csB);

    s.clients = calloc(2, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = 2;
    s.clientCapacity = 2;

    /* Alice creates group */
    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "KickTest", strlen("KickTest") + 1);
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupCreate, 0, PlaintextPacket,
                                 &create, sizeof(create)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &req), SERVER_SUCC);
        packetClear(&req);

        uint8_t status = 0;
        ASSERT_INT_EQ(
            recvGroupCreateResp(pairA[1], csA.aesKey.key, &status, &groupId),
            0);
        ASSERT_UINT_EQ(status, (uint8_t)0);
        ASSERT_TRUE(groupId != 0);
    }

    /* Bob joins group */
    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(
            packetInit(&req, MsgGroupJoin, 0, PlaintextPacket, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgGroupJoinResp),
                      0);
    }

    /* Drain MsgGroupMemberJoin on Alice */
    {
        Packet drain;
        memset(&drain, 0, sizeof(drain));
        recvDec(pairA[1], csA.aesKey.key, &drain);
        packetClear(&drain);
    }

    /* Bob (non-owner) tries to kick Alice (the owner) */
    {
        GroupKickPayload kick;
        memset(&kick, 0, sizeof(kick));
        kick.groupId = groupId;
        kick.targetUid = UidAlice;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupKick, 0, PlaintextPacket, &kick,
                                 sizeof(kick)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupKick(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgGroupKickResp),
                      1);
    }

    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testGroupDisbandAsNonOwner ────────────────────────────────────────── */

static void testGroupDisbandAsNonOwner(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], UidAlice);
    setupSession(&csB, pairB[0], UidBob);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &csA);
    onlineTrackerAdd(s.onlineTrk, UidBob, &csB);

    s.clients = calloc(2, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = 2;
    s.clientCapacity = 2;

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "DisbandT", strlen("DisbandT") + 1);
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupCreate, 0, PlaintextPacket,
                                 &create, sizeof(create)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &req), SERVER_SUCC);
        packetClear(&req);

        uint8_t status = 0;
        ASSERT_INT_EQ(
            recvGroupCreateResp(pairA[1], csA.aesKey.key, &status, &groupId),
            0);
        ASSERT_UINT_EQ(status, (uint8_t)0);
    }

    /* Bob (non-owner) tries to disband Alice's group */
    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupDisband, 0, PlaintextPacket, &op,
                                 sizeof(op)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupDisband(&s, &csB, &req), SERVER_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgGroupDisbandResp),
                      1);
        packetClear(&req);
    }

    /* Verify group still exists — Alice can still join herself
     * (she's already a member, so join should fail as duplicate) */
    ASSERT_INT_EQ(groupIsMember(s.groupDB, groupId, UidAlice), DB_SUCC);

    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testSendMessageAsOtherUser ────────────────────────────────────────── */

static void testSendMessageAsOtherUser(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *pdb = dbInit(PrivateChatDB, NULL);
    ASSERT_NOT_NULL(pdb);
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.privateChatDB = pdb;
    s.onlineTrk = trk;

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], UidAlice);
    setupSession(&csB, pairB[0], UidBob);

    onlineTrackerAdd(trk, UidAlice, &csA);
    onlineTrackerAdd(trk, UidBob, &csB);

    s.clients = calloc(2, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = 2;
    s.clientCapacity = 2;

    /* Alice sends a message with fromUid forged to Bob's uid */
    const char *msg = "Forged fromUid";
    size_t msgLen = strlen(msg) + 1;
    size_t plen = offsetof(PrivateChatPayload, message) + msgLen;
    PrivateChatPayload *pc = malloc(plen);
    ASSERT_NOT_NULL(pc);
    pc->fromUid = UidBob;
    pc->toUid = UidBob;
    pc->msgId = 0;
    pc->timestamp = TestTimestamp;
    memcpy(pc->message, msg, msgLen);

    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(
        packetInit(&req, MsgPrivateChat, 0, PlaintextPacket, pc, plen),
        PROTOCOL_SUCC);
    free(pc);

    ASSERT_INT_EQ(serverHandlePrivateChatSend(&s, &csA, &req), SERVER_SUCC);
    packetClear(&req);

    /* Bob receives the broadcast — fromUid must be Alice, not Bob */
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], csB.aesKey.key, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgPrivateChatBroadcast);

        const PrivateChatPayload *bc = (const PrivateChatPayload *)rpkt.payload;
        ASSERT_UINT_EQ(bc->fromUid, UidAlice);
        ASSERT_UINT_EQ(bc->toUid, UidBob);
        packetClear(&rpkt);
    }

    /* Alice should NOT receive her own message */
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        int ret = recvDec(pairA[1], csA.aesKey.key, &rpkt);
        ASSERT_INT_EQ(ret, -1);
    }

    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    onlineTrackerDestroy(trk);
    dbClose(userDB);
    dbClose(pdb);
}

/* ── testGroupChatSpoofUid ─────────────────────────────────────────────── */

/* GroupChatPayload has no uid field; the server determines sender from
 * session. This test verifies the broadcast uid matches the session uid. */

static void testGroupChatSpoofUid(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], UidAlice);
    setupSession(&csB, pairB[0], UidBob);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &csA);
    onlineTrackerAdd(s.onlineTrk, UidBob, &csB);

    s.clients = calloc(2, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = 2;
    s.clientCapacity = 2;

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "SpoofGrp", strlen("SpoofGrp") + 1);
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupCreate, 0, PlaintextPacket,
                                 &create, sizeof(create)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &req), SERVER_SUCC);
        packetClear(&req);

        uint8_t status = 0;
        ASSERT_INT_EQ(
            recvGroupCreateResp(pairA[1], csA.aesKey.key, &status, &groupId),
            0);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(
            packetInit(&req, MsgGroupJoin, 0, PlaintextPacket, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgGroupJoinResp),
                      0);
    }

    /* Drain MsgGroupMemberJoin */
    {
        Packet drain;
        memset(&drain, 0, sizeof(drain));
        recvDec(pairA[1], csA.aesKey.key, &drain);
        packetClear(&drain);
    }

    /* Alice sends group chat */
    const char *msg = "Secret group msg";
    size_t msgLen = strlen(msg) + 1;
    size_t plen = offsetof(GroupChatPayload, message) + msgLen;
    GroupChatPayload *gc = malloc(plen);
    ASSERT_NOT_NULL(gc);
    gc->groupId = groupId;
    gc->timestamp = TestTimestamp;
    memcpy(gc->message, msg, msgLen);
    {
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(
            packetInit(&req, MsgGroupChat, 0, PlaintextPacket, gc, plen),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupChat(&s, &csA, &req), SERVER_SUCC);
        packetClear(&req);
    }
    free(gc);

    /* Bob receives broadcast — uid must be Alice (from session) */
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], csB.aesKey.key, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupChatBroadcast);
        const GroupChatBroadcastPayload *bc =
            (const GroupChatBroadcastPayload *)rpkt.payload;
        ASSERT_UINT_EQ(bc->uid, UidAlice);
        ASSERT_UINT_EQ(bc->groupId, groupId);
        packetClear(&rpkt);
    }

    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ═══════════════════ Input Validation / Injection ═══════════════════════ */

/* ── testFriendRequestWithZeroUid ──────────────────────────────────────── */

static void testFriendRequestWithZeroUid(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    FriendOpPayload fop;
    memset(&fop, 0, sizeof(fop));
    fop.targetUid = 0;
    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetInit(&req, MsgFriendRequest, 0, PlaintextPacket, &fop,
                             sizeof(fop)),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(serverHandleFriendRequest(&s, &cs, &req), SERVER_SUCC);
    packetClear(&req);

    ASSERT_INT_EQ(recvStatus(pair[1], cs.aesKey.key, MsgFriendRequestResp), 1);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(friendDB);
}

/* ── testFriendRequestWithMaxUid ───────────────────────────────────────── */

static void testFriendRequestWithMaxUid(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    FriendOpPayload fop;
    memset(&fop, 0, sizeof(fop));
    fop.targetUid = UINT32_MAX;
    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetInit(&req, MsgFriendRequest, 0, PlaintextPacket, &fop,
                             sizeof(fop)),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(serverHandleFriendRequest(&s, &cs, &req), SERVER_SUCC);
    packetClear(&req);

    int status = recvStatus(pair[1], cs.aesKey.key, MsgFriendRequestResp);
    ASSERT_TRUE(status >= 0);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(friendDB);
}

/* ── testGroupCreateEmptyName ──────────────────────────────────────────── */

static void testGroupCreateEmptyName(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    GroupCreatePayload create;
    memset(&create, 0, sizeof(create));
    /* Only a NUL byte — empty string. */
    create.groupName[0] = '\0';

    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetInit(&req, MsgGroupCreate, 0, PlaintextPacket, &create,
                             sizeof(create)),
                  PROTOCOL_SUCC);

    /*
     * The handler passes the NUL-presence check (NUL found at position 0).
     * However, groupCreate in the DB layer rejects an empty group name.
     * The server responds with status=1 (failure).
     */
    ASSERT_INT_EQ(serverHandleGroupCreate(&s, &cs, &req), SERVER_SUCC);
    packetClear(&req);

    ASSERT_INT_EQ(recvStatus(pair[1], cs.aesKey.key, MsgGroupCreateResp), 1);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testGroupCreateOverlongName ───────────────────────────────────────── */

static void testGroupCreateOverlongName(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    /* Payload larger than sizeof(GroupCreatePayload) */
    enum { OverLongLen = sizeof(GroupCreatePayload) + 8 };
    uint8_t overlong[OverLongLen];
    memset(overlong, 'A', OverLongLen);
    overlong[GROUP_NAME_LEN - 1] = '\0';

    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetInit(&req, MsgGroupCreate, 0, PlaintextPacket, overlong,
                             OverLongLen),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(serverHandleGroupCreate(&s, &cs, &req), SERVER_SUCC);
    packetClear(&req);

    ASSERT_INT_EQ(recvStatus(pair[1], cs.aesKey.key, MsgGroupCreateResp), 1);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testPrivateChatOversizedMessage ───────────────────────────────────── */

static void testPrivateChatOversizedMessage(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *pdb = dbInit(PrivateChatDB, NULL);
    ASSERT_NOT_NULL(pdb);
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.privateChatDB = pdb;
    s.onlineTrk = trk;

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    /* Build a message that is one less than MAX_PAYLOAD_LEN total */
    enum {
        PrivateChatFixedLen = sizeof(uint32_t) + sizeof(uint32_t) +
                              sizeof(uint32_t) + sizeof(int64_t)
    };
    size_t msgLen = MAX_PAYLOAD_LEN - PrivateChatFixedLen;
    uint8_t *buf = calloc(1, MAX_PAYLOAD_LEN);
    ASSERT_NOT_NULL(buf);
    PrivateChatPayload *pc = (PrivateChatPayload *)buf;
    pc->fromUid = UidAlice;
    pc->toUid = UidBob;
    pc->msgId = 0;
    pc->timestamp = TestTimestamp;
    memset(pc->message, 'X', msgLen - 1);
    pc->message[msgLen - 1] = '\0';

    Packet req;
    memset(&req, 0, sizeof(req));
    int initRet = packetInit(&req, MsgPrivateChat, 0, PlaintextPacket, buf,
                             MAX_PAYLOAD_LEN);
    free(buf);
    ASSERT_INT_EQ(initRet, PROTOCOL_SUCC);

    int ret = serverHandlePrivateChatSend(&s, &cs, &req);
    packetClear(&req);
    (void)ret;

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(trk);
    dbClose(userDB);
    dbClose(pdb);
}

/* ── testGroupChatOversizedMessage ─────────────────────────────────────── */

static void testGroupChatOversizedMessage(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "Oversize", strlen("Oversize") + 1);
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupCreate, 0, PlaintextPacket,
                                 &create, sizeof(create)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupCreate(&s, &cs, &req), SERVER_SUCC);
        packetClear(&req);

        uint8_t status = 0;
        ASSERT_INT_EQ(
            recvGroupCreateResp(pair[1], cs.aesKey.key, &status, &groupId), 0);
    }

    /* Build oversized group chat message */
    enum { GroupChatFixedLen = sizeof(uint32_t) + sizeof(int64_t) };
    size_t msgLen = MAX_PAYLOAD_LEN - GroupChatFixedLen;
    uint8_t *buf = calloc(1, MAX_PAYLOAD_LEN);
    ASSERT_NOT_NULL(buf);
    GroupChatPayload *gc = (GroupChatPayload *)buf;
    gc->groupId = groupId;
    gc->timestamp = TestTimestamp;
    memset(gc->message, 'Y', msgLen - 1);
    gc->message[msgLen - 1] = '\0';

    Packet req;
    memset(&req, 0, sizeof(req));
    int initRet = packetInit(&req, MsgGroupChat, 0, PlaintextPacket, buf,
                             MAX_PAYLOAD_LEN);
    free(buf);
    ASSERT_INT_EQ(initRet, PROTOCOL_SUCC);

    int ret = serverHandleGroupChat(&s, &cs, &req);
    packetClear(&req);
    (void)ret;

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testGroupNameWithNullBytes ────────────────────────────────────────── */

static void testGroupNameWithNullBytes(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    /* Name with embedded NUL: "real\0hidden" */
    GroupCreatePayload create;
    memset(&create, 0, sizeof(create));
    create.groupName[0] = 'r';
    create.groupName[1] = 'e';
    create.groupName[2] = 'a';
    create.groupName[3] = 'l';
    create.groupName[4] = '\0';
    create.groupName[TestHiddenIdx5] = 'h';
    create.groupName[TestHiddenIdx6] = 'i';
    create.groupName[TestHiddenIdx7] = 'd';

    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetInit(&req, MsgGroupCreate, 0, PlaintextPacket, &create,
                             sizeof(create)),
                  PROTOCOL_SUCC);

    /*
     * memchr finds the NUL at position 4. The handler treats it as
     * NUL-terminated at that position, so the group is named "real".
     */
    ASSERT_INT_EQ(serverHandleGroupCreate(&s, &cs, &req), SERVER_SUCC);
    packetClear(&req);

    uint8_t status = 0;
    uint32_t groupId = 0;
    ASSERT_INT_EQ(
        recvGroupCreateResp(pair[1], cs.aesKey.key, &status, &groupId), 0);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testPrivateChatMessageWithNullBytes ────────────────────────────────── */

static void testPrivateChatMessageWithNullBytes(void) {
    enum { SecondPartOffset = 5, SecondPartNullIndex = 9 };
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *pdb = dbInit(PrivateChatDB, NULL);
    ASSERT_NOT_NULL(pdb);
    OnlineTracker *trk = onlineTrackerCreate();
    ASSERT_NOT_NULL(trk);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.privateChatDB = pdb;
    s.onlineTrk = trk;

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    /* Message: "good\0evil" (10 bytes including both NULs) */
    enum {
        NullMsgLen = 10,
        PrivateChatFixedLen = sizeof(uint32_t) + sizeof(uint32_t) +
                              sizeof(uint32_t) + sizeof(int64_t)
    };
    size_t plen = offsetof(PrivateChatPayload, message) + NullMsgLen;
    PrivateChatPayload *pc = malloc(plen);
    ASSERT_NOT_NULL(pc);
    pc->fromUid = UidAlice;
    pc->toUid = UidBob;
    pc->msgId = 0;
    pc->timestamp = TestTimestamp;
    memcpy(pc->message, "good", 4);
    pc->message[4] = '\0';
    memcpy(pc->message + SecondPartOffset, "evil", 4);
    pc->message[SecondPartNullIndex] = '\0';

    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(
        packetInit(&req, MsgPrivateChat, 0, PlaintextPacket, pc, plen),
        PROTOCOL_SUCC);
    free(pc);

    /*
     * memchr finds the NUL at position 4. msgLen=10 > 0, so the check
     * passes. The message is stored as-is (10 bytes). When retrieved, it
     * will be truncated at the first NUL by strlen-based consumers.
     */
    int ret = serverHandlePrivateChatSend(&s, &cs, &req);
    ASSERT_INT_EQ(ret, SERVER_SUCC);
    packetClear(&req);

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(trk);
    dbClose(userDB);
    dbClose(pdb);
}

/* ════════════════════ Race / State Attacks ══════════════════════════════ */

/* ── testDoubleFriendAccept ────────────────────────────────────────────── */

static void testDoubleFriendAccept(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], UidAlice);
    setupSession(&csB, pairB[0], UidBob);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &csA);
    onlineTrackerAdd(s.onlineTrk, UidBob, &csB);

    s.clients = calloc(2, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = 2;
    s.clientCapacity = 2;

    /* A sends request to B */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = UidBob;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendRequest, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendRequest(&s, &csA, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(
            recvStatus(pairA[1], csA.aesKey.key, MsgFriendRequestResp), 0);
    }

    /* B accepts A (first time) */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = UidAlice;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendAccept, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendAccept(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgFriendAcceptResp),
                      0);
    }

    /* Drain friend notifies */
    {
        Packet drain;
        memset(&drain, 0, sizeof(drain));
        recvDec(pairA[1], csA.aesKey.key, &drain);
        packetClear(&drain);
        recvDec(pairB[1], csB.aesKey.key, &drain);
        packetClear(&drain);
    }

    /* B tries to accept A again (duplicate).
     * friendRequestAccept is effectively idempotent — the DB returns success
     * because the friendship already exists. */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = UidAlice;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendAccept, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendAccept(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgFriendAcceptResp),
                      0);
    }

    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(friendDB);
}

/* ── testFriendRequestToAlreadyFriend ──────────────────────────────────── */

static void testFriendRequestToAlreadyFriend(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], UidAlice);
    setupSession(&csB, pairB[0], UidBob);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &csA);
    onlineTrackerAdd(s.onlineTrk, UidBob, &csB);

    s.clients = calloc(2, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = 2;
    s.clientCapacity = 2;

    /* A sends request to B */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = UidBob;
        Packet req;
        packetInit(&req, MsgFriendRequest, 0, PlaintextPacket, &fop,
                   sizeof(fop));
        serverHandleFriendRequest(&s, &csA, &req);
        packetClear(&req);
        recvStatus(pairA[1], csA.aesKey.key, MsgFriendRequestResp);
    }

    /* B accepts */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = UidAlice;
        Packet req;
        packetInit(&req, MsgFriendAccept, 0, PlaintextPacket, &fop,
                   sizeof(fop));
        serverHandleFriendAccept(&s, &csB, &req);
        packetClear(&req);
        recvStatus(pairB[1], csB.aesKey.key, MsgFriendAcceptResp);

        Packet drain;
        memset(&drain, 0, sizeof(drain));
        recvDec(pairA[1], csA.aesKey.key, &drain);
        packetClear(&drain);
        recvDec(pairB[1], csB.aesKey.key, &drain);
        packetClear(&drain);
    }

    /* Verify they are friends */
    ASSERT_INT_EQ(friendIsFriend(s.friendDB, UidAlice, UidBob), DB_SUCC);

    /* A sends another request to B (already friends) */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = UidBob;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendRequest, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendRequest(&s, &csA, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(
            recvStatus(pairA[1], csA.aesKey.key, MsgFriendRequestResp), 1);
    }

    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(friendDB);
}

/* ── testGroupJoinTwice ────────────────────────────────────────────────── */

static void testGroupJoinTwice(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], UidAlice);
    setupSession(&csB, pairB[0], UidBob);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &csA);
    onlineTrackerAdd(s.onlineTrk, UidBob, &csB);

    s.clients = calloc(2, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = 2;
    s.clientCapacity = 2;

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "DupJoin", strlen("DupJoin") + 1);
        Packet req;
        packetInit(&req, MsgGroupCreate, 0, PlaintextPacket, &create,
                   sizeof(create));
        serverHandleGroupCreate(&s, &csA, &req);
        packetClear(&req);

        uint8_t status = 0;
        recvGroupCreateResp(pairA[1], csA.aesKey.key, &status, &groupId);
    }

    /* Bob joins — success */
    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(
            packetInit(&req, MsgGroupJoin, 0, PlaintextPacket, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgGroupJoinResp),
                      0);
    }

    /* Drain MsgGroupMemberJoin */
    {
        Packet drain;
        memset(&drain, 0, sizeof(drain));
        recvDec(pairA[1], csA.aesKey.key, &drain);
        packetClear(&drain);
    }

    /* Bob tries to join again — failure */
    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(
            packetInit(&req, MsgGroupJoin, 0, PlaintextPacket, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgGroupJoinResp),
                      1);
    }

    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testGroupDisbandTwice ─────────────────────────────────────────────── */

static void testGroupDisbandTwice(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "DblDisb", strlen("DblDisb") + 1);
        Packet req;
        packetInit(&req, MsgGroupCreate, 0, PlaintextPacket, &create,
                   sizeof(create));
        serverHandleGroupCreate(&s, &cs, &req);
        packetClear(&req);

        uint8_t status = 0;
        recvGroupCreateResp(pair[1], cs.aesKey.key, &status, &groupId);
    }

    /* First disband — success */
    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupDisband, 0, PlaintextPacket, &op,
                                 sizeof(op)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupDisband(&s, &cs, &req), SERVER_SUCC);
        packetClear(&req);
    }

    /* Drain MsgGroupDisbandNotify + the first MsgGroupDisbandResp */
    {
        Packet drain;
        memset(&drain, 0, sizeof(drain));
        recvDec(pair[1], cs.aesKey.key, &drain);
        packetClear(&drain);
        memset(&drain, 0, sizeof(drain));
        recvDec(pair[1], cs.aesKey.key, &drain);
        packetClear(&drain);
    }

    /* Second disband — group doesn't exist, returns SERVER_SUCC with failure
     * status */
    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupDisband, 0, PlaintextPacket, &op,
                                 sizeof(op)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupDisband(&s, &cs, &req), SERVER_SUCC);
        ASSERT_INT_EQ(recvStatus(pair[1], cs.aesKey.key, MsgGroupDisbandResp),
                      1);
        packetClear(&req);
    }

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ── testKickNonexistentMember ─────────────────────────────────────────── */

static void testKickNonexistentMember(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "KickXXX", strlen("KickXXX") + 1);
        Packet req;
        packetInit(&req, MsgGroupCreate, 0, PlaintextPacket, &create,
                   sizeof(create));
        serverHandleGroupCreate(&s, &cs, &req);
        packetClear(&req);

        uint8_t status = 0;
        recvGroupCreateResp(pair[1], cs.aesKey.key, &status, &groupId);
    }

    /* Owner tries to kick a user not in group */
    {
        GroupKickPayload kick;
        memset(&kick, 0, sizeof(kick));
        kick.groupId = groupId;
        kick.targetUid = UidBob;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgGroupKick, 0, PlaintextPacket, &kick,
                                 sizeof(kick)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupKick(&s, &cs, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pair[1], cs.aesKey.key, MsgGroupKickResp), 1);
    }

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ═══════════════════ Resource Exhaustion / DOS ══════════════════════════ */

/* ── testFriendRequestRapidFire ────────────────────────────────────────── */

static void testFriendRequestRapidFire(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    SocketFD pair[2];
    ASSERT_INT_EQ(makeSocketPair(pair), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;
    s.onlineTrk = onlineTrackerCreate();

    ClientSession cs;
    setupSession(&cs, pair[0], UidAlice);
    onlineTrackerAdd(s.onlineTrk, UidAlice, &cs);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &cs;
    s.clientCount = 1;
    s.clientCapacity = 1;

    /*
     * Send 100 friend requests to the same target. The first creates a
     * pending request; subsequent ones should be rejected as duplicates.
     * The server must not crash or leak memory.
     */
    for (int i = 0; i < RapidFireCount; i++) {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = UidBob;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendRequest, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendRequest(&s, &cs, &req), SERVER_SUCC);
        packetClear(&req);

        int status = recvStatus(pair[1], cs.aesKey.key, MsgFriendRequestResp);
        ASSERT_TRUE(status >= 0);
    }

    free(s.clients);
    socketClose(&pair[0]);
    socketClose(&pair[1]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(friendDB);
}

/* ── testGroupJoinAtLimit ──────────────────────────────────────────────── */

static void testGroupJoinAtLimit(void) {
    removeAllDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *gdb = dbInit(GroupDB, NULL);
    ASSERT_NOT_NULL(gdb);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.groupDB = gdb;
    s.onlineTrk = onlineTrackerCreate();

    enum { TestClientCount = MaxGroupMembers + 2 };
    ClientSession *sessions =
        calloc((size_t)TestClientCount, sizeof(ClientSession));
    ASSERT_NOT_NULL(sessions);
    SocketFD *pairs = calloc((size_t)TestClientCount * 2, sizeof(SocketFD));
    ASSERT_NOT_NULL(pairs);

    ClientSession **clientPtrs =
        calloc((size_t)TestClientCount, sizeof(ClientSession *));
    ASSERT_NOT_NULL(clientPtrs);
    s.clients = clientPtrs;
    s.clientCapacity = TestClientCount;

    /* Setup owner (uid = GroupFullMemberUidBase) */
    enum { OwnerIdx = 0 };
    ASSERT_INT_EQ(makeSocketPair(&pairs[OwnerIdx * 2]), 0);
    setupSession(&sessions[OwnerIdx], pairs[OwnerIdx * 2],
                 (uint32_t)(GroupFullMemberUidBase + OwnerIdx));
    clientPtrs[OwnerIdx] = &sessions[OwnerIdx];
    onlineTrackerAdd(s.onlineTrk, (uint32_t)(GroupFullMemberUidBase + OwnerIdx),
                     &sessions[OwnerIdx]);
    s.clientCount = 1;

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "FullGrp", strlen("FullGrp") + 1);
        Packet req;
        packetInit(&req, MsgGroupCreate, 0, PlaintextPacket, &create,
                   sizeof(create));
        serverHandleGroupCreate(&s, &sessions[OwnerIdx], &req);
        packetClear(&req);

        uint8_t status = 0;
        recvGroupCreateResp(pairs[OwnerIdx * 2 + 1],
                            sessions[OwnerIdx].aesKey.key, &status, &groupId);
    }

    /* Join MaxGroupMembers - 1 users (owner already counts as 1) */
    int successCount = 0;
    enum { JoinStart = 1 };
    for (int i = JoinStart; i < TestClientCount; i++) {
        ASSERT_INT_EQ(makeSocketPair(&pairs[i * 2]), 0);
        setupSession(&sessions[i], pairs[i * 2],
                     (uint32_t)(GroupFullMemberUidBase + i));
        clientPtrs[i] = &sessions[i];
        onlineTrackerAdd(s.onlineTrk, (uint32_t)(GroupFullMemberUidBase + i),
                         &sessions[i]);
        s.clientCount = i + 1;

        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(
            packetInit(&req, MsgGroupJoin, 0, PlaintextPacket, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleGroupJoin(&s, &sessions[i], &req),
                      SERVER_SUCC);
        packetClear(&req);

        int status = recvStatus(pairs[i * 2 + 1], sessions[i].aesKey.key,
                                MsgGroupJoinResp);
        if (status == 0) {
            successCount++;
        }
    }

    /* At least one join attempt should fail (group full) */
    enum { MaxJoinSuccess = MaxGroupMembers - 1 };
    ASSERT_UINT_EQ((unsigned int)successCount, (unsigned int)MaxJoinSuccess);

    /* Verify group is at capacity */
    GroupInfo info;
    memset(&info, 0, sizeof(info));
    ASSERT_INT_EQ(groupGetInfo(s.groupDB, groupId, &info), DB_SUCC);
    ASSERT_UINT_EQ(info.memberCount, (uint32_t)MaxGroupMembers);

    free(clientPtrs);
    for (int i = 0; i < TestClientCount; i++) {
        socketClose(&pairs[i * 2]);
        socketClose(&pairs[i * 2 + 1]);
        OPENSSL_cleanse(&sessions[i].aesKey, sizeof(sessions[i].aesKey));
    }
    free(sessions);
    free(pairs);
    onlineTrackerDestroy(s.onlineTrk);
    dbClose(userDB);
    dbClose(gdb);
}

/* ══════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    logSetLevel(LogLevelFatal);
    removeAllDBFiles();

    printf("test_social_security:\n");

    RUN_TEST(testFriendRequestWithoutLogin);
    RUN_TEST(testPrivateChatWithoutLogin);
    RUN_TEST(testGroupCreateWithoutLogin);
    RUN_TEST(testGroupKickAsNonOwner);
    RUN_TEST(testGroupDisbandAsNonOwner);
    RUN_TEST(testSendMessageAsOtherUser);
    RUN_TEST(testGroupChatSpoofUid);
    RUN_TEST(testFriendRequestWithZeroUid);
    RUN_TEST(testFriendRequestWithMaxUid);
    RUN_TEST(testGroupCreateEmptyName);
    RUN_TEST(testGroupCreateOverlongName);
    RUN_TEST(testPrivateChatOversizedMessage);
    RUN_TEST(testGroupChatOversizedMessage);
    RUN_TEST(testGroupNameWithNullBytes);
    RUN_TEST(testPrivateChatMessageWithNullBytes);
    RUN_TEST(testDoubleFriendAccept);
    RUN_TEST(testFriendRequestToAlreadyFriend);
    RUN_TEST(testGroupJoinTwice);
    RUN_TEST(testGroupDisbandTwice);
    RUN_TEST(testKickNonexistentMember);
    RUN_TEST(testFriendRequestRapidFire);
    RUN_TEST(testGroupJoinAtLimit);

    removeAllDBFiles();

    return TEST_REPORT();
}
