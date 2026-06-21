/**
 * @file test_friend.c
 * @brief Integration tests for the server-side friend system.
 *
 * Uses loopback socket pairs so that friend handler responses (sent
 * encrypted via serverSendStatusResponse / serverSendEncryptedPacket)
 * are verified on the client side of each pair.
 *
 * @date 2026-06-21
 * @copyright GPLv3 License
 */

#include "crypto.h"
#include "protocol.h"
#include "server/database.h"
#include "server/friend.h"
#include "server/onlineTracker.h"
#include "server/server.h"
#include "test_utils.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ──────────────────────────── named constants ───────────────────────────── */

enum {
    UidNonexistent = 99999,
    StrLenAlice = 5,
    StrLenBob = 3,
    TestNickLen = 9,
    ClientCapacity = 2
};

/* ─────────────────────────── helper prototypes ──────────────────────────── */

static void removeDBFiles(void);
static int makeSocketPair(SocketFD pair[2]);
static int recvDec(SocketFD fd, uint8_t key[AES_GCM_KEY_LEN], Packet *out);
static int recvStatus(SocketFD fd, uint8_t key[AES_GCM_KEY_LEN],
                      MessageType expectedMt);
static uint32_t createTestUser(DB *userDB, const char *username,
                               const char *nickname, const char *password);
static void setupSession(ClientSession *cs, SocketFD svrSide, uint32_t uid);

/* ───────────────────────── helper implementations ───────────────────────── */

static void removeDBFiles(void) {
    remove("./db/user.db");
    remove("./db/user.db-wal");
    remove("./db/user.db-shm");
    remove("./db/friend.db");
    remove("./db/friend.db-wal");
    remove("./db/friend.db-shm");
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

/**
 * @brief Create a user in UserDB and return the server-assigned uid.
 *
 * createUser assigns a random uid; this helper retrieves it via
 * verifyUser (lookup by username + password).
 *
 * @return The assigned uid on success, or 0 on failure.
 */
static uint32_t createTestUser(DB *userDB, const char *username,
                               const char *nickname, const char *password) {
    User u;
    memset(&u, 0, sizeof(u));
    memcpy(u.username, username, strlen(username) + 1);
    memcpy(u.nickname, nickname, strlen(nickname) + 1);
    u.uid = 0;
    u.password = strdup(password);
    if (u.password == NULL) {
        return 0;
    }
    int ret = createUser(userDB, &u);
    free(u.password);
    if (ret != DB_SUCC) {
        return 0;
    }

    User verify;
    memset(&verify, 0, sizeof(verify));
    memcpy(verify.username, username, strlen(username) + 1);
    verify.password = strdup(password);
    if (verify.password == NULL) {
        return 0;
    }
    ret = verifyUser(userDB, &verify);
    uint32_t uid = verify.uid;
    free(verify.password);
    free(verify.totpSecret);
    if (ret != DB_SUCC) {
        return 0;
    }
    return uid;
}

static void setupSession(ClientSession *cs, SocketFD svrSide, uint32_t uid) {
    memset(cs, 0, sizeof(*cs));
    cs->fd = svrSide;
    cs->currentUser.uid = uid;
    cryptoRandomBytes(cs->aesKey.key, AES_GCM_KEY_LEN);
    memset(cs->aesKey.nonce, 0, AES_GCM_NONCE_LEN);
    cs->seqID = 0;
}

/* ══════════════════════════ testFriendRequestAndAccept ═════════════════════
 */

static void testFriendRequestAndAccept(void) {
    removeDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    uint32_t uidA = createTestUser(userDB, "Alice", "AliceNick", "alicepass");
    ASSERT_TRUE(uidA != 0);
    uint32_t uidB = createTestUser(userDB, "Bob", "BobNick__", "bobpass__");
    ASSERT_TRUE(uidB != 0);

    /* Two socket pairs: svr side [0], cli side [1] */
    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], uidA);
    setupSession(&csB, pairB[0], uidB);

    s.clients = calloc(ClientCapacity, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = ClientCapacity;
    s.clientCapacity = ClientCapacity;

    s.onlineTrk = onlineTrackerCreate();
    ASSERT_NOT_NULL(s.onlineTrk);
    onlineTrackerAdd(s.onlineTrk, uidA, &csA);
    onlineTrackerAdd(s.onlineTrk, uidB, &csB);

    /* ── A sends friend request to B ── */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidB;
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

    /* ── B accepts A ── */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidA;
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

    /* ── Both receive friend notify ── */
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(pairA[1], csA.aesKey.key, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgFriendNotify);
        ASSERT_TRUE(pkt.header.payloadLength >= sizeof(FriendNotifyPayload));
        FriendNotifyPayload *fn = (FriendNotifyPayload *)pkt.payload;
        ASSERT_UINT_EQ(fn->uid, uidB);
        packetClear(&pkt);
    }
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(pairB[1], csB.aesKey.key, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgFriendNotify);
        ASSERT_TRUE(pkt.header.payloadLength >= sizeof(FriendNotifyPayload));
        FriendNotifyPayload *fn = (FriendNotifyPayload *)pkt.payload;
        ASSERT_UINT_EQ(fn->uid, uidA);
        packetClear(&pkt);
    }

    /* cleanup */
    onlineTrackerDestroy(s.onlineTrk);
    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    dbClose(userDB);
    dbClose(friendDB);
}

/* ═════════════════════════ testFriendRequestAndReject ══════════════════════
 */

static void testFriendRequestAndReject(void) {
    removeDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    uint32_t uidA = createTestUser(userDB, "Alice", "AliceNick", "alicepass");
    ASSERT_TRUE(uidA != 0);
    uint32_t uidB = createTestUser(userDB, "Bob", "BobNick__", "bobpass__");
    ASSERT_TRUE(uidB != 0);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], uidA);
    setupSession(&csB, pairB[0], uidB);

    s.clients = calloc(ClientCapacity, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = ClientCapacity;
    s.clientCapacity = ClientCapacity;

    s.onlineTrk = onlineTrackerCreate();
    ASSERT_NOT_NULL(s.onlineTrk);
    onlineTrackerAdd(s.onlineTrk, uidA, &csA);
    onlineTrackerAdd(s.onlineTrk, uidB, &csB);

    /* A sends request to B */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidB;
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

    /* B rejects A */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidA;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendReject, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendReject(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgFriendReject), 0);
    }

    /* Verify no friendship */
    ASSERT_INT_EQ(friendIsFriend(s.friendDB, uidA, uidB), DB_FAIL);
    ASSERT_INT_EQ(friendIsFriend(s.friendDB, uidB, uidA), DB_FAIL);

    onlineTrackerDestroy(s.onlineTrk);
    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    dbClose(userDB);
    dbClose(friendDB);
}

/* ═════════════════════════ testFriendListAfterAccept ═══════════════════════
 */

static void testFriendListAfterAccept(void) {
    removeDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    uint32_t uidA = createTestUser(userDB, "Alice", "AliceNick", "alicepass");
    ASSERT_TRUE(uidA != 0);
    uint32_t uidB = createTestUser(userDB, "Bob", "BobNick__", "bobpass__");
    ASSERT_TRUE(uidB != 0);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], uidA);
    setupSession(&csB, pairB[0], uidB);

    s.clients = calloc(ClientCapacity, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = ClientCapacity;
    s.clientCapacity = ClientCapacity;

    s.onlineTrk = onlineTrackerCreate();
    ASSERT_NOT_NULL(s.onlineTrk);
    onlineTrackerAdd(s.onlineTrk, uidA, &csA);
    onlineTrackerAdd(s.onlineTrk, uidB, &csB);

    /* Request A -> B */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidB;
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

    /* Accept B -> A */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidA;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendAccept, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendAccept(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);
        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgFriendAcceptResp),
                      0);

        /* Drain notify on A and B */
        Packet drain;
        memset(&drain, 0, sizeof(drain));
        recvDec(pairA[1], csA.aesKey.key, &drain);
        packetClear(&drain);
        recvDec(pairB[1], csB.aesKey.key, &drain);
        packetClear(&drain);
    }

    /* A requests friend list */
    ASSERT_INT_EQ(serverHandleFriendList(&s, &csA), SERVER_SUCC);
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(pairA[1], csA.aesKey.key, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgFriendListResp);
        ASSERT_TRUE(pkt.header.payloadLength >= sizeof(uint32_t));

        uint32_t count;
        memcpy(&count, pkt.payload, sizeof(count));
        ASSERT_UINT_EQ(count, (uint32_t)1);

        ASSERT_TRUE(pkt.header.payloadLength >=
                    sizeof(uint32_t) + count * sizeof(FriendInfo));
        FriendInfo *fi = (FriendInfo *)(pkt.payload + sizeof(uint32_t));
        ASSERT_UINT_EQ(fi->uid, uidB);
        ASSERT_STR_EQ(fi->username, "Bob");
        ASSERT_STR_EQ(fi->nickname, "BobNick__");
        ASSERT_UINT_EQ(fi->online, (uint8_t)1);

        packetClear(&pkt);
    }

    /* B requests friend list — should show Alice online */
    ASSERT_INT_EQ(serverHandleFriendList(&s, &csB), SERVER_SUCC);
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(pairB[1], csB.aesKey.key, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgFriendListResp);

        uint32_t count;
        memcpy(&count, pkt.payload, sizeof(count));
        ASSERT_UINT_EQ(count, (uint32_t)1);
        FriendInfo *fi = (FriendInfo *)(pkt.payload + sizeof(uint32_t));
        ASSERT_UINT_EQ(fi->uid, uidA);
        ASSERT_UINT_EQ(fi->online, (uint8_t)1);

        packetClear(&pkt);
    }

    onlineTrackerDestroy(s.onlineTrk);
    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    dbClose(userDB);
    dbClose(friendDB);
}

/* ═══════════════════════════ testFriendDelete ══════════════════════════════
 */

static void testFriendDelete(void) {
    removeDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    uint32_t uidA = createTestUser(userDB, "Alice", "AliceNick", "alicepass");
    ASSERT_TRUE(uidA != 0);
    uint32_t uidB = createTestUser(userDB, "Bob", "BobNick__", "bobpass__");
    ASSERT_TRUE(uidB != 0);

    SocketFD pairA[2], pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;

    ClientSession csA, csB;
    setupSession(&csA, pairA[0], uidA);
    setupSession(&csB, pairB[0], uidB);

    s.clients = calloc(ClientCapacity, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clients[1] = &csB;
    s.clientCount = ClientCapacity;
    s.clientCapacity = ClientCapacity;

    s.onlineTrk = onlineTrackerCreate();
    ASSERT_NOT_NULL(s.onlineTrk);
    onlineTrackerAdd(s.onlineTrk, uidA, &csA);
    onlineTrackerAdd(s.onlineTrk, uidB, &csB);

    /* Request A -> B */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidB;
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

    /* Accept B -> A */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidA;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendAccept, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendAccept(&s, &csB, &req), SERVER_SUCC);
        packetClear(&req);
        ASSERT_INT_EQ(recvStatus(pairB[1], csB.aesKey.key, MsgFriendAcceptResp),
                      0);

        Packet drain;
        memset(&drain, 0, sizeof(drain));
        recvDec(pairA[1], csA.aesKey.key, &drain);
        packetClear(&drain);
        recvDec(pairB[1], csB.aesKey.key, &drain);
        packetClear(&drain);
    }

    /* A deletes B */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidB;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendDelete, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendDelete(&s, &csA, &req), SERVER_SUCC);
        packetClear(&req);

        ASSERT_INT_EQ(recvStatus(pairA[1], csA.aesKey.key, MsgFriendDeleteResp),
                      0);
    }

    /* Verify no longer friends */
    ASSERT_INT_EQ(friendIsFriend(s.friendDB, uidA, uidB), DB_FAIL);

    /* A's friend list should be empty */
    ASSERT_INT_EQ(serverHandleFriendList(&s, &csA), SERVER_SUCC);
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(pairA[1], csA.aesKey.key, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgFriendListResp);

        uint32_t count;
        memcpy(&count, pkt.payload, sizeof(count));
        ASSERT_UINT_EQ(count, (uint32_t)0);
        packetClear(&pkt);
    }

    onlineTrackerDestroy(s.onlineTrk);
    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    socketClose(&pairB[0]);
    socketClose(&pairB[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    OPENSSL_cleanse(&csB.aesKey, sizeof(csB.aesKey));
    dbClose(userDB);
    dbClose(friendDB);
}

/* ═════════════════════════ testFriendSelfRequest ═══════════════════════════
 */

static void testFriendSelfRequest(void) {
    removeDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    uint32_t uidA = createTestUser(userDB, "Alice", "AliceNick", "alicepass");
    ASSERT_TRUE(uidA != 0);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;

    ClientSession csA;
    setupSession(&csA, pairA[0], uidA);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clientCount = 1;
    s.clientCapacity = 1;

    s.onlineTrk = onlineTrackerCreate();
    ASSERT_NOT_NULL(s.onlineTrk);
    onlineTrackerAdd(s.onlineTrk, uidA, &csA);

    /* A sends friend request to self */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidA;
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

    onlineTrackerDestroy(s.onlineTrk);
    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    dbClose(userDB);
    dbClose(friendDB);
}

/* ═══════════════════════ testFriendDuplicateRequest ════════════════════════
 */

static void testFriendDuplicateRequest(void) {
    removeDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    uint32_t uidA = createTestUser(userDB, "Alice", "AliceNick", "alicepass");
    ASSERT_TRUE(uidA != 0);
    uint32_t uidB = createTestUser(userDB, "Bob", "BobNick__", "bobpass__");
    ASSERT_TRUE(uidB != 0);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;

    ClientSession csA;
    setupSession(&csA, pairA[0], uidA);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clientCount = 1;
    s.clientCapacity = 1;

    s.onlineTrk = onlineTrackerCreate();
    ASSERT_NOT_NULL(s.onlineTrk);
    onlineTrackerAdd(s.onlineTrk, uidA, &csA);

    /* First request: success */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidB;
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

    /* Second request: duplicate -> failure */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = uidB;
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

    onlineTrackerDestroy(s.onlineTrk);
    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    dbClose(userDB);
    dbClose(friendDB);
}

/* ══════════════════════ testFriendRequestNonexistentUser ═══════════════════
 */

static void testFriendRequestNonexistentUser(void) {
    removeDBFiles();

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    DB *friendDB = dbInit(FriendDB, NULL);
    ASSERT_NOT_NULL(friendDB);

    uint32_t uidA = createTestUser(userDB, "Alice", "AliceNick", "alicepass");
    ASSERT_TRUE(uidA != 0);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    Server s;
    memset(&s, 0, sizeof(s));
    s.userDB = userDB;
    s.friendDB = friendDB;

    ClientSession csA;
    setupSession(&csA, pairA[0], uidA);

    s.clients = calloc(1, sizeof(ClientSession *));
    ASSERT_NOT_NULL(s.clients);
    s.clients[0] = &csA;
    s.clientCount = 1;
    s.clientCapacity = 1;

    s.onlineTrk = onlineTrackerCreate();
    ASSERT_NOT_NULL(s.onlineTrk);
    onlineTrackerAdd(s.onlineTrk, uidA, &csA);

    /* A sends friend request to nonexistent uid */
    {
        FriendOpPayload fop;
        memset(&fop, 0, sizeof(fop));
        fop.targetUid = UidNonexistent;
        Packet req;
        memset(&req, 0, sizeof(req));
        ASSERT_INT_EQ(packetInit(&req, MsgFriendRequest, 0, PlaintextPacket,
                                 &fop, sizeof(fop)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverHandleFriendRequest(&s, &csA, &req), SERVER_SUCC);
        packetClear(&req);

        /* Current implementation does not validate target user existence,
         * so the request is accepted. Expect success (0) for now. */
        ASSERT_INT_EQ(
            recvStatus(pairA[1], csA.aesKey.key, MsgFriendRequestResp), 0);
    }

    /* Verify no friendship created by accident */
    ASSERT_INT_EQ(friendIsFriend(s.friendDB, uidA, UidNonexistent), DB_FAIL);

    onlineTrackerDestroy(s.onlineTrk);
    free(s.clients);
    socketClose(&pairA[0]);
    socketClose(&pairA[1]);
    OPENSSL_cleanse(&csA.aesKey, sizeof(csA.aesKey));
    dbClose(userDB);
    dbClose(friendDB);
}

/* ══════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    printf("test_friend:\n");

    RUN_TEST(testFriendRequestAndAccept);
    RUN_TEST(testFriendRequestAndReject);
    RUN_TEST(testFriendListAfterAccept);
    RUN_TEST(testFriendDelete);
    RUN_TEST(testFriendSelfRequest);
    RUN_TEST(testFriendDuplicateRequest);
    RUN_TEST(testFriendRequestNonexistentUser);

    return TEST_REPORT();
}
