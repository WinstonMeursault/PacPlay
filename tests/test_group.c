/**
 * @file test_group.c
 * @brief Integration tests for group chat — create, join, chat, quit, kick,
 *        disband.
 *
 * Uses socketpair pairs + full server handler functions.
 *
 * @date 2026-06-21
 * @copyright GPLv3 License
 */

#include "client/communication.h"
#include "crypto.h"
#include "log.h"
#include "protocol.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/group.h"
#include "server/onlineTracker.h"
#include "server/server.h"
#include "test_utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/* ──────────────────────────── named constants ────────────────────────── */

enum {
    UidAlice = 2000,
    UidBob = 2001,
    UidCharlie = 2002,
    TestTimestamp = 1234567890,
    NoPaginationMsgId = 0x7FFFFFFF,
    HistoryDefaultLimit = 50,
    TestBatchMsgCount = 10,
    TestPageBeforeIdx = 5,
};

/* ──────────────────────── helper prototypes ──────────────────────────── */

static int makeSocketPair(SocketFD pair[2]);
static int clientDoKeyExchange(SocketFD fd, AESGCMKey *outKey);
static int serverDoKeyExchangeOnFd(SocketFD fd, AESGCMKey *outKey);
static int sendEnc(SocketFD fd, AESGCMKey *key, uint32_t *seq, MessageType mt,
                   const void *data, size_t len);
static int recvDec(SocketFD fd, AESGCMKey *key, Packet *out);
static int recvStatus(SocketFD fd, AESGCMKey *key, MessageType expectedMt);
static DB *ensureTestUser(const char *username, uint32_t uid,
                          const char *password);
static void removeTestDBFiles(void);
static int serverSetupLogin(Server *s, ClientSession *cs);

/* ─────────────────────── helper implementations ──────────────────────── */

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

static int clientDoKeyExchange(SocketFD fd, AESGCMKey *outKey) {
    return clientExchangeAESKey(fd, outKey);
}

static int serverDoKeyExchangeOnFd(SocketFD fd, AESGCMKey *outKey) {
    Packet req;
    memset(&req, 0, sizeof(req));
    if (packetRecv(&req, fd) != PROTOCOL_SUCC) {
        return -1;
    }
    int ret = serverExchangeAESKey(fd, &req, outKey);
    packetClear(&req);
    return ret;
}

static int sendEnc(SocketFD fd, AESGCMKey *key, uint32_t *seq, MessageType mt,
                   const void *data, size_t len) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    if (packetInit(&pkt, mt, *seq, PlaintextPacket, data, len) !=
        PROTOCOL_SUCC) {
        return -1;
    }
    if (packetAESEncrypt(&pkt, key->key) != PROTOCOL_SUCC) {
        packetClear(&pkt);
        return -1;
    }
    (*seq)++;
    int ret = packetSend(&pkt, fd);
    packetClear(&pkt);
    return ret;
}

static int recvDec(SocketFD fd, AESGCMKey *key, Packet *out) {
    if (packetRecv(out, fd) != PROTOCOL_SUCC) {
        return -1;
    }
    if (out->header.packetType != AES256GCMPacket) {
        packetClear(out);
        return -1;
    }
    int ret = packetAESDecrypt(out, key->key);
    if (ret != PROTOCOL_SUCC) {
        packetClear(out);
        return -1;
    }
    return 0;
}

static int recvStatus(SocketFD fd, AESGCMKey *key, MessageType expectedMt) {
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

static DB *ensureTestUser(const char *username, uint32_t uid,
                          const char *password) {
    enum { TestNickLen = 8 };
    DB *userDB = dbInit(UserDB, NULL);
    if (userDB == NULL) {
        return NULL;
    }
    User u;
    memset(&u, 0, sizeof(u));
    memcpy(u.username, username, strlen(username) + 1);
    memcpy(u.nickname, "TestNick", TestNickLen + 1);
    u.uid = uid;
    u.password = strdup(password);
    if (createUser(userDB, &u) != DB_SUCC) {
    }
    free(u.password);
    return userDB;
}

static void removeTestDBFiles(void) {
    remove(USER_DB_PATH);
    remove(USER_DB_PATH "-wal");
    remove(USER_DB_PATH "-shm");
    remove(GROUP_DB_PATH);
    remove(GROUP_DB_PATH "-wal");
    remove(GROUP_DB_PATH "-shm");
    remove("./db/server.db");
    remove("./db/server.db-wal");
    remove("./db/server.db-shm");
    rmdir("./db");
}

static int serverSetupLogin(Server *s, ClientSession *cs) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    if (serverRecvEncryptedPacket(cs, &pkt) != SERVER_SUCC) {
        return -1;
    }
    if (pkt.header.messageType != MsgLoginReq) {
        packetClear(&pkt);
        return -1;
    }

    LoginRequestPayload *login = (LoginRequestPayload *)pkt.payload;
    User verify;
    memset(&verify, 0, sizeof(verify));
    memcpy(verify.username, login->username, USERNAME_MAX_LEN);
    char *dupPw = strdup(login->password);
    packetClear(&pkt);
    verify.password = dupPw;

    int dbRet = verifyUser(s->userDB, &verify);
    OPENSSL_cleanse(verify.password, strlen(verify.password));
    free(verify.password);

    if (dbRet != DB_SUCC) {
        LoginResponsePayload fr;
        memset(&fr, 0, sizeof(fr));
        serverSendEncryptedPacket(cs, MsgLoginResp, &fr, sizeof(fr));
        return -1;
    }

    cs->currentUser = verify;
    cs->state = SessionLobby;

    LoginResponsePayload sr;
    memset(&sr, 0, sizeof(sr));
    sr.uid = verify.uid;
    memcpy(sr.username, verify.username, LOGIN_USERNAME_LEN);
    memcpy(sr.nickname, verify.nickname, LOGIN_NICKNAME_LEN);
    serverSendEncryptedPacket(cs, MsgLoginResp, &sr, sizeof(sr));
    return 0;
}

/* Helper: login a client and capture their real UID. */
static uint32_t loginClient(SocketFD fd, AESGCMKey *key, uint32_t *seq,
                            const char *un, const char *pw) {
    size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *lp = calloc(1, plen);
    memcpy(lp->username, un, strlen(un) + 1);
    memcpy(lp->password, pw, strlen(pw) + 1);
    sendEnc(fd, key, seq, MsgLoginReq, lp, plen);
    OPENSSL_cleanse(lp, plen);
    free(lp);
    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    recvDec(fd, key, &rpkt);
    LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
    uint32_t uid = lresp->uid;
    packetClear(&rpkt);
    return uid;
}

/* ═══════════════════════ Group Create and List ══════════════════════════ */

static void testGroupCreateAndList(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession *clients[4] = {&csA};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 1;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgGroupCreate);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgGroupListReq);
            ASSERT_INT_EQ(serverHandleGroupList(&s, &csA), SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    uint32_t aliceUid =
        loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");
    ASSERT_TRUE(aliceUid != 0);

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "TestGroup", strlen("TestGroup") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);

        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupCreateResp);
        ASSERT_TRUE(rpkt.header.payloadLength >=
                    sizeof(GroupCreateRespPayload));
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        ASSERT_TRUE(resp->groupId != 0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupListReq, NULL, 0),
            PROTOCOL_SUCC);

        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupListResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(uint32_t));
        uint32_t count = 0;
        memcpy(&count, rpkt.payload, sizeof(uint32_t));
        ASSERT_UINT_EQ(count, (uint32_t)1);

        GroupInfo *info = (GroupInfo *)(rpkt.payload + sizeof(uint32_t));
        ASSERT_UINT_EQ(info->groupId, groupId);
        ASSERT_STR_EQ(info->groupName, "TestGroup");
        ASSERT_UINT_EQ(info->ownerUid, aliceUid);
        ASSERT_UINT_EQ(info->memberCount, (uint32_t)1);
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ═══════════════════════════ Group Join & Chat ══════════════════════════ */

static void testGroupJoinAndChat(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);
    {
        DB *tmpDB = ensureTestUser("Bob", UidBob, "bobpw");
        ASSERT_NOT_NULL(tmpDB);
        dbClose(tmpDB);
    }

    SocketFD pairA[2];
    SocketFD pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);
        socketClose(&pairB[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession csB;
        memset(&csB, 0, sizeof(csB));
        csB.fd = pairB[0];

        ClientSession *clients[4] = {&csA, &csB};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);
        onlineTrackerAdd(s.onlineTrk, csB.currentUser.uid, &csB);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgGroupCreate);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csB, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgGroupJoin);
            ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgGroupChat);
            ASSERT_INT_EQ(serverHandleGroupChat(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);
    socketClose(&pairB[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    AESGCMKey cliKeyB;
    ASSERT_INT_EQ(clientDoKeyExchange(pairB[1], &cliKeyB), PROTOCOL_SUCC);

    uint32_t seqA = 0;
    uint32_t seqB = 0;
    uint32_t aliceUid =
        loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");
    ASSERT_TRUE(aliceUid != 0);
    uint32_t bobUid = loginClient(pairB[1], &cliKeyB, &seqB, "Bob", "bobpw");
    ASSERT_TRUE(bobUid != 0);

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "TestGroup", strlen("TestGroup") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);

        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupCreateResp);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        ASSERT_TRUE(resp->groupId != 0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(
            sendEnc(pairB[1], &cliKeyB, &seqB, MsgGroupJoin, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], &cliKeyB, MsgGroupJoinResp), 0);
    }

    /* Alice receives MsgGroupMemberJoin for Bob */
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupMemberJoin);
        GroupMemberNotify *notify = (GroupMemberNotify *)rpkt.payload;
        ASSERT_UINT_EQ(notify->groupId, groupId);
        ASSERT_UINT_EQ(notify->uid, bobUid);
        packetClear(&rpkt);
    }

    {
        const char *msg = "Hello group!";
        size_t msgLen = strlen(msg) + 1;
        size_t plen = sizeof(uint32_t) + sizeof(int64_t) + msgLen;
        GroupChatPayload *gc = malloc(plen);
        ASSERT_NOT_NULL(gc);
        gc->groupId = groupId;
        gc->timestamp = TestTimestamp;
        memcpy(gc->message, msg, msgLen);
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupChat, gc, plen),
            PROTOCOL_SUCC);
        free(gc);
    }

    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupChatBroadcast);

        GroupChatBroadcastPayload *bc =
            (GroupChatBroadcastPayload *)rpkt.payload;
        ASSERT_UINT_EQ(bc->groupId, groupId);
        ASSERT_UINT_EQ(bc->uid, aliceUid);
        ASSERT_STR_EQ((const char *)bc->message, "Hello group!");
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ══════════════════════════════ Group Quit ══════════════════════════════ */

static void testGroupQuit(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);
    {
        DB *tmpDB = ensureTestUser("Bob", UidBob, "bobpw");
        ASSERT_NOT_NULL(tmpDB);
        dbClose(tmpDB);
    }

    SocketFD pairA[2];
    SocketFD pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);
        socketClose(&pairB[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession csB;
        memset(&csB, 0, sizeof(csB));
        csB.fd = pairB[0];

        ClientSession *clients[4] = {&csA, &csB};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);
        onlineTrackerAdd(s.onlineTrk, csB.currentUser.uid, &csB);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csB, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csB, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgGroupQuit);
            ASSERT_INT_EQ(serverHandleGroupQuit(&s, &csB, &pkt), SERVER_SUCC);
            ASSERT_UINT_EQ(csB.currentGroupId, (uint32_t)0);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);
    socketClose(&pairB[0]);

    AESGCMKey cliKeyA;
    AESGCMKey cliKeyB;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    ASSERT_INT_EQ(clientDoKeyExchange(pairB[1], &cliKeyB), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    uint32_t seqB = 0;

    uint32_t aliceUid =
        loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");
    ASSERT_TRUE(aliceUid != 0);
    uint32_t bobUid = loginClient(pairB[1], &cliKeyB, &seqB, "Bob", "bobpw");
    ASSERT_TRUE(bobUid != 0);

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "QuitGroup", strlen("QuitGroup") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupCreateResp);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(
            sendEnc(pairB[1], &cliKeyB, &seqB, MsgGroupJoin, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], &cliKeyB, MsgGroupJoinResp), 0);

        /* Consume MsgGroupMemberJoin on A */
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupMemberJoin);
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(
            sendEnc(pairB[1], &cliKeyB, &seqB, MsgGroupQuit, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], &cliKeyB, MsgGroupQuitResp), 0);
    }

    /* A receives MsgGroupMemberQuit for B */
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupMemberQuit);
        GroupMemberNotify *notify = (GroupMemberNotify *)rpkt.payload;
        ASSERT_UINT_EQ(notify->groupId, groupId);
        ASSERT_UINT_EQ(notify->uid, bobUid);
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ══════════════════════════ Group Kick by Owner ═════════════════════════ */

static void testGroupKickByOwner(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);
    {
        DB *tmpDB = ensureTestUser("Bob", UidBob, "bobpw");
        ASSERT_NOT_NULL(tmpDB);
        dbClose(tmpDB);
    }

    SocketFD pairA[2];
    SocketFD pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);
        socketClose(&pairB[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession csB;
        memset(&csB, 0, sizeof(csB));
        csB.fd = pairB[0];

        ClientSession *clients[4] = {&csA, &csB};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);
        onlineTrackerAdd(s.onlineTrk, csB.currentUser.uid, &csB);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csB, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupKick(&s, &csA, &pkt), SERVER_SUCC);
            ASSERT_UINT_EQ(csB.currentGroupId, (uint32_t)0);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);
    socketClose(&pairB[0]);

    AESGCMKey cliKeyA;
    AESGCMKey cliKeyB;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    ASSERT_INT_EQ(clientDoKeyExchange(pairB[1], &cliKeyB), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    uint32_t seqB = 0;

    uint32_t aliceUid =
        loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");
    ASSERT_TRUE(aliceUid != 0);
    uint32_t bobUid = loginClient(pairB[1], &cliKeyB, &seqB, "Bob", "bobpw");
    ASSERT_TRUE(bobUid != 0);

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "KickGroup", strlen("KickGroup") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupCreateResp);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(
            sendEnc(pairB[1], &cliKeyB, &seqB, MsgGroupJoin, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], &cliKeyB, MsgGroupJoinResp), 0);

        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupMemberJoin);
        packetClear(&rpkt);
    }

    {
        GroupKickPayload kick;
        memset(&kick, 0, sizeof(kick));
        kick.groupId = groupId;
        kick.targetUid = bobUid;
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupKick, &kick,
                              sizeof(kick)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairA[1], &cliKeyA, MsgGroupKickResp), 0);
    }

    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupMemberQuit);
        GroupMemberNotify *notify = (GroupMemberNotify *)rpkt.payload;
        ASSERT_UINT_EQ(notify->groupId, groupId);
        ASSERT_UINT_EQ(notify->uid, bobUid);
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ════════════════════════ Kick by Non-Owner Fails ═══════════════════════ */

static void testGroupKickByNonOwnerFails(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);
    {
        DB *tmpDB = ensureTestUser("Bob", UidBob, "bobpw");
        ASSERT_NOT_NULL(tmpDB);
        dbClose(tmpDB);
    }
    {
        DB *tmpDB = ensureTestUser("Charlie", UidCharlie, "charliepw");
        ASSERT_NOT_NULL(tmpDB);
        dbClose(tmpDB);
    }

    SocketFD pairA[2];
    SocketFD pairB[2];
    SocketFD pairC[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);
    ASSERT_INT_EQ(makeSocketPair(pairC), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);
        socketClose(&pairB[1]);
        socketClose(&pairC[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession csB;
        memset(&csB, 0, sizeof(csB));
        csB.fd = pairB[0];

        ClientSession csC;
        memset(&csC, 0, sizeof(csC));
        csC.fd = pairC[0];

        ClientSession *clients[4] = {&csA, &csB, &csC};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 3;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairC[0], &csC.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);
        onlineTrackerAdd(s.onlineTrk, csB.currentUser.uid, &csB);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csC), 0);
        onlineTrackerAdd(s.onlineTrk, csC.currentUser.uid, &csC);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csB, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csC, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csC, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csB, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupKick(&s, &csB, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
        socketClose(&pairC[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);
    socketClose(&pairB[0]);
    socketClose(&pairC[0]);

    AESGCMKey cliKeyA;
    AESGCMKey cliKeyB;
    AESGCMKey cliKeyC;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    ASSERT_INT_EQ(clientDoKeyExchange(pairB[1], &cliKeyB), PROTOCOL_SUCC);
    ASSERT_INT_EQ(clientDoKeyExchange(pairC[1], &cliKeyC), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    uint32_t seqB = 0;
    uint32_t seqC = 0;

    uint32_t aliceUid =
        loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");
    ASSERT_TRUE(aliceUid != 0);
    uint32_t bobUid = loginClient(pairB[1], &cliKeyB, &seqB, "Bob", "bobpw");
    ASSERT_TRUE(bobUid != 0);
    loginClient(pairC[1], &cliKeyC, &seqC, "Charlie", "charliepw");

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "NoKick", strlen("NoKick") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupCreateResp);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(
            sendEnc(pairB[1], &cliKeyB, &seqB, MsgGroupJoin, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], &cliKeyB, MsgGroupJoinResp), 0);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupMemberJoin);
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(
            sendEnc(pairC[1], &cliKeyC, &seqC, MsgGroupJoin, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairC[1], &cliKeyC, MsgGroupJoinResp), 0);
        Packet rpktA;
        memset(&rpktA, 0, sizeof(rpktA));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpktA), 0);
        ASSERT_INT_EQ(rpktA.header.messageType, MsgGroupMemberJoin);
        packetClear(&rpktA);
        Packet rpktB;
        memset(&rpktB, 0, sizeof(rpktB));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpktB), 0);
        ASSERT_INT_EQ(rpktB.header.messageType, MsgGroupMemberJoin);
        packetClear(&rpktB);
    }

    {
        GroupKickPayload kick;
        memset(&kick, 0, sizeof(kick));
        kick.groupId = groupId;
        kick.targetUid = bobUid;
        ASSERT_INT_EQ(sendEnc(pairB[1], &cliKeyB, &seqB, MsgGroupKick, &kick,
                              sizeof(kick)),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], &cliKeyB, MsgGroupKickResp), 1);
    }

    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    socketClose(&pairC[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ════════════════════════════ Group Disband ═════════════════════════════ */

static void testGroupDisband(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);
    {
        DB *tmpDB = ensureTestUser("Bob", UidBob, "bobpw");
        ASSERT_NOT_NULL(tmpDB);
        dbClose(tmpDB);
    }

    SocketFD pairA[2];
    SocketFD pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);
        socketClose(&pairB[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession csB;
        memset(&csB, 0, sizeof(csB));
        csB.fd = pairB[0];

        ClientSession *clients[4] = {&csA, &csB};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);
        onlineTrackerAdd(s.onlineTrk, csB.currentUser.uid, &csB);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csB, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgGroupDisband);
            ASSERT_INT_EQ(serverHandleGroupDisband(&s, &csA, &pkt),
                          SERVER_SUCC);
            ASSERT_UINT_EQ(csA.currentGroupId, (uint32_t)0);
            ASSERT_UINT_EQ(csB.currentGroupId, (uint32_t)0);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);
    socketClose(&pairB[0]);

    AESGCMKey cliKeyA;
    AESGCMKey cliKeyB;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    ASSERT_INT_EQ(clientDoKeyExchange(pairB[1], &cliKeyB), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    uint32_t seqB = 0;

    loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");
    loginClient(pairB[1], &cliKeyB, &seqB, "Bob", "bobpw");

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "DisbandMe", strlen("DisbandMe") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupCreateResp);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(
            sendEnc(pairB[1], &cliKeyB, &seqB, MsgGroupJoin, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], &cliKeyB, MsgGroupJoinResp), 0);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupMemberJoin);
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupDisband, &op,
                              sizeof(op)),
                      PROTOCOL_SUCC);
    }

    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupDisbandNotify);
        GroupDisbandNotifyPayload *notify =
            (GroupDisbandNotifyPayload *)rpkt.payload;
        ASSERT_UINT_EQ(notify->groupId, groupId);
        packetClear(&rpkt);
    }

    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupDisbandNotify);
        GroupDisbandNotifyPayload *notify =
            (GroupDisbandNotifyPayload *)rpkt.payload;
        ASSERT_UINT_EQ(notify->groupId, groupId);
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ════════════════════ Join Nonexistent Group Fails ══════════════════════ */

static void testGroupJoinNonexistent(void) {
    enum { NonexistentGroupId = 999999 };
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession *clients[4] = {&csA};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 1;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    uint32_t seqA = 0;

    loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = NonexistentGroupId;
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupJoin, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairA[1], &cliKeyA, MsgGroupJoinResp), 1);
    }

    socketClose(&pairA[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ════════════════ Group Chat Broadcast Excludes Sender ══════════════════ */

static void testGroupChatBroadcastExcludesSender(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);
    {
        DB *tmpDB = ensureTestUser("Bob", UidBob, "bobpw");
        ASSERT_NOT_NULL(tmpDB);
        dbClose(tmpDB);
    }

    SocketFD pairA[2];
    SocketFD pairB[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);
    ASSERT_INT_EQ(makeSocketPair(pairB), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);
        socketClose(&pairB[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession csB;
        memset(&csB, 0, sizeof(csB));
        csB.fd = pairB[0];

        ClientSession *clients[4] = {&csA, &csB};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);
        onlineTrackerAdd(s.onlineTrk, csB.currentUser.uid, &csB);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csB, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupJoin(&s, &csB, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupChat(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);
    socketClose(&pairB[0]);

    AESGCMKey cliKeyA;
    AESGCMKey cliKeyB;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    ASSERT_INT_EQ(clientDoKeyExchange(pairB[1], &cliKeyB), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    uint32_t seqB = 0;

    uint32_t aliceUid =
        loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");
    ASSERT_TRUE(aliceUid != 0);
    loginClient(pairB[1], &cliKeyB, &seqB, "Bob", "bobpw");

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "NoSelf", strlen("NoSelf") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupCreateResp);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupOpPayload op;
        memset(&op, 0, sizeof(op));
        op.groupId = groupId;
        ASSERT_INT_EQ(
            sendEnc(pairB[1], &cliKeyB, &seqB, MsgGroupJoin, &op, sizeof(op)),
            PROTOCOL_SUCC);
        ASSERT_INT_EQ(recvStatus(pairB[1], &cliKeyB, MsgGroupJoinResp), 0);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupMemberJoin);
        packetClear(&rpkt);
    }

    {
        const char *msg = "No echo";
        size_t msgLen = strlen(msg) + 1;
        size_t plen = sizeof(uint32_t) + sizeof(int64_t) + msgLen;
        GroupChatPayload *gc = malloc(plen);
        ASSERT_NOT_NULL(gc);
        gc->groupId = groupId;
        gc->timestamp = TestTimestamp;
        memcpy(gc->message, msg, msgLen);
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupChat, gc, plen),
            PROTOCOL_SUCC);
        free(gc);
    }

    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupChatBroadcast);
        ASSERT_STR_EQ(
            (const char *)(rpkt.payload +
                           offsetof(GroupChatBroadcastPayload, message)),
            "No echo");
        packetClear(&rpkt);
    }

    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        int ret = recvDec(pairA[1], &cliKeyA, &rpkt);
        ASSERT_INT_EQ(ret, -1);
    }

    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ═══════════════════════ Group Chat History ═════════════════════════════ */

static void testGroupChatHistoryEmpty(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession *clients[4] = {&csA};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 1;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupChatHistory(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "HistEmpty", strlen("HistEmpty") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupChatHistoryReqPayload req;
        memset(&req, 0, sizeof(req));
        req.groupId = groupId;
        req.beforeMsgId = UINT32_MAX;
        req.limit = HistoryDefaultLimit;
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupChatHistoryReq,
                              &req, sizeof(req)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupChatHistoryResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(uint32_t));
        uint32_t count = 0;
        memcpy(&count, rpkt.payload, sizeof(uint32_t));
        count = ntohl(count);
        ASSERT_UINT_EQ(count, (uint32_t)0);
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

static void testGroupChatHistoryBasic(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession *clients[4] = {&csA};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 1;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        /* Store 3 messages directly in the DB */
        uint32_t groupId = csA.currentGroupId;
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "Msg1", 1000, NULL),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "Msg2", 2000, NULL),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "Msg3", 3000, NULL),
            DB_SUCC);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupChatHistory(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "HistBasic", strlen("HistBasic") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupChatHistoryReqPayload req;
        memset(&req, 0, sizeof(req));
        req.groupId = groupId;
        req.beforeMsgId = UINT32_MAX;
        req.limit = HistoryDefaultLimit;
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupChatHistoryReq,
                              &req, sizeof(req)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupChatHistoryResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(uint32_t));

        uint32_t count = 0;
        memcpy(&count, rpkt.payload, sizeof(uint32_t));
        count = ntohl(count);
        ASSERT_UINT_EQ(count, (uint32_t)3);

        /* Verify messages are in chronological (ASC) order */
        uint8_t *cursor = rpkt.payload + sizeof(uint32_t);
        for (uint32_t i = 0; i < count; i++) {
            GroupChatBroadcastPayload *gc = (GroupChatBroadcastPayload *)cursor;
            ASSERT_UINT_EQ(gc->uid, UidAlice);
            size_t msgLen = strlen((const char *)gc->message) + 1;
            (void)msgLen;
            size_t entrySize =
                offsetof(GroupChatBroadcastPayload, message) + msgLen;
            cursor += entrySize;
        }
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

static void testGroupChatHistoryLimit(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession *clients[4] = {&csA};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 1;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        uint32_t groupId = csA.currentGroupId;
        ASSERT_INT_EQ(groupStoreChat(gdb, groupId, UidAlice, "A", 1000, NULL),
                      DB_SUCC);
        ASSERT_INT_EQ(groupStoreChat(gdb, groupId, UidAlice, "B", 2000, NULL),
                      DB_SUCC);
        ASSERT_INT_EQ(groupStoreChat(gdb, groupId, UidAlice, "C", 3000, NULL),
                      DB_SUCC);
        ASSERT_INT_EQ(groupStoreChat(gdb, groupId, UidAlice, "D", 4000, NULL),
                      DB_SUCC);
        ASSERT_INT_EQ(groupStoreChat(gdb, groupId, UidAlice, "E", 5000, NULL),
                      DB_SUCC);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupChatHistory(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "HistLim", strlen("HistLim") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    {
        GroupChatHistoryReqPayload req;
        memset(&req, 0, sizeof(req));
        req.groupId = groupId;
        req.beforeMsgId = UINT32_MAX;
        req.limit = 2;
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupChatHistoryReq,
                              &req, sizeof(req)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupChatHistoryResp);

        uint32_t count = 0;
        memcpy(&count, rpkt.payload, sizeof(uint32_t));
        count = ntohl(count);
        ASSERT_UINT_EQ(count, (uint32_t)2);
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

static void testGroupChatHistoryPagination(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *gdb = dbInit(GroupDB, NULL);
        ASSERT_NOT_NULL(gdb);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession *clients[4] = {&csA};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.groupDB = gdb;
        s.clients = clients;
        s.clientCount = 1;
        s.clientCapacity = 4;
        s.onlineTrk = onlineTrackerCreate();

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        onlineTrackerAdd(s.onlineTrk, csA.currentUser.uid, &csA);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupCreate(&s, &csA, &pkt), SERVER_SUCC);
            packetClear(&pkt);
        }

        /* Store messages. We will paginate with beforeMsgId set to the
         * ID of the 6th message to get messages 1-5 (ASC). The SQL query
         * returns msgId < beforeMsgId ORDER BY msgId DESC, then the
         * handler reverses to ASC. */
        uint32_t groupId = csA.currentGroupId;
        uint64_t msgIds[TestBatchMsgCount];
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "0", 1000, &msgIds[0]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "1", 2000, &msgIds[1]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "2", 3000, &msgIds[2]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "3", 4000, &msgIds[3]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "4", 5000, &msgIds[4]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "5", 6000, &msgIds[5]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "6", 7000, &msgIds[6]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "7", 8000, &msgIds[7]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "8", 9000, &msgIds[8]),
            DB_SUCC);
        ASSERT_INT_EQ(
            groupStoreChat(gdb, groupId, UidAlice, "9", 10000, &msgIds[9]),
            DB_SUCC);

        (void)msgIds;

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupChatHistory(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(serverHandleGroupChatHistory(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gdb);
        socketClose(&pairA[0]);
        onlineTrackerDestroy(s.onlineTrk);
        _exit(0);
    }

    socketClose(&pairA[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    uint32_t seqA = 0;
    loginClient(pairA[1], &cliKeyA, &seqA, "Alice", "alicepw");

    uint32_t groupId = 0;
    {
        GroupCreatePayload create;
        memset(&create, 0, sizeof(create));
        memcpy(create.groupName, "HistPage", strlen("HistPage") + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupCreate,
                              &create, sizeof(create)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        GroupCreateRespPayload *resp = (GroupCreateRespPayload *)rpkt.payload;
        ASSERT_UINT_EQ(resp->status, (uint8_t)0);
        groupId = resp->groupId;
        packetClear(&rpkt);
    }

    /* First request: get all messages to find the msgId of the 6th */
    {
        GroupChatHistoryReqPayload req;
        memset(&req, 0, sizeof(req));
        req.groupId = groupId;
        req.beforeMsgId = UINT32_MAX;
        req.limit = HistoryDefaultLimit;
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupChatHistoryReq,
                              &req, sizeof(req)),
                      PROTOCOL_SUCC);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgGroupChatHistoryResp);

        uint32_t count = 0;
        memcpy(&count, rpkt.payload, sizeof(uint32_t));
        count = ntohl(count);
        ASSERT_UINT_EQ(count, (uint32_t)TestBatchMsgCount);

        /* Get msgId of the 6th message (index TestPageBeforeIdx) */
        uint32_t midMsgId = 0;
        uint8_t *cursor = rpkt.payload + sizeof(uint32_t);
        for (uint32_t i = 0; i < count; i++) {
            GroupChatBroadcastPayload *gc = (GroupChatBroadcastPayload *)cursor;
            if (i == TestPageBeforeIdx) {
                midMsgId = gc->msgId;
            }
            size_t msgLen = strlen((const char *)gc->message) + 1;
            size_t entrySize =
                offsetof(GroupChatBroadcastPayload, message) + msgLen;
            cursor += entrySize;
        }
        packetClear(&rpkt);

        /* Second request: paginate with beforeMsgId = 6th message's ID.
         * Should get messages before it = TestPageBeforeIdx messages. */
        GroupChatHistoryReqPayload req2;
        memset(&req2, 0, sizeof(req2));
        req2.groupId = groupId;
        req2.beforeMsgId = midMsgId;
        req2.limit = HistoryDefaultLimit;
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgGroupChatHistoryReq,
                              &req2, sizeof(req2)),
                      PROTOCOL_SUCC);
        Packet rpkt2;
        memset(&rpkt2, 0, sizeof(rpkt2));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt2), 0);
        ASSERT_INT_EQ(rpkt2.header.messageType, MsgGroupChatHistoryResp);

        uint32_t count2 = 0;
        memcpy(&count2, rpkt2.payload, sizeof(uint32_t));
        count2 = ntohl(count2);
        ASSERT_UINT_EQ(count2, (uint32_t)TestPageBeforeIdx);
        packetClear(&rpkt2);
    }

    socketClose(&pairA[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ════════════════════════════════ Main ═════════════════════════════════ */

int main(void) {
    logSetLevel(LogLevelFatal);
    removeTestDBFiles();

    printf("test_group:\n");

    RUN_TEST(testGroupCreateAndList);
    RUN_TEST(testGroupJoinAndChat);
    RUN_TEST(testGroupQuit);
    RUN_TEST(testGroupKickByOwner);
    RUN_TEST(testGroupKickByNonOwnerFails);
    RUN_TEST(testGroupDisband);
    RUN_TEST(testGroupJoinNonexistent);
    RUN_TEST(testGroupChatBroadcastExcludesSender);
    RUN_TEST(testGroupChatHistoryEmpty);
    RUN_TEST(testGroupChatHistoryBasic);
    RUN_TEST(testGroupChatHistoryLimit);
    RUN_TEST(testGroupChatHistoryPagination);

    removeTestDBFiles();

    return TEST_REPORT();
}
