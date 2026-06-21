/**
 * @file test_private_chat.c
 * @brief Integration tests for private (1-to-1) chat.
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
#include "server/onlineTracker.h"
#include "server/privateChat.h"
#include "server/server.h"
#include "test_utils.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/* ──────────────────────────── named constants ────────────────────────── */

enum {
    UidAlice = 1000,
    UidBob = 1001,
    TestTimestamp = 1234567890,
    TestTimestamp2 = 1234567891,
    TestTimestamp3 = 1234567892,
    DefaultHistoryLimit = 50,
    MinChatPayloadSize = 8,
};

/* ──────────────────────── helper prototypes ──────────────────────────── */

static int makeSocketPair(SocketFD pair[2]);
static int clientDoKeyExchange(SocketFD fd, AESGCMKey *outKey);
static int serverDoKeyExchangeOnFd(SocketFD fd, AESGCMKey *outKey);
static int sendEnc(SocketFD fd, AESGCMKey *key, uint32_t *seq, MessageType mt,
                   const void *data, size_t len);
static int recvDec(SocketFD fd, AESGCMKey *key, Packet *out);
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
    enum { SocketTimeoutSec = 30 };
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

static DB *ensureTestUser(const char *username, uint32_t uid,
                          const char *password) {
    DB *userDB = dbInit(UserDB, NULL);
    if (userDB == NULL) {
        return NULL;
    }
    User u;
    memset(&u, 0, sizeof(u));
    memcpy(u.username, username, strlen(username) + 1);
    memcpy(u.nickname, "TestNick", MinChatPayloadSize + 1);
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
    remove(PRIVATE_CHAT_DB_PATH);
    remove(PRIVATE_CHAT_DB_PATH "-wal");
    remove(PRIVATE_CHAT_DB_PATH "-shm");
    remove(FRIEND_DB_PATH);
    remove(FRIEND_DB_PATH "-wal");
    remove(FRIEND_DB_PATH "-shm");
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
    onlineTrackerAdd(s->onlineTrk, verify.uid, cs);

    serverDeliverOfflineMessages(s, cs);

    LoginResponsePayload sr;
    memset(&sr, 0, sizeof(sr));
    sr.uid = verify.uid;
    memcpy(sr.username, verify.username, LOGIN_USERNAME_LEN);
    memcpy(sr.nickname, verify.nickname, LOGIN_NICKNAME_LEN);
    serverSendEncryptedPacket(cs, MsgLoginResp, &sr, sizeof(sr));
    return 0;
}

/* ═══════════════════════ Private Chat Send & Receive ═══════════════════ */

static void testPrivateChatSendAndReceive(void) {
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
        DB *pdb = dbInit(PrivateChatDB, NULL);
        ASSERT_NOT_NULL(pdb);

        OnlineTracker *trk = onlineTrackerCreate();
        ASSERT_NOT_NULL(trk);

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
        s.privateChatDB = pdb;
        s.onlineTrk = trk;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);

        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgPrivateChat);
            ASSERT_INT_EQ(serverHandlePrivateChatSend(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(pdb);
        onlineTrackerDestroy(trk);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
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
    uint32_t aliceUid = 0;
    uint32_t bobUid = 0;

    /* Login Alice — capture real UID */
    {
        const char *un = "Alice";
        const char *pw = "alicepw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        ASSERT_NOT_NULL(lp);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgLoginReq, lp, plen),
                      PROTOCOL_SUCC);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        aliceUid = lresp->uid;
        packetClear(&rpkt);
    }

    /* Login Bob — capture real UID */
    {
        const char *un = "Bob";
        const char *pw = "bobpw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        ASSERT_NOT_NULL(lp);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(pairB[1], &cliKeyB, &seqB, MsgLoginReq, lp, plen),
                      PROTOCOL_SUCC);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        bobUid = lresp->uid;
        packetClear(&rpkt);
    }

    /* Alice sends private chat to Bob using real UIDs */
    {
        const char *msg = "Hello Bob!";
        size_t msgLen = strlen(msg) + 1;
        size_t plen = offsetof(PrivateChatPayload, message) + msgLen;
        PrivateChatPayload *pc = malloc(plen);
        ASSERT_NOT_NULL(pc);
        pc->fromUid = aliceUid;
        pc->toUid = bobUid;
        pc->msgId = 0;
        pc->timestamp = TestTimestamp;
        memcpy(pc->message, msg, msgLen);
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgPrivateChat, pc, plen),
            PROTOCOL_SUCC);
        free(pc);

        /* Bob receives broadcast */
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgPrivateChatBroadcast);

        PrivateChatPayload *bc = (PrivateChatPayload *)rpkt.payload;
        ASSERT_UINT_EQ(bc->fromUid, aliceUid);
        ASSERT_UINT_EQ(bc->toUid, bobUid);
        ASSERT_STR_EQ((const char *)bc->message, msg);
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ══════════════════════ Empty Message Rejected ══════════════════════════ */

static void testPrivateChatEmptyMessageRejected(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);

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
        DB *pdb = dbInit(PrivateChatDB, NULL);
        ASSERT_NOT_NULL(pdb);
        OnlineTracker *trk = onlineTrackerCreate();
        ASSERT_NOT_NULL(trk);

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
        s.privateChatDB = pdb;
        s.onlineTrk = trk;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgPrivateChat);
            ASSERT_INT_EQ(serverHandlePrivateChatSend(&s, &csA, &pkt),
                          SERVER_FAIL);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(pdb);
        onlineTrackerDestroy(trk);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
        _exit(0);
    }

    socketClose(&pairA[0]);
    socketClose(&pairB[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    AESGCMKey cliKeyB;
    ASSERT_INT_EQ(clientDoKeyExchange(pairB[1], &cliKeyB), PROTOCOL_SUCC);

    uint32_t seqA = 0;

    /* Login Alice */
    {
        const char *un = "Alice";
        const char *pw = "alicepw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        ASSERT_NOT_NULL(lp);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgLoginReq, lp, plen),
                      PROTOCOL_SUCC);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        packetClear(&rpkt);
    }

    /* Send empty message (only NUL byte) */
    {
        const char *msg = "";
        size_t msgLen = 1;
        size_t plen = offsetof(PrivateChatPayload, message) + msgLen;
        PrivateChatPayload *pc = malloc(plen);
        ASSERT_NOT_NULL(pc);
        pc->fromUid = UidAlice;
        pc->toUid = UidBob;
        pc->msgId = 0;
        pc->timestamp = TestTimestamp;
        memcpy(pc->message, msg, msgLen);
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgPrivateChat, pc, plen),
            PROTOCOL_SUCC);
        free(pc);
    }

    (void)cliKeyB;
    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ═══════════════════════════ Chat History ════════════════════════════════ */

static void testPrivateChatHistory(void) {
    removeTestDBFiles();
    DB *userDB = ensureTestUser("Alice", UidAlice, "alicepw");
    ASSERT_NOT_NULL(userDB);
    {
        DB *tmpDB = ensureTestUser("Bob", UidBob, "bobpw");
        ASSERT_NOT_NULL(tmpDB);
        dbClose(tmpDB);
    }

    SocketFD pairA[2];
    ASSERT_INT_EQ(makeSocketPair(pairA), 0);

    dbClose(userDB);
    pid_t child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        socketClose(&pairA[1]);

        userDB = dbInit(UserDB, NULL);
        ASSERT_NOT_NULL(userDB);
        DB *pdb = dbInit(PrivateChatDB, NULL);
        ASSERT_NOT_NULL(pdb);
        OnlineTracker *trk = onlineTrackerCreate();
        ASSERT_NOT_NULL(trk);

        ClientSession csA;
        memset(&csA, 0, sizeof(csA));
        csA.fd = pairA[0];

        ClientSession *clients[4] = {&csA};

        Server s;
        memset(&s, 0, sizeof(s));
        s.userDB = userDB;
        s.privateChatDB = pdb;
        s.onlineTrk = trk;
        s.clients = clients;
        s.clientCount = 1;
        s.clientCapacity = 4;

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);

        /* Alice sends 3 messages */
        for (int i = 0; i < 3; i++) {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgPrivateChat);
            ASSERT_INT_EQ(serverHandlePrivateChatSend(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        /* Alice requests history */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgPrivateChatHistoryReq);
            ASSERT_INT_EQ(serverHandlePrivateChatHistory(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(pdb);
        onlineTrackerDestroy(trk);
        socketClose(&pairA[0]);
        _exit(0);
    }

    socketClose(&pairA[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    uint32_t seqA = 0;

    /* Login Alice */
    {
        const char *un = "Alice";
        const char *pw = "alicepw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        ASSERT_NOT_NULL(lp);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgLoginReq, lp, plen),
                      PROTOCOL_SUCC);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        packetClear(&rpkt);
    }

    /* Alice sends 3 messages to Bob */
    const char *msgs[] = {"Msg1", "Msg2", "Msg3"};
    for (int i = 0; i < 3; i++) {
        size_t msgLen = strlen(msgs[i]) + 1;
        size_t plen = offsetof(PrivateChatPayload, message) + msgLen;
        PrivateChatPayload *pc = malloc(plen);
        ASSERT_NOT_NULL(pc);
        pc->fromUid = UidAlice;
        pc->toUid = UidBob;
        pc->msgId = 0;
        pc->timestamp = TestTimestamp + (int64_t)i;
        memcpy(pc->message, msgs[i], msgLen);
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgPrivateChat, pc, plen),
            PROTOCOL_SUCC);
        free(pc);
    }

    /* Alice requests history with Bob */
    {
        PrivateChatHistoryReqPayload req;
        memset(&req, 0, sizeof(req));
        req.peerUid = UidBob;
        req.beforeMsgId = 0;
        req.limit = DefaultHistoryLimit;
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA,
                              MsgPrivateChatHistoryReq, &req, sizeof(req)),
                      PROTOCOL_SUCC);

        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgPrivateChatHistoryResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(uint32_t));
        uint32_t netCount = 0;
        memcpy(&netCount, rpkt.payload, sizeof(uint32_t));
        uint32_t count = ntohl(netCount);
        ASSERT_UINT_EQ(count, (uint32_t)3);

        PacketHeader *hdr = &rpkt.header;
        size_t offset = sizeof(uint32_t);
        for (uint32_t i = 0; i < count; i++) {
            ASSERT_TRUE(offset + offsetof(PrivateChatPayload, message) <=
                        hdr->payloadLength);
            PrivateChatPayload *pc =
                (PrivateChatPayload *)(rpkt.payload + offset);
            size_t msgLen = strlen((const char *)pc->message) + 1;
            offset += offsetof(PrivateChatPayload, message) + msgLen;
        }
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ═══════════════════════════ Offline Delivery ════════════════════════════ */

static void testPrivateChatOfflineDelivery(void) {
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
        DB *pdb = dbInit(PrivateChatDB, NULL);
        ASSERT_NOT_NULL(pdb);
        OnlineTracker *trk = onlineTrackerCreate();
        ASSERT_NOT_NULL(trk);

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
        s.privateChatDB = pdb;
        s.onlineTrk = trk;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);

        /* Alice sends message while Bob is offline */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgPrivateChat);
            ASSERT_INT_EQ(serverHandlePrivateChatSend(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        /* Bob logs in (key exchange + login) */
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);

        dbClose(userDB);
        dbClose(pdb);
        onlineTrackerDestroy(trk);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
        _exit(0);
    }

    socketClose(&pairA[0]);
    socketClose(&pairB[0]);

    AESGCMKey cliKeyA;
    ASSERT_INT_EQ(clientDoKeyExchange(pairA[1], &cliKeyA), PROTOCOL_SUCC);
    uint32_t seqA = 0;

    /* Login Alice */
    {
        const char *un = "Alice";
        const char *pw = "alicepw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        ASSERT_NOT_NULL(lp);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgLoginReq, lp, plen),
                      PROTOCOL_SUCC);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        packetClear(&rpkt);
    }

    /* Alice sends message to offline Bob */
    {
        const char *msg = "Offline hello";
        size_t msgLen = strlen(msg) + 1;
        size_t plen = offsetof(PrivateChatPayload, message) + msgLen;
        PrivateChatPayload *pc = malloc(plen);
        ASSERT_NOT_NULL(pc);
        pc->fromUid = UidAlice;
        pc->toUid = UidBob;
        pc->msgId = 0;
        pc->timestamp = TestTimestamp;
        memcpy(pc->message, msg, msgLen);
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgPrivateChat, pc, plen),
            PROTOCOL_SUCC);
        free(pc);
    }

    /* Bob logs in and receives offline messages */
    {
        AESGCMKey cliKeyB;
        ASSERT_INT_EQ(clientDoKeyExchange(pairB[1], &cliKeyB), PROTOCOL_SUCC);
        uint32_t seqB = 0;

        const char *un = "Bob";
        const char *pw = "bobpw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        ASSERT_NOT_NULL(lp);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(pairB[1], &cliKeyB, &seqB, MsgLoginReq, lp, plen),
                      PROTOCOL_SUCC);
        OPENSSL_cleanse(lp, plen);
        free(lp);

        /* serverDeliverOfflineMessages sends before MsgLoginResp */
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);

        if (rpkt.header.messageType == MsgPrivateChatBroadcast) {
            ASSERT_STR_EQ((const char *)(rpkt.payload +
                                         offsetof(PrivateChatPayload, message)),
                          "Offline hello");
            packetClear(&rpkt);
            /* Now receive the login response */
            memset(&rpkt, 0, sizeof(rpkt));
            ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        }

        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        packetClear(&rpkt);
    }

    socketClose(&pairA[1]);
    socketClose(&pairB[1]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ═══════════════════ Sender Not Receive Own Message ══════════════════════ */

static void testPrivateChatSenderNotReceiveOwnMessage(void) {
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
        DB *pdb = dbInit(PrivateChatDB, NULL);
        ASSERT_NOT_NULL(pdb);
        OnlineTracker *trk = onlineTrackerCreate();
        ASSERT_NOT_NULL(trk);

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
        s.privateChatDB = pdb;
        s.onlineTrk = trk;
        s.clients = clients;
        s.clientCount = 2;
        s.clientCapacity = 4;

        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairA[0], &csA.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverDoKeyExchangeOnFd(pairB[0], &csB.aesKey),
                      PROTOCOL_SUCC);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csA), 0);
        ASSERT_INT_EQ(serverSetupLogin(&s, &csB), 0);

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(serverRecvEncryptedPacket(&csA, &pkt), SERVER_SUCC);
            ASSERT_INT_EQ(pkt.header.messageType, MsgPrivateChat);
            ASSERT_INT_EQ(serverHandlePrivateChatSend(&s, &csA, &pkt),
                          SERVER_SUCC);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(pdb);
        onlineTrackerDestroy(trk);
        socketClose(&pairA[0]);
        socketClose(&pairB[0]);
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
    uint32_t aliceUid = 0;
    uint32_t bobUid = 0;

    /* Login Alice */
    {
        const char *un = "Alice";
        const char *pw = "alicepw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        ASSERT_NOT_NULL(lp);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(pairA[1], &cliKeyA, &seqA, MsgLoginReq, lp, plen),
                      PROTOCOL_SUCC);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairA[1], &cliKeyA, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        aliceUid = lresp->uid;
        packetClear(&rpkt);
    }

    /* Login Bob */
    {
        const char *un = "Bob";
        const char *pw = "bobpw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        ASSERT_NOT_NULL(lp);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(pairB[1], &cliKeyB, &seqB, MsgLoginReq, lp, plen),
                      PROTOCOL_SUCC);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        bobUid = lresp->uid;
        packetClear(&rpkt);
    }

    /* Alice sends to Bob */
    {
        const char *msg = "Only Bob should see this";
        size_t msgLen = strlen(msg) + 1;
        size_t plen = offsetof(PrivateChatPayload, message) + msgLen;
        PrivateChatPayload *pc = malloc(plen);
        ASSERT_NOT_NULL(pc);
        pc->fromUid = aliceUid;
        pc->toUid = bobUid;
        pc->msgId = 0;
        pc->timestamp = TestTimestamp;
        memcpy(pc->message, msg, msgLen);
        ASSERT_INT_EQ(
            sendEnc(pairA[1], &cliKeyA, &seqA, MsgPrivateChat, pc, plen),
            PROTOCOL_SUCC);
        free(pc);
    }

    /* Bob receives broadcast */
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(pairB[1], &cliKeyB, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgPrivateChatBroadcast);
        ASSERT_STR_EQ((const char *)(rpkt.payload +
                                     offsetof(PrivateChatPayload, message)),
                      "Only Bob should see this");
        packetClear(&rpkt);
    }

    /* Alice should NOT receive anything */
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

/* ════════════════════════════════ Main ══════════════════════════════════ */

int main(void) {
    logSetLevel(LogLevelFatal);
    removeTestDBFiles();

    printf("test_private_chat:\n");

    RUN_TEST(testPrivateChatSendAndReceive);
    RUN_TEST(testPrivateChatEmptyMessageRejected);
    RUN_TEST(testPrivateChatHistory);
    RUN_TEST(testPrivateChatOfflineDelivery);
    RUN_TEST(testPrivateChatSenderNotReceiveOwnMessage);

    removeTestDBFiles();

    return TEST_REPORT();
}
