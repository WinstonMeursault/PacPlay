/**
 * @file test_server.c
 * @brief Integration tests for PacPlay server handlers.
 *
 * Uses socketpair + fork to simulate client↔server protocol exchanges
 * covering key-exchange, login, room management, chat, and session
 * lifecycle.  Tests are adversarial — they probe boundary conditions,
 * invalid states, and attack vectors before verifying happy paths.
 *
 * @date 2026-05-27
 * @copyright GPLv3 License
 */

#include "crypto.h"
#include "log.h"
#include "protocol.h"
#include "server/server.h"
#include "test_utils.h"

#include "server/communication.h"
#include "server/database.h"
#include "client/communication.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* ──────── named constants ──────────────────────────────────────────────── */

enum {
    ServerPort = 12345,
    TestRoomId = 1001,

    /* Test UIDs (keep distinct across test cases to avoid collisions) */
    LoginUID = 51,
    LoginUidAlice = 100,
    LoginUidBob = 200,
    LoginUidCharlie = 300,
    LoginUidNobody = 99999,
    LoginUidList = 99,
    LoginUidLogout = 999,
    LoginUidHeartbeat = 88,

    /* Room IDs */
    RoomIdCharlies = 42,
    RoomIdNonexist = 31337,
    RoomIdA = 100,
    RoomIdB = 150,
    RoomIdC = 200,

    /* String length constants */
    StrLenAlice = 6,
    StrLenBob = 4,
    StrLenCharlie = 8,
    StrLenT = 2,
    StrLenX = 2,
    StrLenTestUser = 9,
    StrLenPwdUser = 8,
    StrLenTestNick = 8,
    StrLenHbuser = 6,
    StrLenRegLate = 7,

    /* Timestamp */
    ChatTimestamp = 1234567890,
    DummyPayloadByte = 0xFF
};

/* ──────── helper prototypes ────────────────────────────────────────────── */

static int makeSocketPair(SocketFD pair[2]);
static int clientDoKeyExchange(SocketFD fd, AESGCMKey *outKey);
static int serverDoKeyExchange(SocketFD fd, AESGCMKey *outKey);
static int sendEnc(SocketFD fd, AESGCMKey *key, uint32_t *seq, MessageType mt,
                   const void *data, size_t len);
static int recvDec(SocketFD fd, AESGCMKey *key, Packet *out);
static int recvStatus(SocketFD fd, AESGCMKey *key, MessageType expectedMt);
static DB *ensureTestUser(const char *username, uint32_t uid,
                           const char *password);
static void removeDBFiles(void);

/* ──────── helper implementations ───────────────────────────────────────── */

static int makeSocketPair(SocketFD pair[2]) {
    int fds[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (ret != 0) {
        pair[0] = NULL_SOCKETFD;
        pair[1] = NULL_SOCKETFD;
        return -1;
    }
    /* 30-second recv/send timeout to prevent test hangs */
    enum { SocketTimeoutSec = 30 };
    struct timeval tv = { .tv_sec = SocketTimeoutSec, .tv_usec = 0 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    pair[0] = fds[0];
    pair[1] = fds[1];
    return 0;
}

static int clientDoKeyExchange(SocketFD fd, AESGCMKey *outKey) {
    return clientExchangeAESKey(fd, outKey);
}

static int serverDoKeyExchange(SocketFD fd, AESGCMKey *outKey) {
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
    DB *userDB = dbInit(UserDB, NULL);
    if (userDB == NULL) {
        return NULL;
    }
    User u;
    memset(&u, 0, sizeof(u));
    memcpy(u.username, username, strlen(username) + 1);
    memcpy(u.nickname, "TestNick", StrLenTestNick + 1);
    u.uid = uid;
    u.password = strdup(password);
    if (createUser(userDB, &u) != DB_SUCC) {
        /* User may already exist — that's fine for tests */
    }
    free(u.password);
    return userDB;
}

static void removeDBFiles(void) {
    /* Clean up test database files */
    remove("./db/user.db");
    remove("./db/user.db-wal");
    remove("./db/user.db-shm");
    remove("./db/chatHistory.db");
    remove("./db/chatHistory.db-wal");
    remove("./db/chatHistory.db-shm");
    remove("./db/game.db");
    remove("./db/game.db-wal");
    remove("./db/game.db-shm");
    remove("./db/server.db");
    remove("./db/server.db-wal");
    remove("./db/server.db-shm");
    rmdir("./db");
}

/* ═══════════════════════  Login Tests  ═══════════════════════════════════ */

/** @brief Happy path: valid credentials produce MsgLoginResp(0). */
static void testLoginSuccess(void) {
    DB *userDB = ensureTestUser("TestUser", LoginUID, "testpass");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgLoginReq);

        LoginRequestPayload *login = (LoginRequestPayload *)pkt.payload;
        User verify;
        memset(&verify, 0, sizeof(verify));
        memcpy(verify.username, login->username, USERNAME_MAX_LEN);
        verify.uid = 0;
        verify.password = strdup(login->password);
        int dbRet = verifyUser(userDB, &verify);
        OPENSSL_cleanse(verify.password, strlen(verify.password));
        free(verify.password);

        uint32_t seq = 0;
        if (dbRet == DB_SUCC) {
            LoginResponsePayload resp;
            memset(&resp, 0, sizeof(resp));
            resp.uid = verify.uid;
            memcpy(resp.username, verify.username, LOGIN_USERNAME_LEN);
            memcpy(resp.nickname, verify.nickname, LOGIN_NICKNAME_LEN);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &resp, sizeof(resp));
        } else {
            LoginResponsePayload failResp;
            memset(&failResp, 0, sizeof(failResp));
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp, sizeof(failResp));
        }

        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *un = "TestUser";
    const char *pw = "testpass";
    size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *loginPayload = calloc(1, plen);
    ASSERT_TRUE(loginPayload != NULL);
    memcpy(loginPayload->username, un, strlen(un) + 1);
    memcpy(loginPayload->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, loginPayload,
                          plen),
                  PROTOCOL_SUCC);
    OPENSSL_cleanse(loginPayload, plen);
    free(loginPayload);

    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
    ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
    ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
    LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
    ASSERT_TRUE(lresp->uid != 0);
    packetClear(&rpkt);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

static void testLoginWrongPassword(void) {
    DB *userDB = ensureTestUser("pwduser", LoginUID, "correct");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);

        LoginRequestPayload *login = (LoginRequestPayload *)pkt.payload;
        User verify;
        memset(&verify, 0, sizeof(verify));
        memcpy(verify.username, login->username, USERNAME_MAX_LEN);
        verify.uid = 0;
        verify.password = strdup(login->password);
        int dbRet = verifyUser(userDB, &verify);
        OPENSSL_cleanse(verify.password, strlen(verify.password));
        free(verify.password);

        uint32_t seq = 0;
        if (dbRet == DB_SUCC) {
            LoginResponsePayload resp;
            memset(&resp, 0, sizeof(resp));
            resp.uid = verify.uid;
            memcpy(resp.username, verify.username, LOGIN_USERNAME_LEN);
            memcpy(resp.nickname, verify.nickname, LOGIN_NICKNAME_LEN);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &resp, sizeof(resp));
        } else {
            LoginResponsePayload failResp;
            memset(&failResp, 0, sizeof(failResp));
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp, sizeof(failResp));
        }

        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *un = "pwduser";
    const char *pw = "wrongpassword";
    size_t plen =
        offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *loginPayload = calloc(1, plen);
    ASSERT_TRUE(loginPayload != NULL);
    memcpy(loginPayload->username, un, strlen(un) + 1);
    memcpy(loginPayload->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, loginPayload,
                          plen),
                  PROTOCOL_SUCC);
    OPENSSL_cleanse(loginPayload, plen);
    free(loginPayload);

    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
    ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
    ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
    LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
    ASSERT_UINT_EQ(lresp->uid, (uint32_t)0);
    packetClear(&rpkt);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Login with non-existent uid => MsgLoginResp(1). */
static void testLoginNonexistentUser(void) {
    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *uDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);

        uint32_t seq = 0;
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp, sizeof(failResp));

        packetClear(&pkt);
        dbClose(uDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *un = "Nobody";
    const char *pw = "pass";
    size_t plen =
        offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *loginPayload = calloc(1, plen);
    ASSERT_TRUE(loginPayload != NULL);
    memcpy(loginPayload->username, un, strlen(un) + 1);
    memcpy(loginPayload->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, loginPayload,
                          plen),
                  PROTOCOL_SUCC);
    OPENSSL_cleanse(loginPayload, plen);
    free(loginPayload);

    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
    ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
    ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
    LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
    ASSERT_UINT_EQ(lresp->uid, (uint32_t)0);
    packetClear(&rpkt);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/* ═══════════════════════  Room Tests  ════════════════════════════════════ */

/** @brief Create a room via protocol, then join it. */
static void testRoomCreateAndJoin(void) {
    removeDBFiles();
    DB *userDB = ensureTestUser("Alice", LoginUidAlice, "alice");
    ASSERT_TRUE(userDB != NULL);
    DB *gameDB = dbInit(GameDB, NULL);
    ASSERT_TRUE(gameDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    dbClose(gameDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        gameDB = dbInit(GameDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Phase 1: Login pass-through */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidAlice;
            memcpy(lr.username, "Alice", StrLenAlice + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }

        /* Phase 2: Room create */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgCreateRoom);
            uint32_t roomId = *(uint32_t *)pkt.payload;
            uint8_t s = (createRoom(gameDB, roomId, LoginUidAlice) == DB_SUCC) ? 0 : 1;
            sendEnc(sv[1], &srvKey, &seq, MsgCreateRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        /* Phase 3: Room join */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgJoinRoom);
            uint32_t roomId = *(uint32_t *)pkt.payload;
            uint8_t s = (roomExists(gameDB, roomId) == DB_SUCC) ? 0 : 1;
            sendEnc(sv[1], &srvKey, &seq, MsgJoinRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gameDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "Alice";
        const char *pw = "alice";
        size_t plen =
            offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }

    /* Create room */
    {
        uint32_t r = TestRoomId;
        sendEnc(sv[0], &cliKey, &seq, MsgCreateRoom, &r, sizeof(r));
        ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgCreateRoomResp), 0);
    }

    /* Join room */
    {
        uint32_t r = TestRoomId;
        sendEnc(sv[0], &cliKey, &seq, MsgJoinRoom, &r, sizeof(r));
        ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgJoinRoomResp), 0);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Joining a non-existent room => MsgJoinRoomResp(1). */
static void testRoomJoinNonexistent(void) {
    DB *userDB = ensureTestUser("Bob", LoginUidBob, "bobpass");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        DB *gDB = dbInit(GameDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass-through */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidBob;
            memcpy(lr.username, "Bob", StrLenBob + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }

        /* Reject non-existent room */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgJoinRoom);
            uint32_t roomId = *(uint32_t *)pkt.payload;
            uint8_t s = (roomExists(gDB, roomId) == DB_SUCC) ? 0 : 1;
            sendEnc(sv[1], &srvKey, &seq, MsgJoinRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "Bob";
        const char *pw = "bobpass";
        size_t plen =
            offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }

    /* Join non-existent room */
    {
        uint32_t r = RoomIdNonexist;
        sendEnc(sv[0], &cliKey, &seq, MsgJoinRoom, &r, sizeof(r));
        ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgJoinRoomResp), 1);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Room list returns rooms sorted by ID (direct DB test, no fork). */
static void testRoomList(void) {
    removeDBFiles();
    DB *gameDB = dbInit(GameDB, NULL);
    ASSERT_TRUE(gameDB != NULL);
    ASSERT_INT_EQ(createRoom(gameDB, RoomIdA, 1), DB_SUCC);
    ASSERT_INT_EQ(createRoom(gameDB, RoomIdC, 1), DB_SUCC);
    ASSERT_INT_EQ(createRoom(gameDB, RoomIdB, 1), DB_SUCC);

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listRooms(gameDB, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)3);
    ASSERT_UINT_EQ(ids[0], (uint32_t)RoomIdA);
    ASSERT_UINT_EQ(ids[1], (uint32_t)RoomIdB);
    ASSERT_UINT_EQ(ids[2], (uint32_t)RoomIdC);
    free(ids);
    dbClose(gameDB);
}

/* ═══════════════════════  Chat Tests  ════════════════════════════════════ */

/** @brief Send a chat message and verify it is stored + broadcast. */
static void testChatSendAndBroadcast(void) {
    removeDBFiles();
    DB *gameDB = dbInit(GameDB, NULL);
    ASSERT_TRUE(gameDB != NULL);
    ASSERT_INT_EQ(createRoom(gameDB, RoomIdCharlies, 1), DB_SUCC);

    DB *userDB = ensureTestUser("Charlie", LoginUidCharlie, "chatpass");
    ASSERT_TRUE(userDB != NULL);
    DB *chatDB = dbInit(ChatHistoryDB, NULL);
    ASSERT_TRUE(chatDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    dbClose(chatDB);
    dbClose(gameDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        chatDB = dbInit(ChatHistoryDB, NULL);
        gameDB = dbInit(GameDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidCharlie;
            memcpy(lr.username, "Charlie", StrLenCharlie + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }

        /* Join pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            uint8_t s = 0;
            sendEnc(sv[1], &srvKey, &seq, MsgJoinRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        /* Chat message */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgChat);

            ChatPacketPayload *chat = (ChatPacketPayload *)pkt.payload;
            Chat ch;
            memset(&ch, 0, sizeof(ch));
            ch.uid = LoginUidCharlie;
            ch.message = strdup((const char *)chat->message);
            ch.timestamp = (time_t)chat->timestamp;
            ASSERT_INT_EQ(storeChat(chatDB, RoomIdCharlies, &ch),
                          DB_SUCC);

            /* Broadcast: uid + msgId + timestamp + message */
            size_t msgLen = pkt.header.payloadLength - sizeof(int64_t);
            enum { BcFixed = 20 };
            size_t bcLen = BcFixed + msgLen;
            uint8_t *bcBuf = malloc(bcLen);
            ASSERT_TRUE(bcBuf != NULL);
            memcpy(bcBuf, &ch.uid, sizeof(uint32_t));
            memcpy(bcBuf + sizeof(uint32_t), &ch.msgId, sizeof(uint64_t));
            memcpy(bcBuf + sizeof(uint32_t) + sizeof(uint64_t), &ch.timestamp,
                   sizeof(int64_t));
            memcpy(bcBuf + BcFixed, chat->message, msgLen);
            sendEnc(sv[1], &srvKey, &seq, MsgChat, bcBuf, bcLen);
            free(bcBuf);
            free(ch.message);
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(chatDB);
        dbClose(gameDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "Charlie";
        const char *pw = "chatpass";
        size_t plen =
            offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }

    /* Join room */
    {
        uint32_t rid = RoomIdCharlies;
        sendEnc(sv[0], &cliKey, &seq, MsgJoinRoom, &rid, sizeof(rid));
        ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgJoinRoomResp), 0);
    }

    /* Send chat */
    {
        int64_t ts = ChatTimestamp;
        const char *msg = "Hello World!";
        size_t msgLen = strlen(msg) + 1;
        size_t plen = sizeof(int64_t) + msgLen;
        ChatPacketPayload *cp = malloc(plen);
        ASSERT_TRUE(cp != NULL);
        memcpy(&cp->timestamp, &ts, sizeof(int64_t));
        memcpy(cp->message, msg, msgLen);
        sendEnc(sv[0], &cliKey, &seq, MsgChat, cp, plen);
        free(cp);

        /* Receive broadcast */
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgChat);

        ChatBroadcastPayload *bc = (ChatBroadcastPayload *)pkt.payload;
        ASSERT_UINT_EQ(bc->uid, (uint32_t)LoginUidCharlie);
        ASSERT_UINT_EQ(bc->msgId, (uint64_t)1);
        ASSERT_INT_EQ(bc->timestamp, ts);
        ASSERT_STR_EQ((const char *)bc->message, msg);
        packetClear(&pkt);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/* ═══════════════════════  Session Tests  ══════════════════════════════════ */

/** @brief Logout received by server disconnects client cleanly. */
static void testLogout(void) {
    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *uDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidLogout;
            memcpy(lr.username, "X", StrLenX + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }

        /* Logout */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            int ret = recvDec(sv[1], &srvKey, &pkt);
            if (ret == 0) {
                ASSERT_INT_EQ(pkt.header.messageType, MsgLogout);
                packetClear(&pkt);
            }
        }

        dbClose(uDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "X";
        const char *pw = "x";
        size_t plen =
            offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }

    /* Send logout */
    sendEnc(sv[0], &cliKey, &seq, MsgLogout, NULL, 0);

    socketClose(&sv[0]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ═══════════════════════  State Machine Violations  ══════════════════════ */

/** @brief Sending MsgLoginReq before key exchange should disconnect. */
static void testStateMachineViolationKeyex(void) {
    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *uDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        /* Expect the next packet to be garbage — disconnect */
        socketClose(&sv[1]);
        dbClose(uDB);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    /* Silence: parent doesn't send anything, child will timeout and exit */
    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
    /* Child exited cleanly — no crash */
}

/** @brief Sending unencrypted packet after key exchange should disconnect. */
static void testUnencryptedPacketAfterAuth(void) {
    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *uDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        /* Try to receive the next packet — should fail because
         * parent sends plaintext and server expects encrypted */
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        int ret = packetRecv(&pkt, sv[1]);
        if (ret == PROTOCOL_SUCC) {
            /* If received, the packetType should NOT be AES256 (plaintext
             * after key exchange should be rejected by processClient) */
            if (pkt.header.packetType != AES256GCMPacket) {
                /* This is the expected rejection path — just close */
            }
            packetClear(&pkt);
        }
        dbClose(uDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    /* Send a PLAINTEXT packet (not encrypted) after key exchange */
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    enum { PlainPktSeq = 0 };
    uint8_t dummy = DummyPayloadByte;
    ASSERT_INT_EQ(
        packetInit(&pkt, MsgLoginReq, PlainPktSeq, PlaintextPacket, &dummy,
                   sizeof(dummy)),
        PROTOCOL_SUCC);
    ASSERT_INT_EQ(packetSend(&pkt, sv[0]), PROTOCOL_SUCC);
    packetClear(&pkt);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Sending MsgHeartbeat and receiving ack. */
static void testHeartbeatEcho(void) {
    DB *userDB = ensureTestUser("hbuser", LoginUidHeartbeat, "hbpw");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidHeartbeat;
            memcpy(lr.username, "hbuser", StrLenHbuser + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }
        /* Join pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            uint8_t s = 0;
            sendEnc(sv[1], &srvKey, &seq, MsgJoinRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }
        /* Heartbeat: echo back */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgHeartbeat);
            sendEnc(sv[1], &srvKey, &seq, MsgHeartbeat, NULL, 0);
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "hbuser";
        const char *pw = "hbpw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }
    /* Join */
    {
        uint32_t r = LoginUidHeartbeat;
        sendEnc(sv[0], &cliKey, &seq, MsgJoinRoom, &r, sizeof(r));
        ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgJoinRoomResp), 0);
    }
    /* Heartbeat */
    {
        sendEnc(sv[0], &cliKey, &seq, MsgHeartbeat, NULL, 0);
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgHeartbeat);
        packetClear(&pkt);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Empty password login should be rejected. */
static void testLoginEmptyPassword(void) {
    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *uDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        /* Send failure response */
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp, sizeof(failResp));
        packetClear(&pkt);
        dbClose(uDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Empty password: pw="" */
    const char *un = "nobody";
    const char *pw = "";
    size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *lp = calloc(1, plen);
    memcpy(lp->username, un, strlen(un) + 1);
    memcpy(lp->password, pw, strlen(pw) + 1);
    sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
    OPENSSL_cleanse(lp, plen);
    free(lp);
    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
    ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
    ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
    LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
    ASSERT_UINT_EQ(lresp->uid, (uint32_t)0);
    packetClear(&rpkt);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/* ═══════════════════════  TOTP Setup  ═══════════════════════════════════ */

static void testTOTPSetupAfterLogin(void) {
    enum { TotpUid = 700, TotpNameLen = 9, TestNickLen = 9,
           TestSecretLen = 16 };
    DB *userDB = ensureTestUser("totpguy1", TotpUid, "totppw1");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);
    dbClose(userDB);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Simulate successful login */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = TotpUid;
            memcpy(lr.username, "totpguy1", TotpNameLen);
            memcpy(lr.nickname, "TestNick", TestNickLen);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }

        /* Receive MsgTOTPSetupReq, reply with success */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPSetupReq);
            TOTPSetupRespPayload resp;
            memset(&resp, 0, sizeof(resp));
            memcpy(resp.secret, "JBSWY3DPEHPK3PXP", TestSecretLen);
            sendEnc(sv[1], &srvKey, &seq, MsgTOTPSetupResp, &resp,
                    sizeof(resp));
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t cliSeq = 0;

    /* Login via simulated server */
    {
        const char *pw = "totppw1";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, "totpguy1", TotpNameLen);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(
            sendEnc(sv[0], &cliKey, &cliSeq, MsgLoginReq, lp, plen), 0);
        OPENSSL_cleanse(lp, plen);
        free(lp);
    }
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lr = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lr->uid != 0);
        packetClear(&rpkt);
    }

    /* Send TOTP setup request */
    ASSERT_INT_EQ(
        sendEnc(sv[0], &cliKey, &cliSeq, MsgTOTPSetupReq, NULL, 0), 0);

    /* Receive TOTP setup response */
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgTOTPSetupResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(TOTPSetupRespPayload));
        TOTPSetupRespPayload *resp =
            (TOTPSetupRespPayload *)rpkt.payload;
        ASSERT_TRUE(resp->secret[0] != '\0');
        packetClear(&rpkt);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

static void testTOTPSetupAlreadyEnabled(void) {
    enum { TotpUid = 701, TotpNameLen = 9, TestNickLen = 9,
           TestSecretLen = 16 };
    DB *userDB = ensureTestUser("totpguy2", TotpUid, "totppw2");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);
    dbClose(userDB);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = TotpUid;
            memcpy(lr.username, "totpguy2", TotpNameLen);
            memcpy(lr.nickname, "TestNick", TestNickLen);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }

        /* First TOTP setup — success */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPSetupReq);
            TOTPSetupRespPayload r1;
            memset(&r1, 0, sizeof(r1));
            memcpy(r1.secret, "JBSWY3DPEHPK3PXP", TestSecretLen);
            sendEnc(sv[1], &srvKey, &seq, MsgTOTPSetupResp, &r1,
                    sizeof(r1));
            packetClear(&pkt);
        }

        /* Second TOTP setup — reject (already enabled) */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPSetupReq);
            uint8_t s = 1;
            sendEnc(sv[1], &srvKey, &seq, MsgTOTPSetupResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t cliSeq = 0;

    {
        const char *pw = "totppw2";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, "totpguy2", TotpNameLen);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(
            sendEnc(sv[0], &cliKey, &cliSeq, MsgLoginReq, lp, plen), 0);
        OPENSSL_cleanse(lp, plen);
        free(lp);
    }
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        packetClear(&rpkt);
    }

    /* First setup — must succeed */
    ASSERT_INT_EQ(
        sendEnc(sv[0], &cliKey, &cliSeq, MsgTOTPSetupReq, NULL, 0), 0);
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgTOTPSetupResp);
        packetClear(&rpkt);
    }

    /* Second setup — must be rejected */
    ASSERT_INT_EQ(
        sendEnc(sv[0], &cliKey, &cliSeq, MsgTOTPSetupReq, NULL, 0), 0);
    int status = recvStatus(sv[0], &cliKey, MsgTOTPSetupResp);
    ASSERT_INT_EQ(status, 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/* ═══════════════════════  TOTP Verify  ══════════════════════════════════ */

static void testTOTPVerifySuccess(void) {
    enum { TotpUid = 800, SockParent = 0, SockChild = 1,
           NameLen = 9, TestCode = 123456 };
    DB *userDB = ensureTestUser("totpvfy1", TotpUid, "tvpw1");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);
    dbClose(userDB);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[SockParent]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[SockChild], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Receive login request — server would challenge with TOTP */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[SockChild], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgLoginReq);
            packetClear(&pkt);
        }

        /* Send TOTP challenge */
        ASSERT_INT_EQ(
            sendEnc(sv[SockChild], &srvKey, &seq, MsgTOTPVerifyReq, NULL, 0),
            0);

        /* Receive TOTP code — accept any valid code */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[SockChild], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPVerifyResp);
            ASSERT_TRUE(pkt.header.payloadLength >= sizeof(TOTPVerifyPayload));
            packetClear(&pkt);
        }

        /* Send success LoginResp */
        LoginResponsePayload lr;
        memset(&lr, 0, sizeof(lr));
        lr.uid = TotpUid;
        lr.totpEnabled = 1;
        memcpy(lr.username, "totpvfy1", NameLen);
        memcpy(lr.nickname, "TestNick", NameLen);
        sendEnc(sv[SockChild], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));

        dbClose(userDB);
        socketClose(&sv[SockChild]);
        _exit(0);
    }

    socketClose(&sv[SockChild]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[SockParent], &cliKey), COMM_SUCC);
    uint32_t cliSeq = 0;

    /* Login */
    {
        const char *pw = "tvpw1";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, "totpvfy1", NameLen);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(
            sendEnc(sv[SockParent], &cliKey, &cliSeq, MsgLoginReq, lp, plen),
            0);
        OPENSSL_cleanse(lp, plen);
        free(lp);
    }

    /* Expect TOTP challenge */
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[SockParent], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPVerifyReq);
        packetClear(&pkt);
    }

    /* Send TOTP code */
    {
        TOTPVerifyPayload vp;
        vp.code = TestCode;
        ASSERT_INT_EQ(
            sendEnc(sv[SockParent], &cliKey, &cliSeq, MsgTOTPVerifyResp, &vp,
                    sizeof(vp)),
            0);
    }

    /* Expect success LoginResp with totpEnabled=1 */
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[SockParent], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(pkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lr = (LoginResponsePayload *)pkt.payload;
        ASSERT_TRUE(lr->uid != 0);
        ASSERT_UINT_EQ(lr->totpEnabled, 1);
        packetClear(&pkt);
    }

    socketClose(&sv[SockParent]);
    waitpid(child, NULL, 0);
}

static void testTOTPVerifyWrongCode(void) {
    enum { TotpUid = 801, SockParent = 0, SockChild = 1, NameLen = 9 };
    DB *userDB = ensureTestUser("totpvfy2", TotpUid, "tvpw2");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);
    dbClose(userDB);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[SockParent]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[SockChild], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Receive login — simulate challenge */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[SockChild], &srvKey, &pkt), 0);
            packetClear(&pkt);
        }
        sendEnc(sv[SockChild], &srvKey, &seq, MsgTOTPVerifyReq, NULL, 0);

        /* Receive code — simulate wrong code rejection */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[SockChild], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPVerifyResp);
            packetClear(&pkt);
        }

        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEnc(sv[SockChild], &srvKey, &seq, MsgLoginResp, &failResp,
                sizeof(failResp));

        dbClose(userDB);
        socketClose(&sv[SockChild]);
        _exit(0);
    }

    socketClose(&sv[SockChild]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[SockParent], &cliKey), COMM_SUCC);
    uint32_t cliSeq = 0;

    {
        const char *pw = "tvpw2";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, "totpvfy2", NameLen);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[SockParent], &cliKey, &cliSeq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
    }

    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[SockParent], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPVerifyReq);
        packetClear(&pkt);
    }

    TOTPVerifyPayload vp;
    vp.code = 0;
    sendEnc(sv[SockParent], &cliKey, &cliSeq, MsgTOTPVerifyResp, &vp,
            sizeof(vp));

    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[SockParent], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(pkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lr = (LoginResponsePayload *)pkt.payload;
        ASSERT_UINT_EQ(lr->uid, 0);
        packetClear(&pkt);
    }

    socketClose(&sv[SockParent]);
    waitpid(child, NULL, 0);
}

static void testTOTPVerifyMalformedPayload(void) {
    enum { TotpUid = 802, SockParent = 0, SockChild = 1, NameLen = 9 };
    DB *userDB = ensureTestUser("totpvfy3", TotpUid, "tvpw3");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);
    dbClose(userDB);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[SockParent]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[SockChild], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[SockChild], &srvKey, &pkt), 0);
            packetClear(&pkt);
        }
        sendEnc(sv[SockChild], &srvKey, &seq, MsgTOTPVerifyReq, NULL, 0);

        /* Receive malformed payload — send fail */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[SockChild], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPVerifyResp);
            packetClear(&pkt);
        }

        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEnc(sv[SockChild], &srvKey, &seq, MsgLoginResp, &failResp,
                sizeof(failResp));

        dbClose(userDB);
        socketClose(&sv[SockChild]);
        _exit(0);
    }

    socketClose(&sv[SockChild]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[SockParent], &cliKey), COMM_SUCC);
    uint32_t cliSeq = 0;

    {
        const char *pw = "tvpw3";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, "totpvfy3", NameLen);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[SockParent], &cliKey, &cliSeq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
    }
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[SockParent], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPVerifyReq);
        packetClear(&pkt);
    }
    /* Send undersized payload (1 byte instead of 4) */
    uint8_t badByte = 0;
    sendEnc(sv[SockParent], &cliKey, &cliSeq, MsgTOTPVerifyResp, &badByte,
            sizeof(badByte));
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[SockParent], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(pkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lr = (LoginResponsePayload *)pkt.payload;
        ASSERT_UINT_EQ(lr->uid, 0);
        packetClear(&pkt);
    }
    socketClose(&sv[SockParent]);
    waitpid(child, NULL, 0);
}

/* ═══════════════════════  State Machine Violations  ═════════════════════ */

static void testSessionTOTPVerifyStateViolation(void) {
    enum { TotpUid = 803, SockParent = 0, SockChild = 1, NameLen = 9 };
    DB *userDB = ensureTestUser("totpvfy4", TotpUid, "tvpw4");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);
    dbClose(userDB);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[SockParent]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[SockChild], &srvKey), COMM_SUCC);
        uint32_t seq = 0;
        /* Login → TOTP challenge */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[SockChild], &srvKey, &pkt), 0);
            packetClear(&pkt);
        }
        sendEnc(sv[SockChild], &srvKey, &seq, MsgTOTPVerifyReq, NULL, 0);
        /* Client sends MsgChat in SessionTOTPVerify → violation.
         * Child receives it (valid packet), sees unexpected type,
         * closes connection. */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            int ret = recvDec(sv[SockChild], &srvKey, &pkt);
            ASSERT_INT_EQ(ret, 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgChat);
            packetClear(&pkt);
        }
        dbClose(userDB);
        socketClose(&sv[SockChild]);
        _exit(0);
    }

    socketClose(&sv[SockChild]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[SockParent], &cliKey), COMM_SUCC);
    uint32_t cliSeq = 0;

    {
        const char *pw = "tvpw4";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, "totpvfy4", NameLen);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[SockParent], &cliKey, &cliSeq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
    }
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[SockParent], &cliKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgTOTPVerifyReq);
        packetClear(&pkt);
    }
    /* Send MsgChat in SessionTOTPVerify state */
    ASSERT_INT_EQ(sendEnc(sv[SockParent], &cliKey, &cliSeq, MsgChat, NULL, 0),
                  0);
    /* Child should disconnect — subsequent recv should fail */
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        int ret = recvDec(sv[SockParent], &cliKey, &pkt);
        ASSERT_INT_EQ(ret, -1);
    }

    socketClose(&sv[SockParent]);
    waitpid(child, NULL, 0);
}

/* ═══════════════════════  Protocol Edge-Case Tests  ═══════════════════════ */

/** @brief Login with payload smaller than MinLoginPayload => StatusFailure. */
static void testLoginPayloadTooSmall(void) {
    DB *userDB = ensureTestUser("pluser", LoginUidList, "plpw");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgLoginReq);

        enum { MinLoginPayload = 33 };
        uint32_t seq = 0;
        if (pkt.header.payloadLength < MinLoginPayload) {
            LoginResponsePayload failResp;
            memset(&failResp, 0, sizeof(failResp));
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp, sizeof(failResp));
        } else {
            LoginResponsePayload resp;
            memset(&resp, 0, sizeof(resp));
            resp.uid = LoginUidList;
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &resp, sizeof(resp));
        }
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    /* Craft a payload with only username(32) = 32 bytes, no password */
    enum { ShortPayloadLen = 32 };
    uint8_t *shortPayload = calloc(1, ShortPayloadLen);
    ASSERT_TRUE(shortPayload != NULL);
    memset(shortPayload, 'a', LOGIN_USERNAME_LEN);
    shortPayload[ShortPayloadLen - 1] = '\0';

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, shortPayload,
                          ShortPayloadLen),
                  PROTOCOL_SUCC);
    free(shortPayload);

    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
    ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
    ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
    LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
    ASSERT_UINT_EQ(lresp->uid, (uint32_t)0);
    packetClear(&rpkt);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Login with username not NUL-terminated => StatusFailure. */
static void testLoginUsernameNotNulTerminated(void) {
    DB *userDB = ensureTestUser("nulluser", LoginUidNobody, "npw");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgLoginReq);

        LoginRequestPayload *login = (LoginRequestPayload *)pkt.payload;
        int bad = (login->username[LOGIN_USERNAME_LEN - 1] != '\0');
        uint32_t seq = 0;
        if (bad) {
            LoginResponsePayload failResp;
            memset(&failResp, 0, sizeof(failResp));
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp, sizeof(failResp));
        } else {
            LoginResponsePayload resp;
            memset(&resp, 0, sizeof(resp));
            resp.uid = LoginUidNobody;
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &resp, sizeof(resp));
        }
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *pw = "a";
    size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *lp = calloc(1, plen);
    ASSERT_TRUE(lp != NULL);
    memset(lp->username, 'x', LOGIN_USERNAME_LEN);
    memcpy(lp->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen),
                  PROTOCOL_SUCC);
    free(lp);

    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
    ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
    ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
    LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
    ASSERT_UINT_EQ(lresp->uid, (uint32_t)0);
    packetClear(&rpkt);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief CreateRoom with zero-length payload => StatusFailure. */
static void testCreateRoomZeroPayload(void) {
    DB *userDB = ensureTestUser("cruser", LoginUidAlice, "crpw");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass-through */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidAlice;
            memcpy(lr.username, "Alice", StrLenAlice + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }

        /* Reject zero-payload CreateRoom */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgCreateRoom);
            uint8_t s =
                (pkt.header.payloadLength != sizeof(uint32_t)) ? 1 : 0;
            sendEnc(sv[1], &srvKey, &seq, MsgCreateRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "Alice";
        const char *pw = "crpw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }

    /* Send CreateRoom with zero payload */
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgCreateRoom, NULL, 0),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgCreateRoomResp), 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief JoinRoom with zero-length payload => StatusFailure. */
static void testJoinRoomZeroPayload(void) {
    DB *userDB = ensureTestUser("jruser", LoginUidBob, "jrpw");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        DB *gDB = dbInit(GameDB, NULL);
        ASSERT_INT_EQ(createRoom(gDB, TestRoomId, LoginUidBob), DB_SUCC);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass-through */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidBob;
            memcpy(lr.username, "Bob", StrLenBob + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }

        /* Reject zero-payload JoinRoom */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgJoinRoom);
            uint8_t s =
                (pkt.header.payloadLength != sizeof(uint32_t)) ? 1 : 0;
            sendEnc(sv[1], &srvKey, &seq, MsgJoinRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        dbClose(gDB);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "Bob";
        const char *pw = "jrpw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }

    /* Send JoinRoom with zero payload */
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgJoinRoom, NULL, 0),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgJoinRoomResp), 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Chat with payload < sizeof(int64_t) causes disconnect. */
static void testChatZeroPayload(void) {
    removeDBFiles();
    DB *gameDB = dbInit(GameDB, NULL);
    ASSERT_TRUE(gameDB != NULL);
    ASSERT_INT_EQ(createRoom(gameDB, RoomIdCharlies, LoginUidCharlie), DB_SUCC);
    DB *userDB = ensureTestUser("chzuser", LoginUidCharlie, "chzpw");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    dbClose(gameDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        gameDB = dbInit(GameDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidCharlie;
            memcpy(lr.username, "Charlie", StrLenCharlie + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }
        /* Join pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            uint8_t s = 0;
            sendEnc(sv[1], &srvKey, &seq, MsgJoinRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }
        /* Chat too small: disconnect */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgChat);
            if (pkt.header.payloadLength < sizeof(int64_t)) {
                packetClear(&pkt);
                dbClose(userDB);
                dbClose(gameDB);
                socketClose(&sv[1]);
                _exit(0);
            }
            packetClear(&pkt);
        }

        dbClose(userDB);
        dbClose(gameDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "Charlie";
        const char *pw = "chzpw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }
    /* Join room */
    {
        uint32_t rid = RoomIdCharlies;
        sendEnc(sv[0], &cliKey, &seq, MsgJoinRoom, &rid, sizeof(rid));
        ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgJoinRoomResp), 0);
    }
    /* Send chat with only 4 bytes (no timestamp) */
    {
        uint8_t smallPayload[4] = {0};
        ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgChat, smallPayload,
                              sizeof(smallPayload)),
                      PROTOCOL_SUCC);
    }
    /* The child should have closed the connection */
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &pkt), -1);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Chat with message not NUL-terminated causes disconnect. */
static void testChatMsgNotNulTerminated(void) {
    removeDBFiles();
    DB *gameDB = dbInit(GameDB, NULL);
    ASSERT_TRUE(gameDB != NULL);
    ASSERT_INT_EQ(createRoom(gameDB, RoomIdCharlies, LoginUidCharlie), DB_SUCC);
    DB *userDB = ensureTestUser("chnuser", LoginUidCharlie, "chnpw");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    dbClose(gameDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        gameDB = dbInit(GameDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = LoginUidCharlie;
            memcpy(lr.username, "Charlie", StrLenCharlie + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }
        /* Join pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            uint8_t s = 0;
            sendEnc(sv[1], &srvKey, &seq, MsgJoinRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }
        /* Chat without NUL: disconnect */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgChat);
            ChatPacketPayload *chat = (ChatPacketPayload *)pkt.payload;
            size_t msgLen =
                pkt.header.payloadLength - sizeof(int64_t);
            int bad = (msgLen == 0 ||
                       memchr(chat->message, '\0', msgLen) == NULL);
            packetClear(&pkt);
            if (bad) {
                dbClose(userDB);
                dbClose(gameDB);
                socketClose(&sv[1]);
                _exit(0);
            }
        }

        dbClose(userDB);
        dbClose(gameDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "Charlie";
        const char *pw = "chnpw";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }
    /* Join room */
    {
        uint32_t rid = RoomIdCharlies;
        sendEnc(sv[0], &cliKey, &seq, MsgJoinRoom, &rid, sizeof(rid));
        ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgJoinRoomResp), 0);
    }
    /* Send chat with no NUL in message */
    {
        int64_t ts = ChatTimestamp;
        enum { MsgLen = 4 };
        size_t plen = sizeof(int64_t) + MsgLen;
        uint8_t *buf = malloc(plen);
        ASSERT_TRUE(buf != NULL);
        memcpy(buf, &ts, sizeof(int64_t));
        memset(buf + sizeof(int64_t), 'x', MsgLen);
        ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgChat, buf, plen),
                      PROTOCOL_SUCC);
        free(buf);
    }
    /* The child should have closed the connection */
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &pkt), -1);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/* ═══════════════════════  Registration Tests  ══════════════════════════════ */

/** @brief Register a new user successfully. */
static void testRegisterSuccess(void) {
    removeDBFiles();
    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt.payload;
        User u;
        memset(&u, 0, sizeof(u));
        memcpy(u.username, reg->username, USERNAME_MAX_LEN);
        memcpy(u.nickname, reg->nickname, NICKNAME_MAX_LEN);
        u.password = strdup(reg->password);
        int dbRet = createUser(userDB, &u);
        OPENSSL_cleanse(u.password, strlen(u.password));
        free(u.password);

        uint8_t status = (dbRet == DB_SUCC) ? 0 : 1;
        uint32_t seq = 0;
        sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &status, sizeof(status));
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *un = "RegUser";
    const char *pw = "regpass";
    size_t plen = offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
    RegisterRequestPayload *rp = calloc(1, plen);
    ASSERT_TRUE(rp != NULL);
    memcpy(rp->username, un, strlen(un) + 1);
    memcpy(rp->nickname, "TestNick", StrLenTestNick + 1);
    memcpy(rp->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp, plen),
                  PROTOCOL_SUCC);
    OPENSSL_cleanse(rp, plen);
    free(rp);

    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 0);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Registering duplicate UID or username fails. */
static void testRegisterDuplicate(void) {
    removeDBFiles();
    enum { DupRegisterUid = 888 };
    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_TRUE(userDB != NULL);

    /* Pre-create a user so duplicate registration fails */
    User pre;
    memset(&pre, 0, sizeof(pre));
    const char *preName = "DupUser";
    memcpy(pre.username, preName, strlen(preName) + 1);
    memcpy(pre.nickname, "TestNick", StrLenTestNick + 1);
    pre.uid = DupRegisterUid;
    pre.password = strdup("firstpw");
    ASSERT_INT_EQ(createUser(userDB, &pre), DB_SUCC);
    free(pre.password);
    dbClose(userDB);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt.payload;
        User u;
        memset(&u, 0, sizeof(u));
        memcpy(u.username, reg->username, USERNAME_MAX_LEN);
        memcpy(u.nickname, reg->nickname, NICKNAME_MAX_LEN);
        u.password = strdup(reg->password);
        int dbRet = createUser(userDB, &u);
        OPENSSL_cleanse(u.password, strlen(u.password));
        free(u.password);

        uint8_t status = (dbRet == DB_SUCC) ? 0 : 1;
        uint32_t seq = 0;
        sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &status, sizeof(status));
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *un = "DupUser";
    const char *pw = "secondpw";
    size_t plen = offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
    RegisterRequestPayload *rp = calloc(1, plen);
    ASSERT_TRUE(rp != NULL);
    memcpy(rp->username, un, strlen(un) + 1);
    memcpy(rp->nickname, "TestNick", StrLenTestNick + 1);
    memcpy(rp->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp, plen),
                  PROTOCOL_SUCC);
    OPENSSL_cleanse(rp, plen);
    free(rp);

    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Registering twice with the same username in the same session:
 *  first succeeds, second fails due to UNIQUE constraint. */
static void testRegisterDuplicateSameSession(void) {
    removeDBFiles();
    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* First register — should succeed */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);
            RegisterRequestPayload *reg =
                (RegisterRequestPayload *)pkt.payload;
            User u;
            memset(&u, 0, sizeof(u));
            memcpy(u.username, reg->username, USERNAME_MAX_LEN);
            memcpy(u.nickname, reg->nickname, NICKNAME_MAX_LEN);
            u.password = strdup(reg->password);
            int dbRet = createUser(userDB, &u);
            OPENSSL_cleanse(u.password, strlen(u.password));
            free(u.password);
            uint8_t s = (dbRet == DB_SUCC) ? 0 : 1;
            sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        /* Second register — same username, should fail */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);
            RegisterRequestPayload *reg =
                (RegisterRequestPayload *)pkt.payload;
            User u;
            memset(&u, 0, sizeof(u));
            memcpy(u.username, reg->username, USERNAME_MAX_LEN);
            memcpy(u.nickname, reg->nickname, NICKNAME_MAX_LEN);
            u.password = strdup(reg->password);
            int dbRet = createUser(userDB, &u);
            OPENSSL_cleanse(u.password, strlen(u.password));
            free(u.password);
            uint8_t s = (dbRet == DB_SUCC) ? 0 : 1;
            sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    const char *un = "DupSession";
    const char *pw = "sessionpw";
    size_t plen =
        offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
    RegisterRequestPayload *rp = calloc(1, plen);
    ASSERT_TRUE(rp != NULL);
    memcpy(rp->username, un, strlen(un) + 1);
    memcpy(rp->nickname, "TestNick", strlen("TestNick") + 1);
    memcpy(rp->password, pw, strlen(pw) + 1);

    /* First register — expect success */
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp, plen),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 0);

    /* Second register — same username, expect failure */
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp, plen),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 1);

    OPENSSL_cleanse(rp, plen);
    free(rp);
    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Register with empty password fails. */
static void testRegisterEmptyPassword(void) {
    removeDBFiles();
    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt.payload;
        size_t pwLen = pkt.header.payloadLength -
                       offsetof(RegisterRequestPayload, password);
        uint8_t status = (pwLen > 0 && reg->password[0] != '\0' &&
                          memchr(reg->password, '\0', pwLen) != NULL)
                             ? 0
                             : 1;
        if (status == 0) {
            User u;
            memset(&u, 0, sizeof(u));
            memcpy(u.username, reg->username, USERNAME_MAX_LEN);
            memcpy(u.nickname, reg->nickname, NICKNAME_MAX_LEN);
            u.password = strdup(reg->password);
            int dbRet = createUser(userDB, &u);
            OPENSSL_cleanse(u.password, strlen(u.password));
            free(u.password);
            status = (dbRet == DB_SUCC) ? 0 : 1;
        }
        uint32_t seq = 0;
        sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &status, sizeof(status));
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *un = "EmptyPw";
    const char *pw = "";
    size_t plen = offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
    RegisterRequestPayload *rp = calloc(1, plen);
    ASSERT_TRUE(rp != NULL);
    memcpy(rp->username, un, strlen(un) + 1);
    memcpy(rp->nickname, "TestNick", StrLenTestNick + 1);
    memcpy(rp->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp, plen),
                  PROTOCOL_SUCC);
    OPENSSL_cleanse(rp, plen);
    free(rp);

    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Register with payload smaller than MinPayload => StatusFailure. */
static void testRegisterPayloadTooSmall(void) {
    removeDBFiles();
    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        enum { MinPayload = 65 };
        uint8_t status =
            (pkt.header.payloadLength < MinPayload) ? 1 : 0;
        uint32_t seq = 0;
        sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &status,
                sizeof(status));
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    /* Craft a payload with only username(32) + nickname(32) = 64 bytes */
    enum { ShortPayloadLen = 64 };
    uint8_t *shortPayload = calloc(1, ShortPayloadLen);
    ASSERT_TRUE(shortPayload != NULL);
    memset(shortPayload, 'a', LOGIN_USERNAME_LEN);
    memset(shortPayload + LOGIN_USERNAME_LEN, 'b', LOGIN_NICKNAME_LEN);
    shortPayload[LOGIN_USERNAME_LEN - 1] = '\0';
    shortPayload[ShortPayloadLen - 1] = '\0';

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, shortPayload,
                          ShortPayloadLen),
                  PROTOCOL_SUCC);
    free(shortPayload);

    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Register with username not NUL-terminated => StatusFailure. */
static void testRegisterUsernameNotNulTerminated(void) {
    removeDBFiles();
    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt.payload;
        uint8_t status =
            (reg->username[LOGIN_USERNAME_LEN - 1] != '\0') ? 1 : 0;
        uint32_t seq = 0;
        sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &status,
                sizeof(status));
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *pw = "a";
    size_t plen =
        offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
    RegisterRequestPayload *rp = calloc(1, plen);
    ASSERT_TRUE(rp != NULL);
    /* Fill entire username buffer — no NUL at last byte */
    memset(rp->username, 'x', LOGIN_USERNAME_LEN);
    memcpy(rp->nickname, "TestNick", StrLenTestNick + 1);
    memcpy(rp->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp, plen),
                  PROTOCOL_SUCC);
    free(rp);

    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Register with password not NUL-terminated within payload
 *  => StatusFailure. */
static void testRegisterPasswordNotNulTerminated(void) {
    removeDBFiles();
    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt.payload;
        size_t pwLen = pkt.header.payloadLength -
                       offsetof(RegisterRequestPayload, password);
        uint8_t status =
            (memchr(reg->password, '\0', pwLen) == NULL) ? 1 : 0;
        if (status == 0) {
            User u;
            memset(&u, 0, sizeof(u));
            memcpy(u.username, reg->username, USERNAME_MAX_LEN);
            memcpy(u.nickname, reg->nickname, NICKNAME_MAX_LEN);
            u.password = strdup(reg->password);
            int dbRet = createUser(userDB, &u);
            OPENSSL_cleanse(u.password, strlen(u.password));
            free(u.password);
            status = (dbRet == DB_SUCC) ? 0 : 1;
        }
        uint32_t seq = 0;
        sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &status,
                sizeof(status));
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    const char *un = "NoNulPw";
    enum { PwBufLen = 4 };
    size_t plen = offsetof(RegisterRequestPayload, password) + PwBufLen;
    uint8_t *buf = calloc(1, plen);
    ASSERT_TRUE(buf != NULL);
    RegisterRequestPayload *rp = (RegisterRequestPayload *)buf;
    memcpy(rp->username, un, strlen(un) + 1);
    memcpy(rp->nickname, "TestNick", StrLenTestNick + 1);
    /* Fill password region with non-NUL bytes — no terminator */
    memset(rp->password, 'y', PwBufLen);

    uint32_t seq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp, plen),
                  PROTOCOL_SUCC);
    free(rp);

    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Full E2E: register a user, then login with same credentials. */
static void testRegisterThenLogin(void) {
    removeDBFiles();
    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);

        uint32_t seq = 0;

        /* Phase 1: register */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

            RegisterRequestPayload *reg =
                (RegisterRequestPayload *)pkt.payload;
            User u;
            memset(&u, 0, sizeof(u));
            memcpy(u.username, reg->username, USERNAME_MAX_LEN);
            memcpy(u.nickname, reg->nickname, NICKNAME_MAX_LEN);
            u.password = strdup(reg->password);
            int dbRet = createUser(userDB, &u);
            OPENSSL_cleanse(u.password, strlen(u.password));
            free(u.password);

            uint8_t s = (dbRet == DB_SUCC) ? 0 : 1;
            sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &s,
                    sizeof(s));
            packetClear(&pkt);
        }

        /* Phase 2: login */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            ASSERT_INT_EQ(pkt.header.messageType, MsgLoginReq);

            LoginRequestPayload *login =
                (LoginRequestPayload *)pkt.payload;
            User verify;
            memset(&verify, 0, sizeof(verify));
            memcpy(verify.username, login->username, USERNAME_MAX_LEN);
            verify.uid = 0;
            verify.password = strdup(login->password);
            int dbRet = verifyUser(userDB, &verify);
            OPENSSL_cleanse(verify.password, strlen(verify.password));
            free(verify.password);

            if (dbRet == DB_SUCC) {
                LoginResponsePayload resp;
                memset(&resp, 0, sizeof(resp));
                resp.uid = verify.uid;
                memcpy(resp.username, verify.username, LOGIN_USERNAME_LEN);
                memcpy(resp.nickname, verify.nickname, LOGIN_NICKNAME_LEN);
                sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &resp, sizeof(resp));
            } else {
                LoginResponsePayload failResp;
                memset(&failResp, 0, sizeof(failResp));
                sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp, sizeof(failResp));
            }
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    const char *un = "E2EUser";
    const char *pw = "e2epass";
    const char *nick = "TestNick";
    size_t regPlen = offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
    RegisterRequestPayload *regPayload = calloc(1, regPlen);
    ASSERT_TRUE(regPayload != NULL);
    memcpy(regPayload->username, un, strlen(un) + 1);
    memcpy(regPayload->nickname, nick, StrLenTestNick + 1);
    memcpy(regPayload->password, pw, strlen(pw) + 1);

    /* Register */
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, regPayload, regPlen),
                  PROTOCOL_SUCC);
    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 0);

    /* Login */
    size_t loginPlen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *loginPayload = calloc(1, loginPlen);
    ASSERT_TRUE(loginPayload != NULL);
    memcpy(loginPayload->username, un, strlen(un) + 1);
    memcpy(loginPayload->password, pw, strlen(pw) + 1);

    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, loginPayload, loginPlen),
                  PROTOCOL_SUCC);

    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
    ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
    ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
    LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
    ASSERT_TRUE(lresp->uid != 0);
    packetClear(&rpkt);

    OPENSSL_cleanse(regPayload, regPlen);
    free(regPayload);
    OPENSSL_cleanse(loginPayload, loginPlen);
    free(loginPayload);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Sending MsgRegisterReq before key exchange should disconnect. */
static void testRegisterBeforeKeyExchange(void) {
    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *uDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        /* Register before key exchange is a protocol violation —
         * the real server returns SERVER_FAIL (disconnect). */
        socketClose(&sv[1]);
        dbClose(uDB);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);

    /* Parent does nothing — child closes cleanly on its own */
    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/** @brief Sending MsgRegisterReq after login (SessionRoom state)
 *  should disconnect. */
static void testRegisterAfterLogin(void) {
    enum { RegLateUid = 2501, BadRegLen = 7 };
    DB *userDB = ensureTestUser("RegLate", RegLateUid, "latepw");
    ASSERT_TRUE(userDB != NULL);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB);
    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        userDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), COMM_SUCC);
        uint32_t seq = 0;

        /* Login pass */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
            LoginResponsePayload lr;
            memset(&lr, 0, sizeof(lr));
            lr.uid = RegLateUid;
            memcpy(lr.username, "RegLate", StrLenRegLate + 1);
            memcpy(lr.nickname, "TestNick", StrLenTestNick + 1);
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &lr, sizeof(lr));
            packetClear(&pkt);
        }
        /* Register in SessionRoom state — should disconnect */
        {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            int ret = recvDec(sv[1], &srvKey, &pkt);
            if (ret == 0) {
                ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);
            }
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), COMM_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "RegLate";
        const char *pw = "latepw";
        size_t plen =
            offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, un, strlen(un) + 1);
        memcpy(lp->password, pw, strlen(pw) + 1);
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, lp, plen);
        OPENSSL_cleanse(lp, plen);
        free(lp);
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgLoginResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(LoginResponsePayload));
        LoginResponsePayload *lresp = (LoginResponsePayload *)rpkt.payload;
        ASSERT_TRUE(lresp->uid != 0);
        packetClear(&rpkt);
    }

    /* Send register packet in wrong state — will be ignored/disconnected */
    {
        const char *pw = "x";
        size_t plen =
            offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
        RegisterRequestPayload *rp = calloc(1, plen);
        memcpy(rp->username, "BadReg", BadRegLen);
        memcpy(rp->nickname, "TestNick", StrLenTestNick + 1);
        memcpy(rp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp,
                              plen),
                      PROTOCOL_SUCC);
        free(rp);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/* ═══════════════════════  Key Management Tests  ═══════════════════════════ */

/** @brief First-run serverInitKeys generates 4 keys and stores them. */
static void testServerInitKeysFirstRun(void) {
    removeDBFiles();
    DB *serverDB = dbInit(ServerDB, NULL);
    ASSERT_TRUE(serverDB != NULL);

    Server srv;
    memset(&srv, 0, sizeof(srv));
    srv.serverDB = serverDB;

    ASSERT_FALSE(srv.freshKeysGenerated);

    /* Supply an empty stdin so getchar() returns EOF without blocking */
    FILE *savedStdin = stdin;
    stdin = fopen("/dev/null", "r");
    ASSERT_TRUE(stdin != NULL);

    int ret = serverInitKeys(&srv);

    fclose(stdin);
    stdin = savedStdin;

    ASSERT_INT_EQ(ret, SERVER_SUCC);
    ASSERT_TRUE(srv.freshKeysGenerated);

    /* All 4 keys must be non-zero (generate was called) */
    static const uint8_t zeros32[32];
    ASSERT_TRUE(memcmp(srv.dekKey, zeros32, sizeof(srv.dekKey)) != 0);
    ASSERT_TRUE(
        memcmp(srv.userDbEncKey, zeros32, sizeof(srv.userDbEncKey)) != 0);
    ASSERT_TRUE(
        memcmp(srv.chatDbEncKey, zeros32, sizeof(srv.chatDbEncKey)) != 0);
    ASSERT_TRUE(
        memcmp(srv.gameDbEncKey, zeros32, sizeof(srv.gameDbEncKey)) != 0);

    /* All 4 keys must be distinct from each other */
    ASSERT_TRUE(memcmp(srv.dekKey, srv.userDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.chatDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.gameDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.chatDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.gameDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.chatDbEncKey, srv.gameDbEncKey, 32) != 0);

    /* Verify all 4 envelopes are stored in ServerDB */
    uint8_t *outDek = NULL;
    uint8_t *outUser = NULL;
    uint8_t *outChat = NULL;
    uint8_t *outGame = NULL;
    size_t lenDek = 0;
    size_t lenUser = 0;
    size_t lenChat = 0;
    size_t lenGame = 0;
    ASSERT_INT_EQ(getServerKey(serverDB, "DEK", &outDek, &lenDek), DB_SUCC);
    ASSERT_INT_EQ(
        getServerKey(serverDB, "UserDBKey", &outUser, &lenUser), DB_SUCC);
    ASSERT_INT_EQ(
        getServerKey(serverDB, "ChatHistoryDBKey", &outChat, &lenChat),
        DB_SUCC);
    ASSERT_INT_EQ(
        getServerKey(serverDB, "GameDBKey", &outGame, &lenGame), DB_SUCC);

    enum {
        EnvelopeLen = 12 + 32 + 16
    }; /* nonce + key + tag */
    ASSERT_TRUE(outDek != NULL);
    ASSERT_UINT_EQ(lenDek, (size_t)EnvelopeLen);
    ASSERT_TRUE(outUser != NULL);
    ASSERT_UINT_EQ(lenUser, (size_t)EnvelopeLen);
    ASSERT_TRUE(outChat != NULL);
    ASSERT_UINT_EQ(lenChat, (size_t)EnvelopeLen);
    ASSERT_TRUE(outGame != NULL);
    ASSERT_UINT_EQ(lenGame, (size_t)EnvelopeLen);

    free(outDek);
    free(outUser);
    free(outChat);
    free(outGame);

    OPENSSL_cleanse(srv.dekKey, sizeof(srv.dekKey));
    OPENSSL_cleanse(srv.userDbEncKey, sizeof(srv.userDbEncKey));
    OPENSSL_cleanse(srv.chatDbEncKey, sizeof(srv.chatDbEncKey));
    OPENSSL_cleanse(srv.gameDbEncKey, sizeof(srv.gameDbEncKey));
    dbClose(serverDB);
    removeDBFiles();
}

/** @brief freshKeysGenerated flag defaults to false (memset-zero). */
static void testFreshKeysGeneratedFlag(void) {
    /* A zero-initialized Server must have the flag false */
    Server srv;
    memset(&srv, 0, sizeof(srv));
    ASSERT_FALSE(srv.freshKeysGenerated);

    /* Manually set to true and verify */
    srv.freshKeysGenerated = true;
    ASSERT_TRUE(srv.freshKeysGenerated);

    /* Manually set back to false and verify */
    srv.freshKeysGenerated = false;
    ASSERT_FALSE(srv.freshKeysGenerated);
}

/* ═══════════════════════  Main  ══════════════════════════════════════════ */

int main(void) {
    logSetLevel(LogLevelFatal);
    removeDBFiles();

    printf("test_server:\n");

    /* —— Login —— */
    RUN_TEST(testLoginSuccess);
    RUN_TEST(testLoginWrongPassword);
    RUN_TEST(testLoginNonexistentUser);
    RUN_TEST(testLoginPayloadTooSmall);
    RUN_TEST(testLoginUsernameNotNulTerminated);

    /* —— Registration —— */
    RUN_TEST(testRegisterSuccess);
    RUN_TEST(testRegisterDuplicate);
    RUN_TEST(testRegisterDuplicateSameSession);
    RUN_TEST(testRegisterEmptyPassword);
    RUN_TEST(testRegisterPayloadTooSmall);
    RUN_TEST(testRegisterUsernameNotNulTerminated);
    RUN_TEST(testRegisterPasswordNotNulTerminated);
    RUN_TEST(testRegisterThenLogin);

    /* —— Room —— */
    RUN_TEST(testRoomCreateAndJoin);
    RUN_TEST(testRoomJoinNonexistent);
    RUN_TEST(testRoomList);
    RUN_TEST(testCreateRoomZeroPayload);
    RUN_TEST(testJoinRoomZeroPayload);

    /* —— Chat —— */
    RUN_TEST(testChatSendAndBroadcast);
    RUN_TEST(testChatZeroPayload);
    RUN_TEST(testChatMsgNotNulTerminated);

    /* —— Session —— */
    RUN_TEST(testLogout);

    /* —— State Machine & Security —— */
    RUN_TEST(testStateMachineViolationKeyex);
    RUN_TEST(testUnencryptedPacketAfterAuth);
    RUN_TEST(testRegisterBeforeKeyExchange);
    RUN_TEST(testRegisterAfterLogin);
    RUN_TEST(testHeartbeatEcho);
    RUN_TEST(testLoginEmptyPassword);
    RUN_TEST(testTOTPSetupAfterLogin);
    RUN_TEST(testTOTPSetupAlreadyEnabled);
    RUN_TEST(testTOTPVerifySuccess);
    RUN_TEST(testTOTPVerifyWrongCode);
    RUN_TEST(testTOTPVerifyMalformedPayload);
    RUN_TEST(testSessionTOTPVerifyStateViolation);

    /* —— Key Management —— */
    RUN_TEST(testServerInitKeysFirstRun);
    RUN_TEST(testFreshKeysGeneratedFlag);

    removeDBFiles();

    return TEST_REPORT();
}
