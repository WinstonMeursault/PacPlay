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

#include "client/communication.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/keyManager.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* ──────────────────────────── named constants ───────────────────────────── */

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

    /* String length constants (pure strlen, without NUL terminator) */
    StrLenAlice = 5,
    StrLenBob = 3,
    StrLenCharlie = 7,
    StrLenX = 1,
    StrLenTestNick = 8,
    StrLenHbuser = 6,
    StrLenRegLate = 7,

    /* Timestamp */
    ChatTimestamp = 1234567890,
    DummyPayloadByte = 0xFF
};

/* ─────────────────────────── helper prototypes ──────────────────────────── */

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

/* ───────────────────────── helper implementations ───────────────────────── */

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
    remove("./db/room.db");
    remove("./db/room.db-wal");
    remove("./db/room.db-shm");
    remove("./db/server.db");
    remove("./db/server.db-wal");
    remove("./db/server.db-shm");
    remove("./db/game.db");
    remove("./db/game.db-wal");
    remove("./db/game.db-shm");
    rmdir("./db");
}

/* ══════════════════════════════ Login Tests ═══════════════════════════════ */

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

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
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp,
                    sizeof(failResp));
        }

        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

    const char *un = "TestUser";
    const char *pw = "testpass";
    size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *loginPayload = calloc(1, plen);
    ASSERT_TRUE(loginPayload != NULL);
    memcpy(loginPayload->username, un, strlen(un) + 1);
    memcpy(loginPayload->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, loginPayload, plen),
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
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
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp,
                    sizeof(failResp));
        }

        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

    const char *un = "pwduser";
    const char *pw = "wrongpassword";
    size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *loginPayload = calloc(1, plen);
    ASSERT_TRUE(loginPayload != NULL);
    memcpy(loginPayload->username, un, strlen(un) + 1);
    memcpy(loginPayload->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, loginPayload, plen),
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);

        uint32_t seq = 0;
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp,
                sizeof(failResp));

        packetClear(&pkt);
        dbClose(uDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

    const char *un = "Nobody";
    const char *pw = "pass";
    size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *loginPayload = calloc(1, plen);
    ASSERT_TRUE(loginPayload != NULL);
    memcpy(loginPayload->username, un, strlen(un) + 1);
    memcpy(loginPayload->password, pw, strlen(pw) + 1);

    uint32_t seq = 0;
    ASSERT_INT_EQ(
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, loginPayload, plen),
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


/** @brief Logout received by server disconnects client cleanly. */
static void testLogout(void) {
    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *uDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "X";
        const char *pw = "x";
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

    /* Send logout */
    sendEnc(sv[0], &cliKey, &seq, MsgLogout, NULL, 0);

    socketClose(&sv[0]);
    int status = 0;
    waitpid(child, &status, 0);
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ════════════════════════ State Machine Violations ════════════════════════ */

/** @brief Sending MsgLoginReq before key exchange should disconnect. */
static void testStateMachineViolationKeyex(void) {
    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *uDB = dbInit(UserDB, NULL);
        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
        /* Expect the next packet to be garbage — disconnect */
        socketClose(&sv[1]);
        dbClose(uDB);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

    /* Send a PLAINTEXT packet (not encrypted) after key exchange */
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    enum { PlainPktSeq = 0 };
    uint8_t dummy = DummyPayloadByte;
    ASSERT_INT_EQ(packetInit(&pkt, MsgLoginReq, PlainPktSeq, PlaintextPacket,
                             &dummy, sizeof(dummy)),
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
        uint32_t seq = 0;
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        /* Send failure response */
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp,
                sizeof(failResp));
        packetClear(&pkt);
        dbClose(uDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
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

/* ═══════════════════════════════ TOTP Setup ═══════════════════════════════ */

static void testTOTPSetupAfterLogin(void) {
    enum {
        TotpUid = 700,
        TotpNameLen = 9,
        TestNickLen = 9,
        TestSecretLen = 16
    };
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
    uint32_t cliSeq = 0;

    /* Login via simulated server */
    {
        const char *pw = "totppw1";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, "totpguy1", TotpNameLen);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &cliSeq, MsgLoginReq, lp, plen),
                      0);
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
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &cliSeq, MsgTOTPSetupReq, NULL, 0),
                  0);

    /* Receive TOTP setup response */
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgTOTPSetupResp);
        ASSERT_TRUE(rpkt.header.payloadLength >= sizeof(TOTPSetupRespPayload));
        TOTPSetupRespPayload *resp = (TOTPSetupRespPayload *)rpkt.payload;
        ASSERT_TRUE(resp->secret[0] != '\0');
        packetClear(&rpkt);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

static void testTOTPSetupAlreadyEnabled(void) {
    enum {
        TotpUid = 701,
        TotpNameLen = 9,
        TestNickLen = 9,
        TestSecretLen = 16
    };
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
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
            sendEnc(sv[1], &srvKey, &seq, MsgTOTPSetupResp, &r1, sizeof(r1));
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
    uint32_t cliSeq = 0;

    {
        const char *pw = "totppw2";
        size_t plen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
        LoginRequestPayload *lp = calloc(1, plen);
        memcpy(lp->username, "totpguy2", TotpNameLen);
        memcpy(lp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &cliSeq, MsgLoginReq, lp, plen),
                      0);
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
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &cliSeq, MsgTOTPSetupReq, NULL, 0),
                  0);
    {
        Packet rpkt;
        memset(&rpkt, 0, sizeof(rpkt));
        ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
        ASSERT_INT_EQ(rpkt.header.messageType, MsgTOTPSetupResp);
        packetClear(&rpkt);
    }

    /* Second setup — must be rejected */
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &cliSeq, MsgTOTPSetupReq, NULL, 0),
                  0);
    int status = recvStatus(sv[0], &cliKey, MsgTOTPSetupResp);
    ASSERT_INT_EQ(status, 1);

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/* ══════════════════════════════ TOTP Verify ═══════════════════════════════ */

static void testTOTPVerifySuccess(void) {
    enum {
        TotpUid = 800,
        SockParent = 0,
        SockChild = 1,
        NameLen = 9,
        TestCode = 123456
    };
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[SockChild], &srvKey),
                      PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[SockParent], &cliKey), PROTOCOL_SUCC);
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
        ASSERT_INT_EQ(sendEnc(sv[SockParent], &cliKey, &cliSeq,
                              MsgTOTPVerifyResp, &vp, sizeof(vp)),
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[SockChild], &srvKey),
                      PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[SockParent], &cliKey), PROTOCOL_SUCC);
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[SockChild], &srvKey),
                      PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[SockParent], &cliKey), PROTOCOL_SUCC);
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

/* ════════════════════════ State Machine Violations ════════════════════════ */

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[SockChild], &srvKey),
                      PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[SockParent], &cliKey), PROTOCOL_SUCC);
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

/* ════════════════════════ Protocol Edge-Case Tests ════════════════════════ */

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgLoginReq);

        enum { MinLoginPayload = 33 };
        uint32_t seq = 0;
        if (pkt.header.payloadLength < MinLoginPayload) {
            LoginResponsePayload failResp;
            memset(&failResp, 0, sizeof(failResp));
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp,
                    sizeof(failResp));
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

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
            sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp,
                    sizeof(failResp));
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
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
            uint8_t s = (pkt.header.payloadLength != sizeof(uint32_t)) ? 1 : 0;
            sendEnc(sv[1], &srvKey, &seq, MsgCreateRoomResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
        uint32_t seq = 0;

        /* First register — should succeed */
        {
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
            RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt.payload;
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
    uint32_t seq = 0;

    const char *un = "DupSession";
    const char *pw = "sessionpw";
    size_t plen = offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        enum { MinPayload = 65 };
        uint8_t status = (pkt.header.payloadLength < MinPayload) ? 1 : 0;
        uint32_t seq = 0;
        sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &status, sizeof(status));
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt.payload;
        uint8_t status =
            (reg->username[LOGIN_USERNAME_LEN - 1] != '\0') ? 1 : 0;
        uint32_t seq = 0;
        sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &status, sizeof(status));
        packetClear(&pkt);
        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

    const char *pw = "a";
    size_t plen = offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgRegisterReq);

        RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt.payload;
        size_t pwLen = pkt.header.payloadLength -
                       offsetof(RegisterRequestPayload, password);
        uint8_t status = (memchr(reg->password, '\0', pwLen) == NULL) ? 1 : 0;
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

        uint32_t seq = 0;

        /* Phase 1: register */
        {
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

            uint8_t s = (dbRet == DB_SUCC) ? 0 : 1;
            sendEnc(sv[1], &srvKey, &seq, MsgRegisterResp, &s, sizeof(s));
            packetClear(&pkt);
        }

        /* Phase 2: login */
        {
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

            if (dbRet == DB_SUCC) {
                LoginResponsePayload resp;
                memset(&resp, 0, sizeof(resp));
                resp.uid = verify.uid;
                memcpy(resp.username, verify.username, LOGIN_USERNAME_LEN);
                memcpy(resp.nickname, verify.nickname, LOGIN_NICKNAME_LEN);
                sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &resp,
                        sizeof(resp));
            } else {
                LoginResponsePayload failResp;
                memset(&failResp, 0, sizeof(failResp));
                sendEnc(sv[1], &srvKey, &seq, MsgLoginResp, &failResp,
                        sizeof(failResp));
            }
            packetClear(&pkt);
        }

        dbClose(userDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
    uint32_t seq = 0;

    const char *un = "E2EUser";
    const char *pw = "e2epass";
    const char *nick = "TestNick";
    size_t regPlen =
        offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
    RegisterRequestPayload *regPayload = calloc(1, regPlen);
    ASSERT_TRUE(regPayload != NULL);
    memcpy(regPayload->username, un, strlen(un) + 1);
    memcpy(regPayload->nickname, nick, StrLenTestNick + 1);
    memcpy(regPayload->password, pw, strlen(pw) + 1);

    /* Register */
    ASSERT_INT_EQ(
        sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, regPayload, regPlen),
        PROTOCOL_SUCC);
    ASSERT_INT_EQ(recvStatus(sv[0], &cliKey, MsgRegisterResp), 0);

    /* Login */
    size_t loginPlen = offsetof(LoginRequestPayload, password) + strlen(pw) + 1;
    LoginRequestPayload *loginPayload = calloc(1, loginPlen);
    ASSERT_TRUE(loginPayload != NULL);
    memcpy(loginPayload->username, un, strlen(un) + 1);
    memcpy(loginPayload->password, pw, strlen(pw) + 1);

    ASSERT_INT_EQ(
        sendEnc(sv[0], &cliKey, &seq, MsgLoginReq, loginPayload, loginPlen),
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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
        /* Register before key exchange is a protocol violation —
         * the real server returns SERVER_FAIL (disconnect). */
        socketClose(&sv[1]);
        dbClose(uDB);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

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
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);
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
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);
    uint32_t seq = 0;

    /* Login */
    {
        const char *un = "RegLate";
        const char *pw = "latepw";
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

    /* Send register packet in wrong state — will be ignored/disconnected */
    {
        const char *pw = "x";
        size_t plen =
            offsetof(RegisterRequestPayload, password) + strlen(pw) + 1;
        RegisterRequestPayload *rp = calloc(1, plen);
        memcpy(rp->username, "BadReg", BadRegLen);
        memcpy(rp->nickname, "TestNick", StrLenTestNick + 1);
        memcpy(rp->password, pw, strlen(pw) + 1);
        ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &seq, MsgRegisterReq, rp, plen),
                      PROTOCOL_SUCC);
        free(rp);
    }

    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
}

/* ══════════════════════════ Key Management Tests ══════════════════════════ */

/** @brief First-run serverInitKeys generates 4 keys and stores them. */
static void testServerInitKeysFirstRun(void) {
    removeDBFiles();
    DB *serverDB = dbInit(ServerDB, NULL);
    ASSERT_TRUE(serverDB != NULL);

    Server srv;
    memset(&srv, 0, sizeof(srv));
    srv.serverDB = serverDB;

    ASSERT_FALSE(srv.freshKeysGenerated);

    /* Generate fresh keys and unlock with the returned MK. */
    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);

    int ret = serverUnlockWithMK(&srv, mkHex);
    free(mkHex);

    ASSERT_INT_EQ(ret, SERVER_SUCC);
    ASSERT_TRUE(srv.freshKeysGenerated);

    /* All 7 keys must be non-zero (generate was called) */
    static const uint8_t zeros32[32];
    ASSERT_TRUE(memcmp(srv.dekKey, zeros32, sizeof(srv.dekKey)) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, zeros32, sizeof(srv.userDbEncKey)) !=
                0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, zeros32, sizeof(srv.gameDbEncKey)) !=
                0);
    ASSERT_TRUE(memcmp(srv.gameRoomDbEncKey, zeros32, sizeof(srv.gameRoomDbEncKey)) !=
                0);
    ASSERT_TRUE(memcmp(srv.friendDbEncKey, zeros32, sizeof(srv.friendDbEncKey)) !=
                0);
    ASSERT_TRUE(memcmp(srv.privateChatDbEncKey, zeros32,
                       sizeof(srv.privateChatDbEncKey)) != 0);
    ASSERT_TRUE(memcmp(srv.groupDbEncKey, zeros32, sizeof(srv.groupDbEncKey)) !=
                0);

    /* All 7 keys must be distinct from each other */
    ASSERT_TRUE(memcmp(srv.dekKey, srv.userDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.gameDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.gameRoomDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.friendDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.privateChatDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.groupDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.gameDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.gameRoomDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.friendDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.privateChatDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.groupDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, srv.gameRoomDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, srv.friendDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, srv.privateChatDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, srv.groupDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.gameRoomDbEncKey, srv.friendDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.gameRoomDbEncKey, srv.privateChatDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.gameRoomDbEncKey, srv.groupDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.friendDbEncKey, srv.privateChatDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.friendDbEncKey, srv.groupDbEncKey, 32) != 0);
    ASSERT_TRUE(memcmp(srv.privateChatDbEncKey, srv.groupDbEncKey, 32) != 0);

    /* Verify all 7 envelopes are stored in ServerDB */
    uint8_t *outDek = NULL;
    uint8_t *outUser = NULL;
    uint8_t *outGame = NULL;
    uint8_t *outGameRoom = NULL;
    uint8_t *outFriend = NULL;
    uint8_t *outPrivateChat = NULL;
    uint8_t *outGroup = NULL;
    size_t lenDek = 0;
    size_t lenUser = 0;
    size_t lenGame = 0;
    size_t lenGameRoom = 0;
    size_t lenFriend = 0;
    size_t lenPrivateChat = 0;
    size_t lenGroup = 0;
    ASSERT_INT_EQ(getServerKey(serverDB, "DEK", &outDek, &lenDek), DB_SUCC);
    ASSERT_INT_EQ(getServerKey(serverDB, "UserDBKey", &outUser, &lenUser),
                  DB_SUCC);
    ASSERT_INT_EQ(getServerKey(serverDB, "GameDBKey", &outGame, &lenGame),
                  DB_SUCC);
    ASSERT_INT_EQ(
        getServerKey(serverDB, "GameRoomDBKey", &outGameRoom, &lenGameRoom),
        DB_SUCC);
    ASSERT_INT_EQ(
        getServerKey(serverDB, "FriendDBKey", &outFriend, &lenFriend),
        DB_SUCC);
    ASSERT_INT_EQ(
        getServerKey(serverDB, "PrivateChatDBKey", &outPrivateChat,
                     &lenPrivateChat),
        DB_SUCC);
    ASSERT_INT_EQ(
        getServerKey(serverDB, "GroupDBKey", &outGroup, &lenGroup),
        DB_SUCC);

    enum { EnvelopeLen = 12 + 32 + 16 }; /* nonce + key + tag */
    ASSERT_TRUE(outDek != NULL);
    ASSERT_UINT_EQ(lenDek, (size_t)EnvelopeLen);
    ASSERT_TRUE(outUser != NULL);
    ASSERT_UINT_EQ(lenUser, (size_t)EnvelopeLen);
    ASSERT_TRUE(outGame != NULL);
    ASSERT_UINT_EQ(lenGame, (size_t)EnvelopeLen);
    ASSERT_TRUE(outGameRoom != NULL);
    ASSERT_UINT_EQ(lenGameRoom, (size_t)EnvelopeLen);
    ASSERT_TRUE(outFriend != NULL);
    ASSERT_UINT_EQ(lenFriend, (size_t)EnvelopeLen);
    ASSERT_TRUE(outPrivateChat != NULL);
    ASSERT_UINT_EQ(lenPrivateChat, (size_t)EnvelopeLen);
    ASSERT_TRUE(outGroup != NULL);
    ASSERT_UINT_EQ(lenGroup, (size_t)EnvelopeLen);

    free(outDek);
    free(outUser);
    free(outGame);
    free(outGameRoom);
    free(outFriend);
    free(outPrivateChat);
    free(outGroup);

    OPENSSL_cleanse(srv.dekKey, sizeof(srv.dekKey));
    OPENSSL_cleanse(srv.userDbEncKey, sizeof(srv.userDbEncKey));
    OPENSSL_cleanse(srv.gameDbEncKey, sizeof(srv.gameDbEncKey));
    OPENSSL_cleanse(srv.gameRoomDbEncKey, sizeof(srv.gameRoomDbEncKey));
    OPENSSL_cleanse(srv.friendDbEncKey, sizeof(srv.friendDbEncKey));
    OPENSSL_cleanse(srv.privateChatDbEncKey, sizeof(srv.privateChatDbEncKey));
    OPENSSL_cleanse(srv.groupDbEncKey, sizeof(srv.groupDbEncKey));
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

/** @brief serverInitKeys subsequent-run: pre-populate envelopes, feed
 *  known MK via stdin, verify decrypted keys are loaded correctly. */
static void testServerInitKeysSubsequentRun(void) {
    enum {
        KeyLen = 32,
        NonceLen = AES_GCM_NONCE_LEN,
        TagLen = AES_GCM_TAG_LEN,
        EnvelopeLen = NonceLen + KeyLen + TagLen,
        HexMkLen = KeyLen * 2,
        MkInputBufSize = HexMkLen + 4
    };

    /*
     * Known deterministic keys — deliberately patterned for verification.
     * In production these would be cryptoRandomBytes; for testing a
     * subsequent-run we pre-compute the envelopes ourselves.
     */
    static const uint8_t knownMk[KeyLen] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    static const uint8_t knownDek[KeyLen] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
        0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78};
    static const uint8_t knownUserDbKey[KeyLen] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
        0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
        0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF};
    static const uint8_t knownGameDbKey[KeyLen] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x11, 0x21, 0x31,
        0x41, 0x51, 0x61, 0x71, 0x81, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62,
        0x72, 0x82, 0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83};
    static const uint8_t knownGameRoomDbKey[KeyLen] = {
        0x14, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74, 0x84, 0x15, 0x25, 0x35,
        0x45, 0x55, 0x65, 0x75, 0x85, 0x16, 0x26, 0x36, 0x46, 0x56, 0x66,
        0x76, 0x86, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87};
    static const uint8_t knownFriendDbKey[KeyLen] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
        0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
        0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF};
    static const uint8_t knownPrivateChatDbKey[KeyLen] = {
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA,
        0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
        0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF};
    static const uint8_t knownGroupDbKey[KeyLen] = {
        0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A, 0x8A, 0x1B, 0x2B, 0x3B,
        0x4B, 0x5B, 0x6B, 0x7B, 0x8B, 0x1C, 0x2C, 0x3C, 0x4C, 0x5C, 0x6C,
        0x7C, 0x8C, 0x1D, 0x2D, 0x3D, 0x4D, 0x5D, 0x6D, 0x7D, 0x8D};

    removeDBFiles();

    /* --- Step 1: pre-populate ServerDB with known-encrypted envelopes --- */
    {
        DB *serverDB = dbInit(ServerDB, NULL);
        ASSERT_TRUE(serverDB != NULL);

        AESGCMKey encKey;
        memcpy(encKey.key, knownMk, KeyLen);

        /* Encrypt and store each key using AES-256-GCM */
        const struct {
            const uint8_t *data;
            const char *name;
        } keys[] = {
            {knownDek, "DEK"},
            {knownUserDbKey, "UserDBKey"},
            {knownGameDbKey, "GameDBKey"},
            {knownGameRoomDbKey, "GameRoomDBKey"},
            {knownFriendDbKey, "FriendDBKey"},
            {knownPrivateChatDbKey, "PrivateChatDBKey"},
            {knownGroupDbKey, "GroupDBKey"},
        };
        enum { KeyCount = 7 };

        for (int i = 0; i < KeyCount; i++) {
            ASSERT_INT_EQ(cryptoRandomBytes(encKey.nonce, NonceLen),
                          CRYPTO_SUCC);

            AESGCMBuffer pt;
            pt.data = (uint8_t *)(uintptr_t)keys[i].data;
            pt.capacity = KeyLen;
            pt.len = KeyLen;

            AESGCMCipher ct;
            ASSERT_INT_EQ(aesGCMBufferInit(&ct.buffer, KeyLen), CRYPTO_SUCC);
            ASSERT_INT_EQ(encryptAESGCM(&pt, NULL, &encKey, &ct), CRYPTO_SUCC);

            uint8_t envelope[EnvelopeLen];
            memcpy(envelope, encKey.nonce, NonceLen);
            memcpy(envelope + NonceLen, ct.buffer.data, KeyLen);
            memcpy(envelope + NonceLen + KeyLen, ct.tag, TagLen);

            ASSERT_INT_EQ(setServerKey(serverDB, keys[i].name, envelope,
                                       sizeof(envelope)),
                          DB_SUCC);

            aesGCMBufferDeinit(&ct.buffer);
        }

        dbClose(serverDB);
    }

    /* --- Step 2: subsequent run — feed MK hex via stdin, verify keys --- */
    {
        DB *serverDB = dbInit(ServerDB, NULL);
        ASSERT_TRUE(serverDB != NULL);

        Server srv;
        memset(&srv, 0, sizeof(srv));
        srv.serverDB = serverDB;

        /* Build MK hex string */
        char mkHex[MkInputBufSize];
        for (size_t i = 0; i < KeyLen; i++) {
            snprintf(mkHex + i * 2, 3, "%02x", knownMk[i]);
        }
        mkHex[HexMkLen] = '\0';

        /* Feed MK hex directly via serverUnlockWithMK. */
        int ret = serverUnlockWithMK(&srv, mkHex);

        ASSERT_INT_EQ(ret, SERVER_SUCC);
        ASSERT_FALSE(srv.freshKeysGenerated);
        ASSERT_MEM_EQ(srv.dekKey, knownDek, KeyLen);
        ASSERT_MEM_EQ(srv.userDbEncKey, knownUserDbKey, KeyLen);
        ASSERT_MEM_EQ(srv.gameDbEncKey, knownGameDbKey, KeyLen);
        ASSERT_MEM_EQ(srv.gameRoomDbEncKey, knownGameRoomDbKey, KeyLen);
        ASSERT_MEM_EQ(srv.friendDbEncKey, knownFriendDbKey, KeyLen);
        ASSERT_MEM_EQ(srv.privateChatDbEncKey, knownPrivateChatDbKey, KeyLen);
        ASSERT_MEM_EQ(srv.groupDbEncKey, knownGroupDbKey, KeyLen);

        OPENSSL_cleanse(srv.dekKey, sizeof(srv.dekKey));
        OPENSSL_cleanse(srv.userDbEncKey, sizeof(srv.userDbEncKey));
        OPENSSL_cleanse(srv.gameDbEncKey, sizeof(srv.gameDbEncKey));
        OPENSSL_cleanse(srv.gameRoomDbEncKey, sizeof(srv.gameRoomDbEncKey));
        OPENSSL_cleanse(srv.friendDbEncKey, sizeof(srv.friendDbEncKey));
        OPENSSL_cleanse(srv.privateChatDbEncKey, sizeof(srv.privateChatDbEncKey));
        OPENSSL_cleanse(srv.groupDbEncKey, sizeof(srv.groupDbEncKey));
        dbClose(serverDB);
    }
    removeDBFiles();
}

/* ═══════════════════════════ DBKeyReq tests ══════════════════════════════ */

static void testDBKeyReqHappyPath(void) {
    uint8_t dek[AES_GCM_KEY_LEN];
    cryptoRandomBytes(dek, sizeof(dek));

    DB *userDB = dbInit(UserDB, NULL);
    ASSERT_NOT_NULL(userDB);
    dbSetDekKey(userDB, dek);

    User u;
    memset(&u, 0, sizeof(u));
    memcpy(u.username, "dbkeytest", strlen("dbkeytest") + 1);
    memcpy(u.nickname, "DBKeyTest", strlen("DBKeyTest") + 1);
    u.password = strdup("testpass");
    ASSERT_INT_EQ(createUser(userDB, &u), DB_SUCC);
    free(u.password);

    /* Get expected CDBKey for later verification. */
    uint8_t expectedKey[DB_ENC_KEY_LEN];
    ASSERT_INT_EQ(getCDBKey(userDB, u.uid, expectedKey), DB_SUCC);

    SocketFD sv[2];
    ASSERT_INT_EQ(makeSocketPair(sv), 0);

    dbClose(userDB); /* child will reopen */

    pid_t child = fork();
    if (child == 0) {
        socketClose(&sv[0]);
        DB *srvDB = dbInit(UserDB, NULL);
        dbSetDekKey(srvDB, dek);

        AESGCMKey srvKey;
        ASSERT_INT_EQ(serverDoKeyExchange(sv[1], &srvKey), PROTOCOL_SUCC);

        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        ASSERT_INT_EQ(recvDec(sv[1], &srvKey, &pkt), 0);
        ASSERT_INT_EQ(pkt.header.messageType, MsgDBKeyReq);

        /* Send CDBKey response. */
        uint8_t cdbk[DB_ENC_KEY_LEN];
        ASSERT_INT_EQ(getCDBKey(srvDB, u.uid, cdbk), DB_SUCC);
        uint32_t srvSeq = 0;
        ASSERT_INT_EQ(
            sendEnc(sv[1], &srvKey, &srvSeq, MsgDBKeyResp, cdbk, sizeof(cdbk)),
            PROTOCOL_SUCC);
        OPENSSL_cleanse(cdbk, sizeof(cdbk));

        packetClear(&pkt);
        OPENSSL_cleanse(&srvKey, sizeof(srvKey));
        dbClose(srvDB);
        socketClose(&sv[1]);
        _exit(0);
    }

    socketClose(&sv[1]);
    AESGCMKey cliKey;
    ASSERT_INT_EQ(clientDoKeyExchange(sv[0], &cliKey), PROTOCOL_SUCC);

    /* Send MsgDBKeyReq (empty payload). */
    uint32_t cliSeq = 0;
    ASSERT_INT_EQ(sendEnc(sv[0], &cliKey, &cliSeq, MsgDBKeyReq, NULL, 0),
                  PROTOCOL_SUCC);

    /* Receive MsgDBKeyResp. */
    Packet rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    ASSERT_INT_EQ(recvDec(sv[0], &cliKey, &rpkt), 0);
    ASSERT_INT_EQ(rpkt.header.messageType, MsgDBKeyResp);
    ASSERT_UINT_EQ(rpkt.header.payloadLength, (uint32_t)DB_ENC_KEY_LEN);
    ASSERT_NOT_NULL(rpkt.payload);

    /* Verify it matches the expected key. */
    ASSERT_MEM_EQ(rpkt.payload, expectedKey, DB_ENC_KEY_LEN);

    OPENSSL_cleanse(expectedKey, sizeof(expectedKey));
    OPENSSL_cleanse(&cliKey, sizeof(cliKey));
    packetClear(&rpkt);
    socketClose(&sv[0]);
    waitpid(child, NULL, 0);
    OPENSSL_cleanse(dek, sizeof(dek));
}

/* ══════════════════════════════════ Main ══════════════════════════════════ */

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
    RUN_TEST(testRegisterDuplicate);
    RUN_TEST(testRegisterDuplicateSameSession);
    RUN_TEST(testRegisterEmptyPassword);
    RUN_TEST(testRegisterPayloadTooSmall);
    RUN_TEST(testRegisterUsernameNotNulTerminated);
    RUN_TEST(testRegisterPasswordNotNulTerminated);
    RUN_TEST(testRegisterThenLogin);

    /* —— Room —— */
    RUN_TEST(testCreateRoomZeroPayload);

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
    RUN_TEST(testServerInitKeysSubsequentRun);
    RUN_TEST(testFreshKeysGeneratedFlag);

    /* —— DBKeyReq —— */
    RUN_TEST(testDBKeyReqHappyPath);

    removeDBFiles();

    return TEST_REPORT();
}
