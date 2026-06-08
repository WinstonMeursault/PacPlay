/**
 * @file test_communication.c
 * @brief Adversarial tests for client/server ECDH+HKDF key exchange modules.
 *
 * Covers every validation path in clientExchangeAESKey and
 * serverExchangeAESKey with boundary, out-of-range, and fork-based
 * network roundtrip scenarios.
 *
 * @date 2026-05-22
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

#include "client/client.h"
#include "client/communication.h"
#include "server/communication.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Forward-declare the communication functions.  Both client/communication.h
 * and server/communication.h define COMM_SUCC / COMM_FAIL with the same
 * values; including both would cause a macro-redefinition warning.  The
 * declarations below match the published signatures exactly.
 */
int clientExchangeAESKey(SocketFD socketFD, AESGCMKey *outKey);
int serverExchangeAESKey(SocketFD clientFD, Packet *reqPacket,
                         AESGCMKey *outKey);

/* ────────────────────────── test-local constants ────────────────────────── */

/** Indices into a socketpair result array. */
enum { SockA = 0, SockB = 1, SockLen = 2 };

/** Communication-module return codes (mirrors COMM_SUCC / COMM_FAIL). */
enum { CommSucc = 0, CommFail = -1 };

/** Filler / tamper bytes used throughout. */
enum { FillByteA = 0xAB, FillByteB = 0xCD, ZeroByte = 0 };

/** Test payload lengths (bytes). */
enum { Payload32 = 32, Payload31 = 31, Payload33 = 33, Payload64 = 64 };

/** Derived AES-key size. */
enum { AesKeyLen = 32 };

/** Test plaintext for encrypt/decrypt roundtrip. */
static const char testMessage[] = "Key exchange verification payload.";

/* ──────────────────────────────── helpers ───────────────────────────────── */

/**
 * @brief Create a connected pair of local sockets (socketpair).
 *
 * @param pair Output: pair[SockA] and pair[SockB] are connected.
 * @return 0 on success, -1 on failure.
 */
static int makePair(SocketFD pair[SockLen]) {
    int fds[SockLen];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        pair[SockA] = NULL_SOCKETFD;
        pair[SockB] = NULL_SOCKETFD;
        return -1;
    }
    pair[SockA] = fds[SockA];
    pair[SockB] = fds[SockB];
    return 0;
}

/**
 * @brief Build a raw Packet with arbitrary header values.
 *
 * Unlike packetInit this helper accepts out-of-range messageType /
 * packetType via @c memcpy, emulating an attacker who injects arbitrary
 * bytes into the header fields.  payload is @c malloc'd and filled from
 * @p payloadData when @p payloadLen > 0; otherwise it stays NULL.
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static Packet makeRawPacket(uint32_t magic, uint32_t rawMsgType,
                            uint32_t rawPktType, size_t payloadLen,
                            const void *payloadData) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = magic;
    memcpy(&pkt.header.messageType, &rawMsgType, sizeof(rawMsgType));
    memcpy(&pkt.header.packetType, &rawPktType, sizeof(rawPktType));
    pkt.header.payloadLength = payloadLen;
    pkt.header.sequenceID = 0;

    if (payloadLen > 0 && payloadData != NULL) {
        pkt.payload = malloc(payloadLen);
        if (pkt.payload != NULL) {
            memcpy(pkt.payload, payloadData, payloadLen);
        }
    }
    return pkt;
}

/**
 * @brief Build a valid KeyExchangePacketPayload filled with @p fillByte.
 */
static KeyExchangePacketPayload makeKeyPayload(uint8_t fillByte) {
    KeyExchangePacketPayload p;
    memset(&p, fillByte, sizeof(p));
    return p;
}

/* ═════════════════════════════ A1. Constants ══════════════════════════════ */

static void testCommReturnCodes(void) {
    ASSERT_INT_EQ(CommSucc, 0);
    ASSERT_INT_EQ(CommFail, -1);
}

/* ═════════════════ A2. clientExchangeAESKey — error paths ═════════════════ */

/** @brief NULL outKey is rejected immediately. */
static void testClientExchangeNullOutKey(void) {
    ASSERT_INT_EQ(clientExchangeAESKey(NULL_SOCKETFD, NULL), CommFail);
}

/** @brief An invalid socket FD makes packetSend fail → COMM_FAIL. */
static void testClientExchangeInvalidSocket(void) {
    AESGCMKey key;
    ASSERT_INT_EQ(clientExchangeAESKey(NULL_SOCKETFD, &key), CommFail);
}

/* ════════════════ A3. serverExchangeAESKey — NULL / basic ═════════════════ */

static void testServerNullReqPacket(void) {
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, NULL, &key), CommFail);
}

static void testServerNullOutKey(void) {
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               Payload32, &kp);
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, NULL), CommFail);
    packetClear(&req);
}

static void testServerNullPayload(void) {
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               Payload32, NULL);
    /* payload stays NULL (payloadLen>0 but payloadData==NULL). */
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

/* ══════════════ A4. serverExchangeAESKey — wrong messageType ══════════════ */

static void testServerMsgTypeLoginReq(void) {
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet req = makeRawPacket(PACKET_MAGIC, MsgLoginReq, PlaintextPacket,
                               Payload32, &kp);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerMsgTypeLoginResp(void) {
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet req = makeRawPacket(PACKET_MAGIC, MsgLoginResp, PlaintextPacket,
                               Payload32, &kp);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerMsgTypeChat(void) {
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet req =
        makeRawPacket(PACKET_MAGIC, MsgChat, PlaintextPacket, Payload32, &kp);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerMsgTypeHeartbeat(void) {
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet req = makeRawPacket(PACKET_MAGIC, MsgHeartbeat, PlaintextPacket,
                               Payload32, &kp);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerMsgTypeKeyExResp(void) {
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeResp,
                               PlaintextPacket, Payload32, &kp);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

/* ══════════════ A5. serverExchangeAESKey — wrong packetType ═══════════════ */

static void testServerPktTypeAES256GCM(void) {
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, AES256GCMPacket,
                               Payload32, &kp);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

/** @brief Attacker injects packetType=0 (below PlaintextPacket=1). */
static void testServerPktTypeZero(void) {
    enum { RawZero = 0 };
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet req =
        makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, RawZero, Payload32, &kp);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

/* ═════════════ A6. serverExchangeAESKey — wrong payloadLength ═════════════ */

static void testServerPayloadLenZero(void) {
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               ZeroByte, NULL);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerPayloadLenOne(void) {
    enum { OneByte = 1 };
    uint8_t oneBuf[OneByte];
    memset(oneBuf, FillByteA, sizeof(oneBuf));
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               OneByte, oneBuf);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerPayloadLenShort(void) {
    uint8_t buf[Payload31];
    memset(buf, FillByteA, sizeof(buf));
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               Payload31, buf);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerPayloadLenLong(void) {
    uint8_t buf[Payload33];
    memset(buf, FillByteA, sizeof(buf));
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               Payload33, buf);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerPayloadLenDouble(void) {
    uint8_t buf[Payload64];
    memset(buf, FillByteA, sizeof(buf));
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               Payload64, buf);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
}

static void testServerPayloadLenMax(void) {
    uint8_t *buf = malloc(MAX_PAYLOAD_LEN);
    ASSERT_TRUE(buf != NULL);
    memset(buf, FillByteA, MAX_PAYLOAD_LEN);
    Packet req = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               MAX_PAYLOAD_LEN, buf);
    AESGCMKey key;
    ASSERT_INT_EQ(serverExchangeAESKey(NULL_SOCKETFD, &req, &key), CommFail);
    packetClear(&req);
    free(buf);
}

/* ═════════════════ B. Roundtrip & invariants (fork-based) ═════════════════ */

/**
 * @brief Fork a child that runs clientExchangeAESKey; the parent runs
 *        serverExchangeAESKey.  Both derived keys are returned via pointers
 *        so the caller can compare them byte-for-byte.
 *
 * @return 0 on success, non-zero on any failure in either process.
 */
static int doFullRoundtrip(AESGCMKey *clientKey, AESGCMKey *serverKey) {
    SocketFD pair[SockLen];
    if (makePair(pair) != 0) {
        return -1;
    }

    int keyPipe[2];
    if (pipe(keyPipe) != 0) {
        close(pair[SockA]);
        close(pair[SockB]);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pair[SockA]);
        close(pair[SockB]);
        close(keyPipe[0]);
        close(keyPipe[1]);
        return -1;
    }

    if (pid == 0) {
        /* ───────────────────────────── child: client
         * ────────────────────────────── */
        close(pair[SockB]);
        close(keyPipe[0]);

        AESGCMKey cKey;
        int ret = clientExchangeAESKey(pair[SockA], &cKey);
        if (ret != CommSucc) {
            close(pair[SockA]);
            close(keyPipe[1]);
            _exit(1);
        }

        /* Send client's derived key back to the parent. */
        ssize_t w = write(keyPipe[1], &cKey, sizeof(cKey));
        OPENSSL_cleanse(&cKey, sizeof(cKey));
        close(keyPipe[1]);
        close(pair[SockA]);
        _exit((w == sizeof(cKey)) ? 0 : 2);
    }

    /* ───────────────────────────── parent: server
     * ───────────────────────────── */
    close(pair[SockA]);
    close(keyPipe[1]);

    /* Receive the client's MsgKeyExchangeReq. */
    Packet req;
    memset(&req, 0, sizeof(req));
    if (packetRecv(&req, pair[SockB]) != PROTOCOL_SUCC) {
        close(pair[SockB]);
        close(keyPipe[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }

    AESGCMKey sKey;
    int sRet = serverExchangeAESKey(pair[SockB], &req, &sKey);
    packetClear(&req);
    if (sRet != CommSucc) {
        close(pair[SockB]);
        close(keyPipe[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }

    /* Read client's derived key from the pipe. */
    AESGCMKey cKey;
    ssize_t r = read(keyPipe[0], &cKey, sizeof(cKey));
    close(keyPipe[0]);
    close(pair[SockB]);

    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || r != sizeof(cKey)) {
        OPENSSL_cleanse(&sKey, sizeof(sKey));
        OPENSSL_cleanse(&cKey, sizeof(cKey));
        return -1;
    }

    if (clientKey != NULL) {
        memcpy(clientKey, &cKey, sizeof(cKey));
    }
    if (serverKey != NULL) {
        memcpy(serverKey, &sKey, sizeof(sKey));
    }
    OPENSSL_cleanse(&cKey, sizeof(cKey));
    OPENSSL_cleanse(&sKey, sizeof(sKey));
    return 0;
}

/** @brief Full exchange: client and server keys are *byte-identical*. */
static void testRoundtripDerivesSameKey(void) {
    AESGCMKey clientKey;
    AESGCMKey serverKey;
    ASSERT_INT_EQ(doFullRoundtrip(&clientKey, &serverKey), 0);
    ASSERT_MEM_EQ(serverKey.key, clientKey.key, AES_GCM_KEY_LEN);
    OPENSSL_cleanse(&clientKey, sizeof(clientKey));
    OPENSSL_cleanse(&serverKey, sizeof(serverKey));
}

/** @brief Derived AES key must not be all zeros. */
static void testExchangedKeyNonZero(void) {
    AESGCMKey clientKey;
    AESGCMKey serverKey;
    ASSERT_INT_EQ(doFullRoundtrip(&clientKey, &serverKey), 0);

    uint8_t zeros[AES_GCM_KEY_LEN];
    memset(zeros, 0, sizeof(zeros));
    ASSERT_TRUE(memcmp(clientKey.key, zeros, AES_GCM_KEY_LEN) != 0);
    ASSERT_TRUE(memcmp(serverKey.key, zeros, AES_GCM_KEY_LEN) != 0);

    OPENSSL_cleanse(&clientKey, sizeof(clientKey));
    OPENSSL_cleanse(&serverKey, sizeof(serverKey));
}

/** @brief After a successful exchange outKey->nonce is zeroed. */
static void testExchangedKeyNonceZeroed(void) {
    AESGCMKey clientKey;
    /* Pre-fill with non-zero to verify zeroing. */
    memset(&clientKey, FillByteB, sizeof(clientKey));
    AESGCMKey serverKey;
    ASSERT_INT_EQ(doFullRoundtrip(&clientKey, &serverKey), 0);

    uint8_t zeroNonce[AES_GCM_NONCE_LEN];
    memset(zeroNonce, 0, sizeof(zeroNonce));
    ASSERT_MEM_EQ(clientKey.nonce, zeroNonce, AES_GCM_NONCE_LEN);
    ASSERT_MEM_EQ(serverKey.nonce, zeroNonce, AES_GCM_NONCE_LEN);

    OPENSSL_cleanse(&clientKey, sizeof(clientKey));
    OPENSSL_cleanse(&serverKey, sizeof(serverKey));
}

/** @brief Two independent exchanges produce different AES keys. */
static void testKeyExchangeNonDeterministic(void) {
    AESGCMKey aClient;
    AESGCMKey aServer;
    AESGCMKey bClient;
    AESGCMKey bServer;
    ASSERT_INT_EQ(doFullRoundtrip(&aClient, &aServer), 0);
    ASSERT_INT_EQ(doFullRoundtrip(&bClient, &bServer), 0);

    /* Keys from different exchanges must differ. */
    ASSERT_TRUE(memcmp(aClient.key, bClient.key, AES_GCM_KEY_LEN) != 0);

    OPENSSL_cleanse(&aClient, sizeof(aClient));
    OPENSSL_cleanse(&aServer, sizeof(aServer));
    OPENSSL_cleanse(&bClient, sizeof(bClient));
    OPENSSL_cleanse(&bServer, sizeof(bServer));
}

/**
 * @brief The derived key is usable: encrypt with one side, decrypt with
 *        the other, plaintext must be *byte-identical*.
 */
static void testDerivedKeyEncryptDecrypt(void) {
    AESGCMKey clientKey;
    AESGCMKey serverKey;
    ASSERT_INT_EQ(doFullRoundtrip(&clientKey, &serverKey), 0);

    /* Set deterministic nonces for the test. */
    memcpy(clientKey.nonce, serverKey.nonce, AES_GCM_NONCE_LEN);

    size_t ptLen = sizeof(testMessage);
    AESGCMBuffer plaintext;
    plaintext.data = (uint8_t *)(uintptr_t)testMessage;
    plaintext.capacity = ptLen;
    plaintext.len = ptLen;

    AESGCMCipher cipher;
    ASSERT_INT_EQ(aesGCMBufferInit(&cipher.buffer, ptLen), CRYPTO_SUCC);

    /* Client encrypts. */
    ASSERT_INT_EQ(encryptAESGCM(&plaintext, NULL, &clientKey, &cipher),
                  CRYPTO_SUCC);

    /* Server decrypts. */
    AESGCMBuffer decrypted;
    ASSERT_INT_EQ(aesGCMBufferInit(&decrypted, cipher.buffer.len), CRYPTO_SUCC);
    ASSERT_INT_EQ(decryptAESGCM(&cipher, NULL, &serverKey, &decrypted),
                  CRYPTO_SUCC);
    ASSERT_UINT_EQ(decrypted.len, ptLen);
    ASSERT_MEM_EQ(decrypted.data, testMessage, ptLen);

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decrypted);
    OPENSSL_cleanse(&clientKey, sizeof(clientKey));
    OPENSSL_cleanse(&serverKey, sizeof(serverKey));
}

/* ════════════════ B2. client-side rejection helpers (fork) ════════════════ */

/**
 * @brief Fork a child running clientExchangeAESKey; the parent sends a
 *        hand-crafted response so the caller can test client-side validation.
 *
 * @param respMsgType  messageType of the fake server response.
 * @param respPktType  packetType of the fake server response.
 * @param respData     Payload bytes (may be NULL when @p respDataLen == 0).
 * @param respDataLen  Payload length, 0–MAX_PAYLOAD_LEN.
 * @return 0 if the child exited with success (clientExchangeAESKey returned
 *         COMM_SUCC), non-zero if the child indicated failure.
 */
static int runClientWithFakeResp(MessageType respMsgType,
                                 PacketType respPktType, const void *respData,
                                 size_t respDataLen) {
    SocketFD pair[SockLen];
    if (makePair(pair) != 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pair[SockA]);
        close(pair[SockB]);
        return -1;
    }

    if (pid == 0) {
        /* ───────────────────────────── child: client
         * ────────────────────────────── */
        close(pair[SockB]);
        AESGCMKey key;
        int ret = clientExchangeAESKey(pair[SockA], &key);
        close(pair[SockA]);
        _exit(ret == CommSucc ? 0 : 1);
    }

    /* ────────────────────────── parent: fake server
     * ─────────────────────────── */
    close(pair[SockA]);

    /* Discard the child's MsgKeyExchangeReq. */
    Packet discard;
    memset(&discard, 0, sizeof(discard));
    if (packetRecv(&discard, pair[SockB]) == PROTOCOL_SUCC) {
        packetClear(&discard);
    }

    /* Build and send the crafted (potentially invalid) response. */
    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (packetInit(&resp, respMsgType, 0, respPktType, respData, respDataLen) ==
        PROTOCOL_SUCC) {
        packetSend(&resp, pair[SockB]);
        packetClear(&resp);
    }

    close(pair[SockB]);

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

/* ─────────────── client rejects wrong response messageType ──────────────── */

static void testClientRejectsRespMsgTypeChat(void) {
    uint8_t dummyPub[Payload32];
    memset(dummyPub, FillByteA, sizeof(dummyPub));
    ASSERT_INT_EQ(
        runClientWithFakeResp(MsgChat, PlaintextPacket, dummyPub, Payload32),
        1);
}

static void testClientRejectsRespMsgTypeHeartbeat(void) {
    uint8_t dummyPub[Payload32];
    memset(dummyPub, FillByteA, sizeof(dummyPub));
    ASSERT_INT_EQ(runClientWithFakeResp(MsgHeartbeat, PlaintextPacket, dummyPub,
                                        Payload32),
                  1);
}

static void testClientRejectsRespMsgTypeLoginReq(void) {
    uint8_t dummyPub[Payload32];
    memset(dummyPub, FillByteA, sizeof(dummyPub));
    ASSERT_INT_EQ(runClientWithFakeResp(MsgLoginReq, PlaintextPacket, dummyPub,
                                        Payload32),
                  1);
}

/* ──────────────── client rejects wrong response packetType ──────────────── */

static void testClientRejectsRespPktTypeAES256(void) {
    uint8_t dummyPub[Payload32];
    memset(dummyPub, FillByteA, sizeof(dummyPub));
    ASSERT_INT_EQ(runClientWithFakeResp(MsgKeyExchangeResp, AES256GCMPacket,
                                        dummyPub, Payload32),
                  1);
}

/* ────────────── client rejects wrong response payloadLength ─────────────── */

static void testClientRejectsRespPayloadLenZero(void) {
    ASSERT_INT_EQ(
        runClientWithFakeResp(MsgKeyExchangeResp, PlaintextPacket, NULL, 0), 1);
}

static void testClientRejectsRespPayloadLenOne(void) {
    enum { OneByte = 1 };
    uint8_t oneBuf[OneByte];
    memset(oneBuf, FillByteA, sizeof(oneBuf));
    ASSERT_INT_EQ(runClientWithFakeResp(MsgKeyExchangeResp, PlaintextPacket,
                                        oneBuf, OneByte),
                  1);
}

static void testClientRejectsRespPayloadLenShort(void) {
    uint8_t buf[Payload31];
    memset(buf, FillByteA, sizeof(buf));
    ASSERT_INT_EQ(runClientWithFakeResp(MsgKeyExchangeResp, PlaintextPacket,
                                        buf, Payload31),
                  1);
}

static void testClientRejectsRespPayloadLenLong(void) {
    uint8_t buf[Payload33];
    memset(buf, FillByteA, sizeof(buf));
    ASSERT_INT_EQ(runClientWithFakeResp(MsgKeyExchangeResp, PlaintextPacket,
                                        buf, Payload33),
                  1);
}

static void testClientRejectsRespPayloadLenDouble(void) {
    uint8_t buf[Payload64];
    memset(buf, FillByteA, sizeof(buf));
    ASSERT_INT_EQ(runClientWithFakeResp(MsgKeyExchangeResp, PlaintextPacket,
                                        buf, Payload64),
                  1);
}

/* ═══════════════════════════ B3. Memory safety ════════════════════════════ */

/** @brief packetClear is idempotent — double-call must not crash. */
static void testDoublePacketClearSafe(void) {
    KeyExchangePacketPayload kp = makeKeyPayload(FillByteA);
    Packet pkt = makeRawPacket(PACKET_MAGIC, MsgKeyExchangeReq, PlaintextPacket,
                               Payload32, &kp);
    packetClear(&pkt);
    /* Second call on already-cleared packet — must be safe. */
    packetClear(&pkt);
    ASSERT_TRUE(pkt.payload == NULL);
}

/**
 * @brief After a successful full exchange, calling packetClear on a
 *        previously-received packet twice must not crash (double-free
 *        safety across communication boundaries).
 */
static void testDoublePacketClearAfterExchange(void) {
    SocketFD pair[SockLen];
    ASSERT_INT_EQ(makePair(pair), 0);

    int keyPipe[2];
    ASSERT_INT_EQ(pipe(keyPipe), 0);

    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);

    if (pid == 0) {
        close(pair[SockB]);
        close(keyPipe[0]);
        AESGCMKey key;
        int ret = clientExchangeAESKey(pair[SockA], &key);
        close(pair[SockA]);
        close(keyPipe[1]);
        _exit(ret == CommSucc ? 0 : 1);
    }

    close(pair[SockA]);
    close(keyPipe[1]);

    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetRecv(&req, pair[SockB]), PROTOCOL_SUCC);

    AESGCMKey sKey;
    ASSERT_INT_EQ(serverExchangeAESKey(pair[SockB], &req, &sKey), CommSucc);

    /* Already cleared inside serverExchangeAESKey (payload zeroed, not freed).
     * packetClear must be safe. */
    packetClear(&req);
    /* Double-clear — must not crash. */
    packetClear(&req);

    close(keyPipe[0]);
    close(pair[SockB]);
    OPENSSL_cleanse(&sKey, sizeof(sKey));

    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ═══════════════════ B4. clientRecvStatusResponse tests ═══════════════════ */

/** @brief clientRecvStatusResponse with NULL client returns -1. */
static void testClientRecvStatusNull(void) {
    ASSERT_INT_EQ(clientRecvStatusResponse(NULL, MsgLoginResp), -1);
}

/** @brief clientRecvStatusResponse: server with no response (closed connection)
 *  returns -1. */
static void testClientRecvStatusClosedConnection(void) {
    SocketFD pair[SockLen];
    ASSERT_INT_EQ(makePair(pair), 0);

    Client client;
    memset(&client, 0, sizeof(client));
    client.fd = pair[SockA];

    /* Close server side immediately */
    close(pair[SockB]);

    ASSERT_INT_EQ(clientRecvStatusResponse(&client, MsgLoginResp), -1);

    close(pair[SockA]);
}

/** @brief clientRecvStatusResponse: expected message type with status 0. */
static void testClientRecvStatusSuccess(void) {
    SocketFD pair[SockLen];
    ASSERT_INT_EQ(makePair(pair), 0);

    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);

    if (pid == 0) {
        close(pair[SockB]);
        AESGCMKey cKey;
        int ret = clientExchangeAESKey(pair[SockA], &cKey);
        if (ret != CommSucc) {
            _exit(1);
        }

        Client client;
        memset(&client, 0, sizeof(client));
        client.fd = pair[SockA];
        memcpy(client.aesKey.key, cKey.key, AES_GCM_KEY_LEN);
        client.seqID = 1;

        int status = clientRecvStatusResponse(&client, MsgLoginResp);
        close(pair[SockA]);
        _exit((status == 0) ? 0 : 1);
    }

    close(pair[SockA]);
    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetRecv(&req, pair[SockB]), PROTOCOL_SUCC);
    AESGCMKey sKey;
    ASSERT_INT_EQ(serverExchangeAESKey(pair[SockB], &req, &sKey), CommSucc);
    packetClear(&req);

    /* Send status 0 */
    uint32_t seq = 0;
    uint8_t statusOk = 0;
    ASSERT_INT_EQ(packetSendEncrypted(pair[SockB], MsgLoginResp, &seq,
                                      sKey.key, &statusOk, sizeof(statusOk)),
                  PROTOCOL_SUCC);

    close(pair[SockB]);
    OPENSSL_cleanse(&sKey, sizeof(sKey));

    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/** @brief clientRecvStatusResponse: expected message type with status 1. */
static void testClientRecvStatusFailure(void) {
    SocketFD pair[SockLen];
    ASSERT_INT_EQ(makePair(pair), 0);

    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);

    if (pid == 0) {
        close(pair[SockB]);
        AESGCMKey cKey;
        int ret = clientExchangeAESKey(pair[SockA], &cKey);
        if (ret != CommSucc) {
            _exit(1);
        }

        Client client;
        memset(&client, 0, sizeof(client));
        client.fd = pair[SockA];
        memcpy(client.aesKey.key, cKey.key, AES_GCM_KEY_LEN);
        client.seqID = 1;

        int status = clientRecvStatusResponse(&client, MsgCreateRoomResp);
        close(pair[SockA]);
        _exit((status == 1) ? 0 : 1);
    }

    close(pair[SockA]);
    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetRecv(&req, pair[SockB]), PROTOCOL_SUCC);
    AESGCMKey sKey;
    ASSERT_INT_EQ(serverExchangeAESKey(pair[SockB], &req, &sKey), CommSucc);
    packetClear(&req);

    uint32_t seq = 0;
    uint8_t statusFail = 1;
    ASSERT_INT_EQ(packetSendEncrypted(pair[SockB], MsgCreateRoomResp, &seq,
                                      sKey.key, &statusFail, sizeof(statusFail)),
                  PROTOCOL_SUCC);

    close(pair[SockB]);
    OPENSSL_cleanse(&sKey, sizeof(sKey));

    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/** @brief clientRecvStatusResponse: wrong message type on wire returns -1. */
static void testClientRecvStatusWrongMsgType(void) {
    SocketFD pair[SockLen];
    ASSERT_INT_EQ(makePair(pair), 0);

    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);

    if (pid == 0) {
        close(pair[SockB]);
        AESGCMKey cKey;
        int ret = clientExchangeAESKey(pair[SockA], &cKey);
        if (ret != CommSucc) {
            _exit(1);
        }

        Client client;
        memset(&client, 0, sizeof(client));
        client.fd = pair[SockA];
        memcpy(client.aesKey.key, cKey.key, AES_GCM_KEY_LEN);
        client.seqID = 1;

        /* Expect MsgLoginResp but server sends MsgChat */
        int status = clientRecvStatusResponse(&client, MsgLoginResp);
        close(pair[SockA]);
        _exit((status == -1) ? 0 : 1);
    }

    close(pair[SockA]);
    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetRecv(&req, pair[SockB]), PROTOCOL_SUCC);
    AESGCMKey sKey;
    ASSERT_INT_EQ(serverExchangeAESKey(pair[SockB], &req, &sKey), CommSucc);
    packetClear(&req);

    /* Send MsgChat with a single byte (wrong type) */
    uint32_t seq = 0;
    uint8_t dummy = 0;
    ASSERT_INT_EQ(packetSendEncrypted(pair[SockB], MsgChat, &seq, sKey.key,
                                      &dummy, sizeof(dummy)),
                  PROTOCOL_SUCC);

    close(pair[SockB]);
    OPENSSL_cleanse(&sKey, sizeof(sKey));

    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/** @brief clientRecvStatusResponse: zero-payload response returns -1. */
static void testClientRecvStatusZeroPayload(void) {
    SocketFD pair[SockLen];
    ASSERT_INT_EQ(makePair(pair), 0);

    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);

    if (pid == 0) {
        close(pair[SockB]);
        AESGCMKey cKey;
        int ret = clientExchangeAESKey(pair[SockA], &cKey);
        if (ret != CommSucc) {
            _exit(1);
        }

        Client client;
        memset(&client, 0, sizeof(client));
        client.fd = pair[SockA];
        memcpy(client.aesKey.key, cKey.key, AES_GCM_KEY_LEN);
        client.seqID = 1;

        int status = clientRecvStatusResponse(&client, MsgLoginResp);
        close(pair[SockA]);
        _exit((status == -1) ? 0 : 1);
    }

    close(pair[SockA]);
    Packet req;
    memset(&req, 0, sizeof(req));
    ASSERT_INT_EQ(packetRecv(&req, pair[SockB]), PROTOCOL_SUCC);
    AESGCMKey sKey;
    ASSERT_INT_EQ(serverExchangeAESKey(pair[SockB], &req, &sKey), CommSucc);
    packetClear(&req);

    /* Send MsgLoginResp with zero-length payload */
    uint32_t seq = 0;
    ASSERT_INT_EQ(packetSendEncrypted(pair[SockB], MsgLoginResp, &seq,
                                      sKey.key, NULL, 0),
                  PROTOCOL_SUCC);

    close(pair[SockB]);
    OPENSSL_cleanse(&sKey, sizeof(sKey));

    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* ═══════════════════════ serverSendEncryptedPacket ═══════════════════════ */

static void testServerSendEncryptedNullCS(void) {
    int ret = serverSendEncryptedPacket(NULL, MsgChat, "x", 1);
    ASSERT_INT_EQ(ret, SERVER_FAIL);
}

static void testServerSendEncryptedRoundtrip(void) {
    int pair[SockLen];
    makePair(pair);

    ClientSession cs = {0};
    cs.fd = pair[SockA];
    cryptoRandomBytes(cs.aesKey.key, AesKeyLen);
    cs.seqID = 0;

    const char *msg = "test";
    int ret = serverSendEncryptedPacket(&cs, MsgChat, msg, strlen(msg));
    ASSERT_INT_EQ(ret, SERVER_SUCC);

    Packet rx = {0};
    ASSERT_INT_EQ(packetRecvEncrypted(pair[SockB], &rx, cs.aesKey.key),
                  PROTOCOL_SUCC);
    ASSERT_UINT_EQ(rx.header.messageType, (uint32_t)MsgChat);
    ASSERT_UINT_EQ(rx.header.payloadLength, (uint32_t)strlen(msg));

    packetClear(&rx);
    socketClose(&pair[SockA]);
    socketClose(&pair[SockB]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
}

/* ═══════════════════════ serverRecvEncryptedPacket ═══════════════════════ */

static void testServerRecvEncryptedNullCS(void) {
    Packet out = {0};
    int ret = serverRecvEncryptedPacket(NULL, &out);
    ASSERT_INT_EQ(ret, SERVER_FAIL);
}

static void testServerRecvEncryptedNullOut(void) {
    int pair[SockLen];
    makePair(pair);

    ClientSession cs = {0};
    cs.fd = pair[SockA];
    cryptoRandomBytes(cs.aesKey.key, AesKeyLen);
    cs.seqID = 0;

    int ret = serverRecvEncryptedPacket(&cs, NULL);
    ASSERT_INT_EQ(ret, SERVER_FAIL);

    socketClose(&pair[SockA]);
    socketClose(&pair[SockB]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
}

/* ═══════════════════════ serverSendStatusResponse ════════════════════════ */

static void testServerSendStatusSuccess(void) {
    int pair[SockLen];
    makePair(pair);

    ClientSession cs = {0};
    cs.fd = pair[SockA];
    cryptoRandomBytes(cs.aesKey.key, AesKeyLen);
    cs.seqID = 0;

    int ret = serverSendStatusResponse(&cs, MsgLoginResp, 0);
    ASSERT_INT_EQ(ret, SERVER_SUCC);

    Packet rx = {0};
    ASSERT_INT_EQ(packetRecvEncrypted(pair[SockB], &rx, cs.aesKey.key),
                  PROTOCOL_SUCC);
    ASSERT_UINT_EQ(rx.header.payloadLength, 1);
    ASSERT_TRUE(rx.payload[0] == 0);

    packetClear(&rx);
    socketClose(&pair[SockA]);
    socketClose(&pair[SockB]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
}

static void testServerSendStatusFailure(void) {
    int pair[SockLen];
    makePair(pair);

    ClientSession cs = {0};
    cs.fd = pair[SockA];
    cryptoRandomBytes(cs.aesKey.key, AesKeyLen);
    cs.seqID = 0;

    int ret = serverSendStatusResponse(&cs, MsgLoginResp, 1);
    ASSERT_INT_EQ(ret, SERVER_SUCC);

    Packet rx = {0};
    ASSERT_INT_EQ(packetRecvEncrypted(pair[SockB], &rx, cs.aesKey.key),
                  PROTOCOL_SUCC);
    ASSERT_UINT_EQ(rx.header.payloadLength, 1);
    ASSERT_TRUE(rx.payload[0] == 1);

    packetClear(&rx);
    socketClose(&pair[SockA]);
    socketClose(&pair[SockB]);
    OPENSSL_cleanse(&cs.aesKey, sizeof(cs.aesKey));
}

/* ═══════════════════════ clientSendEncryptedPacket ═══════════════════════ */

static void testClientSendEncryptedNull(void) {
    int ret = clientSendEncryptedPacket(NULL, MsgChat, "x", 1);
    ASSERT_INT_EQ(ret, PROTOCOL_FAIL);
}

static void testClientSendEncryptedRoundtrip(void) {
    int pair[SockLen];
    makePair(pair);

    Client client = {0};
    client.fd = pair[SockA];
    cryptoRandomBytes(client.aesKey.key, AesKeyLen);
    client.seqID = 0;

    const char *msg = "roundtrip";
    int ret = clientSendEncryptedPacket(&client, MsgChat, msg, strlen(msg));
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    Packet rx = {0};
    ASSERT_INT_EQ(packetRecvEncrypted(pair[SockB], &rx, client.aesKey.key),
                  PROTOCOL_SUCC);
    ASSERT_UINT_EQ(rx.header.messageType, (uint32_t)MsgChat);
    ASSERT_UINT_EQ(rx.header.payloadLength, (uint32_t)strlen(msg));

    packetClear(&rx);
    socketClose(&pair[SockA]);
    socketClose(&pair[SockB]);
    OPENSSL_cleanse(&client.aesKey, sizeof(client.aesKey));
}

/* ═══════════════════════ clientRecvEncryptedPacket ═══════════════════════ */

static void testClientRecvEncryptedNullClient(void) {
    Packet out = {0};
    int ret = clientRecvEncryptedPacket(NULL, &out);
    ASSERT_INT_EQ(ret, PROTOCOL_FAIL);
}

static void testClientRecvEncryptedNullOut(void) {
    int pair[SockLen];
    makePair(pair);

    Client client = {0};
    client.fd = pair[SockA];
    cryptoRandomBytes(client.aesKey.key, AesKeyLen);
    client.seqID = 0;

    int ret = clientRecvEncryptedPacket(&client, NULL);
    ASSERT_INT_EQ(ret, PROTOCOL_FAIL);

    socketClose(&pair[SockA]);
    socketClose(&pair[SockB]);
    OPENSSL_cleanse(&client.aesKey, sizeof(client.aesKey));
}

/* ══════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    printf("test_communication:\n");

    RUN_TEST(testCommReturnCodes);

    RUN_TEST(testClientExchangeNullOutKey);
    RUN_TEST(testClientExchangeInvalidSocket);

    RUN_TEST(testServerNullReqPacket);
    RUN_TEST(testServerNullOutKey);
    RUN_TEST(testServerNullPayload);

    RUN_TEST(testServerMsgTypeLoginReq);
    RUN_TEST(testServerMsgTypeLoginResp);
    RUN_TEST(testServerMsgTypeChat);
    RUN_TEST(testServerMsgTypeHeartbeat);
    RUN_TEST(testServerMsgTypeKeyExResp);

    RUN_TEST(testServerPktTypeAES256GCM);
    RUN_TEST(testServerPktTypeZero);

    RUN_TEST(testServerPayloadLenZero);
    RUN_TEST(testServerPayloadLenOne);
    RUN_TEST(testServerPayloadLenShort);
    RUN_TEST(testServerPayloadLenLong);
    RUN_TEST(testServerPayloadLenDouble);
    RUN_TEST(testServerPayloadLenMax);

    RUN_TEST(testRoundtripDerivesSameKey);
    RUN_TEST(testExchangedKeyNonZero);
    RUN_TEST(testExchangedKeyNonceZeroed);
    RUN_TEST(testKeyExchangeNonDeterministic);
    RUN_TEST(testDerivedKeyEncryptDecrypt);

    RUN_TEST(testClientRejectsRespMsgTypeChat);
    RUN_TEST(testClientRejectsRespMsgTypeHeartbeat);
    RUN_TEST(testClientRejectsRespMsgTypeLoginReq);
    RUN_TEST(testClientRejectsRespPktTypeAES256);

    RUN_TEST(testClientRejectsRespPayloadLenZero);
    RUN_TEST(testClientRejectsRespPayloadLenOne);
    RUN_TEST(testClientRejectsRespPayloadLenShort);
    RUN_TEST(testClientRejectsRespPayloadLenLong);
    RUN_TEST(testClientRejectsRespPayloadLenDouble);

    RUN_TEST(testDoublePacketClearSafe);
    RUN_TEST(testDoublePacketClearAfterExchange);

    /* clientRecvStatusResponse edge cases */
    RUN_TEST(testClientRecvStatusNull);
    RUN_TEST(testClientRecvStatusClosedConnection);
    RUN_TEST(testClientRecvStatusSuccess);
    RUN_TEST(testClientRecvStatusFailure);
    RUN_TEST(testClientRecvStatusWrongMsgType);
    RUN_TEST(testClientRecvStatusZeroPayload);

    /* serverSendEncryptedPacket / serverRecvEncryptedPacket */
    RUN_TEST(testServerSendEncryptedNullCS);
    RUN_TEST(testServerSendEncryptedRoundtrip);
    RUN_TEST(testServerRecvEncryptedNullCS);
    RUN_TEST(testServerRecvEncryptedNullOut);

    /* serverSendStatusResponse */
    RUN_TEST(testServerSendStatusSuccess);
    RUN_TEST(testServerSendStatusFailure);

    /* clientSendEncryptedPacket / clientRecvEncryptedPacket */
    RUN_TEST(testClientSendEncryptedNull);
    RUN_TEST(testClientSendEncryptedRoundtrip);
    RUN_TEST(testClientRecvEncryptedNullClient);
    RUN_TEST(testClientRecvEncryptedNullOut);

    return TEST_REPORT();
}
