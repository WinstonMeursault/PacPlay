/**
 * @file server.c
 * @brief PacPlay server — event loop, session management, and request dispatch.
 *
 * @date 2026-05-25
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

#include "server.h"
#include "log.h"
#include "utils.h"
#include "server/database.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <openssl/crypto.h>

/* ──────── internal constants (avoiding magic numbers) ──────────────────── */

enum {
    StatusSuccess = 0,
    StatusFailure = 1,
    /* Login payload is username(32B) + password(FAM). */
    LoginHeaderSize = offsetof(LoginRequestPayload, password),
    /* Register payload is username(32B) + nickname(32B) + password(FAM). */
    RegisterHeaderSize = offsetof(RegisterRequestPayload, password)
};

/* ──────── forward declarations ─────────────────────────────────────────── */

static int sendEncryptedPacket(ClientSession *cs, MessageType mt,
                               const void *data, size_t dataLen);
static int sendStatusResp(ClientSession *cs, MessageType mt, uint8_t status);
static void acceptClient(Server *s);
static int  processClient(Server *s, ClientSession *cs);
static void clientDisconnect(Server *s, int idx);

/* Handler functions */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int handleKeyExchange(Server *s, ClientSession *cs, Packet *pkt);
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int handleLogin(Server *s, ClientSession *cs, Packet *pkt);
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int handleRegister(Server *s, ClientSession *cs, Packet *pkt);
static int handleRoomList(Server *s, ClientSession *cs);
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int handleRoomCreate(Server *s, ClientSession *cs, Packet *pkt);
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int handleRoomJoin(Server *s, ClientSession *cs, Packet *pkt);
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int handleChat(Server *s, ClientSession *cs, Packet *pkt);
static int handleHeartbeat(Server *s, ClientSession *cs);
static int handleLogout(Server *s, ClientSession *cs);

/* Room helpers */
static ActiveRoom *findActiveRoom(const Server *s, uint32_t roomId);
static ActiveRoom *getOrCreateActiveRoom(Server *s, uint32_t roomId);
static void removeActiveRoom(Server *s, uint32_t roomId);
static void removeClientFromRoom(Server *s, ClientSession *cs);
static void broadcastToRoom(Server *s, uint32_t roomId, ClientSession *sender,
                            uint32_t uid, uint64_t msgId, int64_t timestamp,
                            const uint8_t *message, size_t msgLen);

/* ═══════════════════════  public API  ════════════════════════════════════ */

int serverInit(Server *server, uint16_t port) {
    SocketFD listenFd = serverSetup(port);
    if (listenFd == NULL_SOCKETFD) {
        return SERVER_FAIL;
    }

    DB *userDB = dbInit(UserDB);
    DB *chatDB = dbInit(ChatHistoryDB);
    DB *gameDB = dbInit(GameDB);
    if (userDB == NULL || chatDB == NULL || gameDB == NULL) {
        LOG_ERROR("serverInit: database initialization failed");
        dbClose(userDB);
        dbClose(chatDB);
        dbClose(gameDB);
        socketClose(&listenFd);
        return SERVER_FAIL;
    }

    server->listenFd = listenFd;
    server->userDB = userDB;
    server->chatDB = chatDB;
    server->gameDB = gameDB;

    server->clientCapacity = SERVER_INITIAL_CAPACITY;
    server->clients = (ClientSession **)calloc(
        (size_t)server->clientCapacity, sizeof(ClientSession *));
    if (server->clients == NULL) {
        LOG_ERROR("serverInit: calloc failed (errno=%d)", errno);
        serverCleanup(server);
        return SERVER_FAIL;
    }

    server->activeRoomCapacity = SERVER_INITIAL_CAPACITY;
    server->activeRooms = (ActiveRoom **)calloc(
        (size_t)server->activeRoomCapacity, sizeof(ActiveRoom *));
    if (server->activeRooms == NULL) {
        LOG_ERROR("serverInit: calloc rooms failed (errno=%d)", errno);
        serverCleanup(server);
        return SERVER_FAIL;
    }

    LOG_INFO("Server listening on port %u", (unsigned int)port);
    return SERVER_SUCC;
}

void serverRun(Server *s) {
    for (;;) {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(s->listenFd, &readFds);
        int maxFd = s->listenFd;

        for (int i = 0; i < s->clientCount; i++) {
            FD_SET(s->clients[i]->fd, &readFds);
            if (s->clients[i]->fd > maxFd) {
                maxFd = s->clients[i]->fd;
            }
        }

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = SERVER_SELECT_TIMEOUT_US;

        int ready = select(maxFd + 1, &readFds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("serverRun: select() failed (errno=%d)", errno);
            break;
        }

        /* Accept new connections */
        if (FD_ISSET(s->listenFd, &readFds)) {
            acceptClient(s);
            ready--;
        }

        /* Process each client that has data pending */
        for (int i = 0; i < s->clientCount && ready > 0; i++) {
            if (FD_ISSET(s->clients[i]->fd, &readFds)) {
                ready--;
                if (processClient(s, s->clients[i]) != SERVER_SUCC) {
                    clientDisconnect(s, i);
                    i--; /* Reprocess index shifted by memmove */
                }
            }
        }

        /* Future: tick game rooms here when games are implemented */
    }
}

void serverCleanup(Server *server) {
    if (server == NULL) {
        return;
    }

    /* Disconnect all clients (removes them from rooms and closes sockets) */
    while (server->clientCount > 0) {
        clientDisconnect(server, 0);
    }
    free((void *)server->clients);
    server->clients = NULL;

    /* Free active rooms (rooms should be empty by now, but be safe) */
    if (server->activeRooms != NULL) {
        for (int i = 0; i < server->activeRoomCount; i++) {
            free(server->activeRooms[i]);
        }
        free((void *)server->activeRooms);
        server->activeRooms = NULL;
    }

    socketClose(&server->listenFd);
    dbClose(server->userDB);
    dbClose(server->chatDB);
    dbClose(server->gameDB);

    LOG_INFO("Server shut down");
}

/* ═══════════════════════  connection lifecycle  ══════════════════════════ */

static void acceptClient(Server *s) {
    SocketFD clientFd = accept(s->listenFd, NULL, NULL);
    if (clientFd == NULL_SOCKETFD) {
        LOG_ERROR("accept failed (errno=%d)", errno);
        return;
    }

    /* FD_SETSIZE protection: reject connections that would overflow fd_set */
    if (clientFd >= FD_SETSIZE) {
        LOG_WARN("acceptClient: fd %d >= FD_SETSIZE (%d), rejecting",
                 clientFd, FD_SETSIZE);
        socketClose(&clientFd);
        return;
    }

    ClientSession *cs = calloc(1, sizeof(ClientSession));
    if (cs == NULL) {
        LOG_ERROR("acceptClient: calloc failed (errno=%d)", errno);
        socketClose(&clientFd);
        return;
    }

    cs->fd = clientFd;
    cs->state = SessionKeyExchange;

    /* Grow the clients array if needed */
    if (s->clientCount >= s->clientCapacity) {
        int newCap = s->clientCapacity * 2;
        ClientSession **tmp =
            (ClientSession **)realloc((void *)s->clients,
                                      (size_t)newCap * sizeof(ClientSession *));
        if (tmp == NULL) {
            LOG_ERROR("acceptClient: realloc failed (errno=%d)", errno);
            free(cs);
            socketClose(&clientFd);
            return;
        }
        s->clients = tmp;
        s->clientCapacity = newCap;
    }

    s->clients[s->clientCount] = cs;
    s->clientCount++;
    LOG_INFO("Client connected (fd=%d)", clientFd);
}

static void clientDisconnect(Server *s, int idx) {
    if (s->clients == NULL || idx < 0 || idx >= s->clientCount) {
        return;
    }
    ClientSession *cs = s->clients[idx];

    LOG_INFO("Client disconnected (fd=%d)", cs->fd);

    /* Remove from room first so empty rooms are cleaned up */
    removeClientFromRoom(s, cs);

    socketClose(&cs->fd);
    OPENSSL_cleanse(&cs->aesKey, sizeof(cs->aesKey));
    free(cs);

    /* Compact the clients array */
    int remaining = s->clientCount - idx - 1;
    if (remaining > 0) {
        memmove((void *)&s->clients[idx], (const void *)&s->clients[idx + 1],
                (size_t)remaining * sizeof(ClientSession *));
    }
    s->clientCount--;
}

/* ═══════════════════════  packet I/O helpers  ════════════════════════════ */

/**
 * @brief Build, encrypt, and send a packet on the session's socket.
 *
 * Increments cs->seqID after construction.
 */
static int sendEncryptedPacket(ClientSession *cs, MessageType mt,
                               const void *data, size_t dataLen) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    if (packetInit(&pkt, mt, cs->seqID, PlaintextPacket, data, dataLen) !=
        PROTOCOL_SUCC) {
        return SERVER_FAIL;
    }

    if (packetAESEncrypt(&pkt, cs->aesKey.key) != PROTOCOL_SUCC) {
        packetClear(&pkt);
        return SERVER_FAIL;
    }

    cs->seqID++;

    int ret = packetSend(&pkt, cs->fd);
    packetClear(&pkt);
    return (ret == PROTOCOL_SUCC) ? SERVER_SUCC : SERVER_FAIL;
}

/**
 * @brief Send a single-byte status response (e.g. 0=SUCC, 1=FAIL).
 */
static int sendStatusResp(ClientSession *cs, MessageType mt, uint8_t status) {
    return sendEncryptedPacket(cs, mt, &status, sizeof(status));
}

/* ═══════════════════════  receive & dispatch  ════════════════════════════ */

static int processClient(Server *s, ClientSession *cs) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    if (packetRecv(&pkt, cs->fd) != PROTOCOL_SUCC) {
        LOG_WARN("processClient: packetRecv failed for fd=%d", cs->fd);
        return SERVER_FAIL;
    }

    /* After key exchange all further packets must be encrypted */
    if (cs->state != SessionKeyExchange) {
        if (pkt.header.packetType != AES256GCMPacket) {
            LOG_WARN("processClient: unencrypted packet from fd=%d in state=%d",
                     cs->fd, cs->state);
            packetClear(&pkt);
            return SERVER_FAIL;
        }
        if (packetAESDecrypt(&pkt, cs->aesKey.key) != PROTOCOL_SUCC) {
            LOG_WARN("processClient: AES decrypt failed for fd=%d", cs->fd);
            packetClear(&pkt);
            return SERVER_FAIL;
        }
    }

    int ret = SERVER_SUCC;
    MessageType mt = pkt.header.messageType;

    switch (cs->state) {
    case SessionKeyExchange:
        if (mt == MsgKeyExchangeReq) {
            ret = handleKeyExchange(s, cs, &pkt);
        } else {
            LOG_WARN("processClient: unexpected msgType %d in state %d (fd=%d)",
                     (int)mt, cs->state, cs->fd);
            ret = SERVER_FAIL;
        }
        break;

    case SessionLogin:
        if (mt == MsgLoginReq) {
            ret = handleLogin(s, cs, &pkt);
        } else if (mt == MsgRegisterReq) {
            ret = handleRegister(s, cs, &pkt);
        } else if (mt == MsgLogout) {
            ret = handleLogout(s, cs);
        } else {
            LOG_WARN("processClient: unexpected msgType %d in state %d (fd=%d)",
                     (int)mt, cs->state, cs->fd);
            ret = SERVER_FAIL;
        }
        break;

    case SessionRoom:
        if (mt == MsgRoomListReq) {
            ret = handleRoomList(s, cs);
        } else if (mt == MsgCreateRoom) {
            ret = handleRoomCreate(s, cs, &pkt);
        } else if (mt == MsgJoinRoom) {
            ret = handleRoomJoin(s, cs, &pkt);
        } else if (mt == MsgLogout) {
            ret = handleLogout(s, cs);
        } else {
            LOG_WARN("processClient: unexpected msgType %d in state %d (fd=%d)",
                     (int)mt, cs->state, cs->fd);
            ret = SERVER_FAIL;
        }
        break;

    case SessionChat:
        if (mt == MsgChat) {
            ret = handleChat(s, cs, &pkt);
        } else if (mt == MsgHeartbeat) {
            ret = handleHeartbeat(s, cs);
        } else if (mt == MsgLogout) {
            ret = handleLogout(s, cs);
        } else {
            LOG_WARN("processClient: unexpected msgType %d in state %d (fd=%d)",
                     (int)mt, cs->state, cs->fd);
            ret = SERVER_FAIL;
        }
        break;
    }

    packetClear(&pkt);
    return ret;
}

/* ═══════════════════════  handlers  ══════════════════════════════════════ */

static int handleKeyExchange(Server *s, ClientSession *cs, Packet *pkt) {
    (void)s;
    AESGCMKey aesKey;

    if (serverExchangeAESKey(cs->fd, pkt, &aesKey) != COMM_SUCC) {
        LOG_WARN("handleKeyExchange: exchange failed for fd=%d", cs->fd);
        return SERVER_FAIL;
    }

    memcpy(&cs->aesKey, &aesKey, sizeof(aesKey));
    OPENSSL_cleanse(&aesKey, sizeof(aesKey));
    cs->state = SessionLogin;
    LOG_INFO("Key exchange complete for fd=%d", cs->fd);
    return SERVER_SUCC;
}

static int handleLogin(Server *s, ClientSession *cs, Packet *pkt) {
    /* LoginRequestPayload minimum size: username(32) + at least one password
     * byte */
    enum { MinLoginPayload = LoginHeaderSize + 1 };

    if (pkt->header.payloadLength < MinLoginPayload) {
        LOG_WARN("handleLogin: payload too small (%u bytes)",
                 pkt->header.payloadLength);
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEncryptedPacket(cs, MsgLoginResp, &failResp, sizeof(failResp));
        return SERVER_SUCC;
    }

    LoginRequestPayload *login = (LoginRequestPayload *)pkt->payload;

    /* Verify username is NUL-terminated within bounds */
    if (login->username[LOGIN_USERNAME_LEN - 1] != '\0') {
        LOG_WARN("handleLogin: username not NUL-terminated");
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEncryptedPacket(cs, MsgLoginResp, &failResp, sizeof(failResp));
        return SERVER_SUCC;
    }

    /* Ensure password is NUL-terminated within the payload */
    size_t pwLen = pkt->header.payloadLength - LoginHeaderSize;
    if (memchr(login->password, '\0', pwLen) == NULL) {
        LOG_WARN("handleLogin: password not NUL-terminated within payload");
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEncryptedPacket(cs, MsgLoginResp, &failResp, sizeof(failResp));
        return SERVER_SUCC;
    }

    User user;
    memset(&user, 0, sizeof(user));
    memcpy(user.username, login->username, USERNAME_MAX_LEN);
    /* nickname is not sent in login request — verifyUser fills it from DB. */
    user.password = strdup(login->password);
    if (user.password == NULL) {
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEncryptedPacket(cs, MsgLoginResp, &failResp, sizeof(failResp));
        return SERVER_SUCC;
    }

    int dbRet = verifyUser(s->userDB, &user);
    OPENSSL_cleanse(user.password, strlen(user.password));
    free(user.password);

    if (dbRet != DB_SUCC) {
        LoginResponsePayload failResp;
        memset(&failResp, 0, sizeof(failResp));
        sendEncryptedPacket(cs, MsgLoginResp, &failResp, sizeof(failResp));
        LOG_INFO("Login failed for username=%s", user.username);
        return SERVER_SUCC;
    }

    /* Login successful — store user identity (clear password pointer).
     * uid and nickname are populated by verifyUser(). */
    memcpy(cs->currentUser.username, user.username, USERNAME_MAX_LEN);
    memcpy(cs->currentUser.nickname, user.nickname, NICKNAME_MAX_LEN);
    cs->currentUser.uid = user.uid;
    cs->currentUser.password = NULL;
    cs->state = SessionRoom;

    LoginResponsePayload succResp;
    memset(&succResp, 0, sizeof(succResp));
    succResp.uid = user.uid;
    memcpy(succResp.username, user.username, LOGIN_USERNAME_LEN);
    memcpy(succResp.nickname, user.nickname, LOGIN_NICKNAME_LEN);
    sendEncryptedPacket(cs, MsgLoginResp, &succResp, sizeof(succResp));
    LOG_INFO("User %u (%s) logged in on fd=%d", user.uid, user.username,
             cs->fd);
    return SERVER_SUCC;
}

static int handleRegister(Server *s, ClientSession *cs, Packet *pkt) {
    /* RegisterRequestPayload minimum size: username(32) + nickname(32) + at
     * least one password byte */
    enum { MinRegisterPayload = RegisterHeaderSize + 1 };

    if (pkt->header.payloadLength < MinRegisterPayload) {
        LOG_WARN("handleRegister: payload too small (%u bytes)",
                 pkt->header.payloadLength);
        sendStatusResp(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }

    RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt->payload;

    if (reg->username[LOGIN_USERNAME_LEN - 1] != '\0') {
        LOG_WARN("handleRegister: username not NUL-terminated");
        sendStatusResp(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }

    /* Verify nickname is NUL-terminated within bounds */
    if (reg->nickname[LOGIN_NICKNAME_LEN - 1] != '\0') {
        LOG_WARN("handleRegister: nickname not NUL-terminated");
        sendStatusResp(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }

    size_t pwLen = pkt->header.payloadLength - RegisterHeaderSize;
    if (memchr(reg->password, '\0', pwLen) == NULL) {
        LOG_WARN("handleRegister: password not NUL-terminated within payload");
        sendStatusResp(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }

    User user;
    memset(&user, 0, sizeof(user));
    memcpy(user.username, reg->username, USERNAME_MAX_LEN);
    memcpy(user.nickname, reg->nickname, NICKNAME_MAX_LEN);
    /* uid is server-assigned by createUser(). */
    user.password = strdup(reg->password);
    if (user.password == NULL) {
        sendStatusResp(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }

    int dbRet = createUser(s->userDB, &user);
    OPENSSL_cleanse(user.password, strlen(user.password));
    free(user.password);

    if (dbRet != DB_SUCC) {
        sendStatusResp(cs, MsgRegisterResp, StatusFailure);
        LOG_INFO("Registration failed for username=%s", user.username);
        return SERVER_SUCC;
    }

    sendStatusResp(cs, MsgRegisterResp, StatusSuccess);
    LOG_INFO("User %u (%s) registered on fd=%d", user.uid, user.username,
             cs->fd);
    return SERVER_SUCC;
}

static int handleRoomList(Server *s, ClientSession *cs) {
    uint32_t *roomIds = NULL;
    size_t count = 0;

    if (listRooms(s->gameDB, &roomIds, &count) != DB_SUCC) {
        /* Send empty list on error */
        sendEncryptedPacket(cs, MsgRoomListResp, NULL, 0);
        return SERVER_SUCC;
    }

    int ret = sendEncryptedPacket(cs, MsgRoomListResp, roomIds,
                                  count * sizeof(uint32_t));
    free(roomIds);
    return (ret == SERVER_SUCC) ? SERVER_SUCC : SERVER_FAIL;
}

static int handleRoomCreate(Server *s, ClientSession *cs, Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(uint32_t)) {
        LOG_WARN("handleRoomCreate: invalid payload size %u",
                 pkt->header.payloadLength);
        sendStatusResp(cs, MsgCreateRoomResp, StatusFailure);
        return SERVER_SUCC;
    }

    uint32_t roomId = *(uint32_t *)pkt->payload;

    if (createRoom(s->gameDB, roomId, cs->currentUser.uid) != DB_SUCC) {
        sendStatusResp(cs, MsgCreateRoomResp, StatusFailure);
        return SERVER_SUCC;
    }

    sendStatusResp(cs, MsgCreateRoomResp, StatusSuccess);
    LOG_INFO("Room %u created by uid=%u", roomId, cs->currentUser.uid);
    return SERVER_SUCC;
}

static int handleRoomJoin(Server *s, ClientSession *cs, Packet *pkt) {
    if (pkt->header.payloadLength != sizeof(uint32_t)) {
        LOG_WARN("handleRoomJoin: invalid payload size %u",
                 pkt->header.payloadLength);
        sendStatusResp(cs, MsgJoinRoomResp, StatusFailure);
        return SERVER_SUCC;
    }

    uint32_t roomId = *(uint32_t *)pkt->payload;

    /* Verify the room exists in the persistent GameDB */
    if (roomExists(s->gameDB, roomId) != DB_SUCC) {
        sendStatusResp(cs, MsgJoinRoomResp, StatusFailure);
        LOG_INFO("handleRoomJoin: room %u does not exist", roomId);
        return SERVER_SUCC;
    }

    /* Leave current room if any */
    if (cs->currentRoomId != 0) {
        removeClientFromRoom(s, cs);
    }

    ActiveRoom *room = getOrCreateActiveRoom(s, roomId);
    if (room == NULL) {
        sendStatusResp(cs, MsgJoinRoomResp, StatusFailure);
        return SERVER_SUCC;
    }

    if (room->memberCount >= MAX_CLIENTS_PER_ROOM) {
        sendStatusResp(cs, MsgJoinRoomResp, StatusFailure);
        LOG_INFO("handleRoomJoin: room %u is full", roomId);
        return SERVER_SUCC;
    }

    room->members[room->memberCount] = cs;
    room->memberCount++;
    cs->currentRoomId = roomId;
    cs->state = SessionChat;

    sendStatusResp(cs, MsgJoinRoomResp, StatusSuccess);
    LOG_INFO("User %u joined room %u (fd=%d)", cs->currentUser.uid, roomId,
             cs->fd);
    return SERVER_SUCC;
}

static int handleChat(Server *s, ClientSession *cs, Packet *pkt) {
    /* Minimum: timestamp (int64_t = 8 bytes) */
    if (pkt->header.payloadLength < sizeof(int64_t)) {
        LOG_WARN("handleChat: payload too small (%u bytes)",
                 pkt->header.payloadLength);
        return SERVER_FAIL;
    }

    ChatPacketPayload *chat = (ChatPacketPayload *)pkt->payload;
    size_t msgLen = pkt->header.payloadLength - sizeof(int64_t);

    /* Ensure NUL-terminated within bounds */
    if (msgLen == 0 ||
        memchr(chat->message, '\0', msgLen) == NULL) {
        LOG_WARN("handleChat: message not NUL-terminated or empty");
        return SERVER_FAIL;
    }

    /* Store in ChatHistoryDB */
    Chat ch;
    memset(&ch, 0, sizeof(ch));
    ch.uid = cs->currentUser.uid;
    ch.message = strdup((const char *)chat->message);
    if (ch.message == NULL) {
        return SERVER_FAIL;
    }
    ch.timestamp = (time_t)chat->timestamp;

    if (storeChat(s->chatDB, cs->currentRoomId, &ch) != DB_SUCC) {
        LOG_WARN("handleChat: storeChat failed");
        free(ch.message);
        return SERVER_FAIL;
    }

    /* Broadcast to all other members of the room */
    broadcastToRoom(s, cs->currentRoomId, cs, ch.uid, ch.msgId, ch.timestamp,
                    chat->message, msgLen);

    free(ch.message);
    return SERVER_SUCC;
}

static int handleHeartbeat(Server *s, ClientSession *cs) {
    (void)s;
    return sendEncryptedPacket(cs, MsgHeartbeat, NULL, 0);
}

static int handleLogout(Server *s, ClientSession *cs) {
    (void)s;
    LOG_INFO("User logging out (fd=%d)", cs->fd);
    return SERVER_FAIL; /* Signal to disconnect */
}

/* ═══════════════════════  room helpers  ══════════════════════════════════ */

static ActiveRoom *findActiveRoom(const Server *s, uint32_t roomId) {
    for (int i = 0; i < s->activeRoomCount; i++) {
        if (s->activeRooms[i]->roomId == roomId) {
            return s->activeRooms[i];
        }
    }
    return NULL;
}

static ActiveRoom *getOrCreateActiveRoom(Server *s, uint32_t roomId) {
    ActiveRoom *room = findActiveRoom(s, roomId);
    if (room != NULL) {
        return room;
    }

    /* Grow the rooms array if needed */
    if (s->activeRoomCount >= s->activeRoomCapacity) {
        int newCap = s->activeRoomCapacity * 2;
        ActiveRoom **tmp =
            (ActiveRoom **)realloc((void *)s->activeRooms,
                                   (size_t)newCap * sizeof(ActiveRoom *));
        if (tmp == NULL) {
            LOG_ERROR("getOrCreateActiveRoom: realloc failed (errno=%d)",
                      errno);
            return NULL;
        }
        s->activeRooms = tmp;
        s->activeRoomCapacity = newCap;
    }

    room = calloc(1, sizeof(ActiveRoom));
    if (room == NULL) {
        LOG_ERROR("getOrCreateActiveRoom: calloc failed (errno=%d)", errno);
        return NULL;
    }

    room->roomId = roomId;
    s->activeRooms[s->activeRoomCount] = room;
    s->activeRoomCount++;

    return room;
}

static void removeActiveRoom(Server *s, uint32_t roomId) {
    for (int i = 0; i < s->activeRoomCount; i++) {
        if (s->activeRooms[i]->roomId == roomId) {
            free(s->activeRooms[i]);
            int remaining = s->activeRoomCount - i - 1;
            if (remaining > 0) {
                memmove((void *)&s->activeRooms[i],
                        (const void *)&s->activeRooms[i + 1],
                        (size_t)remaining * sizeof(ActiveRoom *));
            }
            s->activeRoomCount--;
            return;
        }
    }
}

static void removeClientFromRoom(Server *s, ClientSession *cs) {
    if (cs->currentRoomId == 0) {
        return;
    }

    ActiveRoom *room = findActiveRoom(s, cs->currentRoomId);
    if (room == NULL) {
        cs->currentRoomId = 0;
        return;
    }

    for (int i = 0; i < room->memberCount; i++) {
        if (room->members[i] == cs) {
            int remaining = room->memberCount - i - 1;
            if (remaining > 0) {
                memmove((void *)&room->members[i],
                        (const void *)&room->members[i + 1],
                        (size_t)remaining * sizeof(ClientSession *));
            }
            room->memberCount--;
            break;
        }
    }

    cs->currentRoomId = 0;

    /* Remove empty room */
    if (room->memberCount == 0) {
        removeActiveRoom(s, room->roomId);
    }
}

static void broadcastToRoom(Server *s, uint32_t roomId, ClientSession *sender,
                            uint32_t uid, uint64_t msgId, int64_t timestamp, // NOLINT(bugprone-easily-swappable-parameters)
                            const uint8_t *message, size_t msgLen) {
    ActiveRoom *room = findActiveRoom(s, roomId);
    if (room == NULL) {
        return;
    }

    /* Build a ChatBroadcastPayload on the heap so the struct layout is
     * always consistent with the wire format (no manual memcpy offsets). */
    _Static_assert(offsetof(ChatBroadcastPayload, message) ==
                       sizeof(uint32_t) + sizeof(uint64_t) + sizeof(int64_t),
                   "ChatBroadcastPayload layout mismatch");
    size_t bcLen = offsetof(ChatBroadcastPayload, message) + msgLen;
    ChatBroadcastPayload *bc = malloc(bcLen);
    if (bc == NULL) {
        LOG_ERROR("broadcastToRoom: malloc failed (errno=%d)", errno);
        return;
    }

    bc->uid = uid;
    bc->msgId = msgId;
    bc->timestamp = timestamp;
    memcpy(bc->message, message, msgLen);

    for (int i = 0; i < room->memberCount; i++) {
        ClientSession *member = room->members[i];
        if (member == sender) {
            continue;
        }
        sendEncryptedPacket(member, MsgChat, bc, bcLen);
    }

    free(bc);
}
