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
#include "platform.h"
#include "server/auth.h"
#include "server/chat.h"
#include "server/communication.h"
#include "server/database.h"
#include "server/gameControl.h"
#include "server/keyManager.h"
#include "server/room.h"
#include "server/tui/serverTUI.h"
#include "serverLog.h"
#include "utils.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <openssl/crypto.h>

/* ────────────── internal constants (avoiding magic numbers) ─────────────── */

enum {
    StatusSuccess = 0,
    StatusFailure = 1,
    /* Login payload is username(32B) + password(FAM). */
    LoginHeaderSize = offsetof(LoginRequestPayload, password),
    /* Register payload is username(32B) + nickname(32B) + password(FAM). */
    RegisterHeaderSize = offsetof(RegisterRequestPayload, password)
};

/* ────────────────── signal-based graceful shutdown ──────────────────────── */

static volatile sig_atomic_t gShutdownRequested;

static void shutdownSignalHandler(int sig) {
    (void)sig;
    gShutdownRequested = 1;
}

/* ────────────────────────── forward declarations ────────────────────────── */

static void *serverEventLoop(void *arg);
static void acceptClient(Server *s);
static int processClient(Server *s, ClientSession *cs);
static void clientDisconnect(Server *s, int idx);

/* Handler functions */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int handleKeyExchange(Server *s, ClientSession *cs, Packet *pkt);
static int handleHeartbeat(Server *s, ClientSession *cs);
static int handleLogout(Server *s, ClientSession *cs);

/* ════════════════════════════ server key init ═════════════════════════════ */

/**
 * @brief Encrypt a key with MK via AES-256-GCM and store the envelope
 *        in ServerDB under @p keyName.
 *
 * The envelope format is: nonce(12) || ciphertext(32) || tag(16) = 60 bytes.
 *
 * @param mkKey     32-byte Master Key.
 * @param keyData   32-byte key to encrypt and store.
 * @param keyName   ServerDB key name (e.g. "DEK", "UserDBKey").
 * @param serverDB  Open ServerDB handle.
 * @return @c SERVER_SUCC or @c SERVER_FAIL.
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)

/**
 * @brief Decrypt a key envelope blob from ServerDB and load it into
 *        @p outKey.
 *
 * Verifies the envelope is exactly 60 bytes (nonce + key + tag), decrypts
 * it with @p mkKey via AES-256-GCM, and copies the plaintext key to
 * @p outKey.
 *
 * @param mkKey    32-byte Master Key.
 * @param blob     Raw envelope blob from ServerDB.
 * @param blobLen  Length of @p blob in bytes (must be 60).
 * @param keyName  Key name for error messages.
 * @param outKey   Output buffer (must be at least 32 bytes).
 * @return @c SERVER_SUCC or @c SERVER_FAIL (including AUTH_FAIL).
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)

/* ═══════════════════════════════ public API ═══════════════════════════════ */

int serverInit(Server *server, uint16_t port) {
    (void)serverLogInit();

    SocketFD listenFd = serverSetup(port);
    if (listenFd == NULL_SOCKETFD) {
        return SERVER_FAIL;
    }

    DB *serverDB = dbInit(ServerDB, NULL);
    if (serverDB == NULL) {
        LOG_ERROR("serverInit: ServerDB initialization failed");
        socketClose(&listenFd);
        return SERVER_FAIL;
    }

    server->listenFd = listenFd;
    server->serverDB = serverDB;

    bool firstRun = serverIsFirstRun(server);
    char *mkHex = NULL;
    if (firstRun) {
        mkHex = serverGenerateFreshKeys(server);
        if (mkHex == NULL) {
            LOG_ERROR("serverInit: key generation failed");
            serverCleanup(server);
            return SERVER_FAIL;
        }
    } else {
        if (!serverKeysAreComplete(server)) {
            LOG_FATAL("serverInit: ServerDB key set is incomplete");
        }
    }
    tuiServerEntry(server, firstRun, mkHex);
    free(mkHex);

    return SERVER_SUCC;
}

int serverLaunch(Server *server) {
    if (server->freshKeysGenerated) {
        remove(USER_DB_PATH);
        remove(CHAT_HISTORY_DB_PATH);
        remove(ROOM_DB_PATH);
        remove(GAME_DB_PATH);
    }

    DB *userDB = dbInit(UserDB, server->userDbEncKey);
    DB *chatDB = dbInit(ChatHistoryDB, server->chatDbEncKey);
    DB *roomDB = dbInit(RoomDB, server->roomDbEncKey);
    DB *gameDB = dbInit(GameDB, server->gameDbEncKey);
    if (userDB == NULL || chatDB == NULL || roomDB == NULL ||
        gameDB == NULL) {
        LOG_ERROR("serverLaunch: encrypted database initialization failed");
        return SERVER_FAIL;
    }

    server->userDB = userDB;
    server->chatDB = chatDB;
    server->roomDB = roomDB;
    server->gameDB = gameDB;

    dbSetDekKey(server->userDB, server->dekKey);

    platformMkdirp(GAME_LIB_DIR);

    server->clientCapacity = SERVER_INITIAL_CAPACITY;
    server->clients = (ClientSession **)calloc((size_t)server->clientCapacity,
                                               sizeof(ClientSession *));
    if (server->clients == NULL) {
        LOG_ERROR("serverLaunch: calloc failed (errno=%d)", errno);
        return SERVER_FAIL;
    }

    server->activeRoomCapacity = SERVER_INITIAL_CAPACITY;
    server->activeRooms = (ActiveRoom **)calloc(
        (size_t)server->activeRoomCapacity, sizeof(ActiveRoom *));
    if (server->activeRooms == NULL) {
        LOG_ERROR("serverLaunch: calloc rooms failed (errno=%d)", errno);
        return SERVER_FAIL;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = shutdownSignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);

    server->running = true;
    server->startTime = getCurrentTimestamp();
    if (pthread_create(&server->serverThread, NULL, serverEventLoop, server) !=
        0) {
        LOG_ERROR("serverLaunch: pthread_create failed (errno=%d)", errno);
        server->running = false;
        return SERVER_FAIL;
    }

    LOG_INFO("Server event loop started");
    return SERVER_SUCC;
}

void serverShutdown(Server *server) {
    if (!server->running) {
        return;
    }
    server->running = false;
    pthread_join(server->serverThread, NULL);
}

void serverRun(Server *server) { (void)server; }

/* ═════════════════════════ background event loop ═════════════════════════ */

static void *serverEventLoop(void *arg) {
    Server *s = (Server *)arg;

    while (s->running && !gShutdownRequested) {
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
            LOG_ERROR("serverEventLoop: select() failed (errno=%d)", errno);
            break;
        }

        if (FD_ISSET(s->listenFd, &readFds)) {
            acceptClient(s);
            ready--;
        }

        for (int i = 0; i < s->clientCount && ready > 0; i++) {
            if (FD_ISSET(s->clients[i]->fd, &readFds)) {
                ready--;
                if (processClient(s, s->clients[i]) != SERVER_SUCC) {
                    clientDisconnect(s, i);
                    i--;
                }
            }
        }

        serverLogCheckAndRestart();
    }

    return NULL;
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
    dbClose(server->roomDB);
    dbClose(server->gameDB);
    dbClose(server->serverDB);

    OPENSSL_cleanse(server->dekKey, sizeof(server->dekKey));
    OPENSSL_cleanse(server->userDbEncKey, sizeof(server->userDbEncKey));
    OPENSSL_cleanse(server->chatDbEncKey, sizeof(server->chatDbEncKey));
    OPENSSL_cleanse(server->roomDbEncKey, sizeof(server->roomDbEncKey));
    OPENSSL_cleanse(server->gameDbEncKey, sizeof(server->gameDbEncKey));

    LOG_INFO("Server shut down");
    serverLogClose();
}

/* ══════════════════════════ connection lifecycle ══════════════════════════ */

static void acceptClient(Server *s) {
    SocketFD clientFd = accept(s->listenFd, NULL, NULL);
    if (clientFd == NULL_SOCKETFD) {
        LOG_ERROR("accept failed (errno=%d)", errno);
        return;
    }

    /* FD_SETSIZE protection: reject connections that would overflow fd_set */
    if (clientFd >= FD_SETSIZE) {
        LOG_WARN("acceptClient: fd %d >= FD_SETSIZE (%d), rejecting", clientFd,
                 FD_SETSIZE);
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
        ClientSession **tmp = (ClientSession **)realloc(
            (void *)s->clients, (size_t)newCap * sizeof(ClientSession *));
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
    serverRemoveClientFromRoom(s, cs);

    socketClose(&cs->fd);
    OPENSSL_cleanse(&cs->aesKey, sizeof(cs->aesKey));
    if (cs->currentUser.totpSecret != NULL) {
        OPENSSL_cleanse(cs->currentUser.totpSecret,
                        strlen(cs->currentUser.totpSecret));
        free(cs->currentUser.totpSecret);
    }
    free(cs);

    /* Compact the clients array */
    int remaining = s->clientCount - idx - 1;
    if (remaining > 0) {
        memmove((void *)&s->clients[idx], (const void *)&s->clients[idx + 1],
                (size_t)remaining * sizeof(ClientSession *));
    }
    s->clientCount--;
}

/* ═══════════════════════════ receive & dispatch ═══════════════════════════ */

static int processClient(Server *s, ClientSession *cs) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    if (cs->state == SessionKeyExchange) {
        if (packetRecv(&pkt, cs->fd) != PROTOCOL_SUCC) {
            LOG_WARN("processClient: packetRecv failed for fd=%d", cs->fd);
            return SERVER_FAIL;
        }
    } else {
        if (serverRecvEncryptedPacket(cs, &pkt) != SERVER_SUCC) {
            LOG_WARN("processClient: recv/decrypt failed for fd=%d", cs->fd);
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
            ret = serverHandleLogin(s, cs, &pkt);
        } else if (mt == MsgRegisterReq) {
            ret = serverHandleRegister(s, cs, &pkt);
        } else if (mt == MsgLogout) {
            ret = handleLogout(s, cs);
        } else {
            LOG_WARN("processClient: unexpected msgType %d in state %d (fd=%d)",
                     (int)mt, cs->state, cs->fd);
            ret = SERVER_FAIL;
        }
        break;

    case SessionTOTPVerify:
        if (mt == MsgTOTPVerifyResp) {
            ret = serverHandleTOTPVerify(s, cs, &pkt);
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
            ret = serverHandleRoomList(s, cs);
        } else if (mt == MsgCreateRoom) {
            ret = serverHandleRoomCreate(s, cs, &pkt);
        } else if (mt == MsgJoinRoom) {
            ret = serverHandleRoomJoin(s, cs, &pkt);
        } else if (mt == MsgQuitRoom) {
            serverHandleRoomQuit(s, cs);
            ret = SERVER_SUCC;
        } else if (mt == MsgLogout) {
            ret = handleLogout(s, cs);
        } else if (mt == MsgTOTPSetupReq) {
            ret = serverHandleTOTPSetup(s, cs);
        } else if (mt == MsgDBKeyReq) {
            ret = serverHandleDBKeyReq(s, cs);
        } else {
            LOG_WARN("processClient: unexpected msgType %d in state %d (fd=%d)",
                     (int)mt, cs->state, cs->fd);
            ret = SERVER_FAIL;
        }
        break;

    case SessionChat:
        if (mt == MsgChat) {
            ret = serverHandleChatMessage(s, cs, &pkt);
        } else if (mt == MsgHeartbeat) {
            ret = handleHeartbeat(s, cs);
        } else if (mt == MsgLogout) {
            ret = handleLogout(s, cs);
        } else if (mt == MsgTOTPSetupReq) {
            ret = serverHandleTOTPSetup(s, cs);
        } else if (mt == MsgDBKeyReq) {
            ret = serverHandleDBKeyReq(s, cs);
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

/* ════════════════════════════════ handlers ════════════════════════════════ */

static int handleKeyExchange(Server *s, ClientSession *cs, Packet *pkt) {
    (void)s;
    AESGCMKey aesKey;

    if (serverExchangeAESKey(cs->fd, pkt, &aesKey) != PROTOCOL_SUCC) {
        LOG_WARN("handleKeyExchange: exchange failed for fd=%d", cs->fd);
        return SERVER_FAIL;
    }

    memcpy(&cs->aesKey, &aesKey, sizeof(aesKey));
    OPENSSL_cleanse(&aesKey, sizeof(aesKey));
    cs->state = SessionLogin;
    LOG_INFO("Key exchange complete for fd=%d", cs->fd);
    return SERVER_SUCC;
}

static int handleHeartbeat(Server *s, ClientSession *cs) {
    (void)s;
    return serverSendEncryptedPacket(cs, MsgHeartbeat, NULL, 0);
}

static int handleLogout(Server *s, ClientSession *cs) {
    (void)s;
    LOG_INFO("User logging out (fd=%d)", cs->fd);
    return SERVER_FAIL; /* Signal to disconnect */
}