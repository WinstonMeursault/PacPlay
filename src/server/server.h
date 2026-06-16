/**
 * @file server.h
 * @brief PacPlay server runtime types — sessions, rooms, and server state.
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

#ifndef SERVER_H
#define SERVER_H

#include "crypto.h"
#include "protocol.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* ─────────────────────────────── constants ──────────────────────────────── */

/** @brief Maximum username length (including NUL terminator). */
#define USERNAME_MAX_LEN 32
#define NICKNAME_MAX_LEN 32

/* LOGIN_USERNAME_LEN (protocol.h) and USERNAME_MAX_LEN must stay in sync
 * — they define the same wire-format / DB constraint boundary. */
_Static_assert(LOGIN_USERNAME_LEN == USERNAME_MAX_LEN,
               "LOGIN_USERNAME_LEN must equal USERNAME_MAX_LEN");

/* LOGIN_NICKNAME_LEN (protocol.h) and NICKNAME_MAX_LEN must stay in sync. */
_Static_assert(LOGIN_NICKNAME_LEN == NICKNAME_MAX_LEN,
               "LOGIN_NICKNAME_LEN must equal NICKNAME_MAX_LEN");

/* ────────────────────────── forward declarations ────────────────────────── */

struct DB;

/* ───────────────────────── constants (continued) ────────────────────────── */

/** @brief Maximum clients a single room can hold. */
#define MAX_CLIENTS_PER_ROOM 10

/** @brief Initial capacity for dynamic session / room arrays. */
#define SERVER_INITIAL_CAPACITY 16

/** @brief select() timeout in microseconds (~60 Hz, reserves headroom for
 *         future per-tick game updates). */
#define SERVER_SELECT_TIMEOUT_US 16000

/** @brief Length of per-database encryption keys (256-bit). */
#define DB_ENC_KEY_LEN 32

/* ────────────────────────────── return codes ────────────────────────────── */

#define SERVER_SUCC (0)
#define SERVER_FAIL (-1)

/* ───────────────────────────────── types ────────────────────────────────── */

typedef struct {
    char username[USERNAME_MAX_LEN];
    char nickname[NICKNAME_MAX_LEN];
    uint32_t uid;
    char *password;   /**< Plaintext password (hashed internally on storage). */
    char *totpSecret; /**< Base32-encoded TOTP shared secret, or NULL. */
} User;

/** @brief Represents a single chat message record. */
typedef struct {
    uint32_t uid;
    uint64_t msgId; /**< Globally unique, monotonically increasing ID. */
    char *message;
    time_t timestamp; /**< UNIX timestamp (seconds since epoch, UTC). */
} Chat;

#ifndef PLATFORM_NAME_LEN
#define PLATFORM_NAME_LEN 16
#endif

typedef struct {
    char platform[PLATFORM_NAME_LEN];
    char *fileName;
    char *hash;
    uint64_t fileSize;
} GamePlatformInfo;

typedef struct {
    uint32_t gameId;
    char *name;
    char *version;
    GamePlatformInfo *platforms;
    size_t platformCount;
    time_t createdAt;
    time_t updatedAt;
} GameInfo;

/** @brief Per-connection lifecycle states. */
typedef enum {
    SessionKeyExchange = 0, /**< Awaiting MsgKeyExchangeReq. */
    SessionLogin,           /**< Awaiting MsgLoginReq. */
    SessionTOTPVerify,      /**< Awaiting MsgTOTPVerifyResp. */
    SessionRoom,            /**< Lobby — can list / create / join rooms. */
    SessionChat             /**< Inside a room — can chat and heartbeat. */
} SessionState;

/** @brief One connected client, tracked across its entire session. */
typedef struct {
    SocketFD fd;
    SessionState state;
    AESGCMKey aesKey;
    User currentUser;       /**< Populated after successful login. */
    uint32_t currentRoomId; /**< 0 if not in any room. */
    uint32_t seqID;         /**< Per-client monotonic sequence counter. */
} ClientSession;

/** @brief In-memory room with currently-connected members (used for
 *         broadcasting).  Persisted room existence is managed by RoomDB. */
typedef struct {
    uint32_t roomId;
    ClientSession *members[MAX_CLIENTS_PER_ROOM];
    int memberCount;
} ActiveRoom;

/** @brief Top-level server state. */
typedef struct {
    SocketFD listenFd;
    ClientSession **clients; /**< Dynamic array of connected sessions. */
    int clientCount;
    int clientCapacity;
    ActiveRoom **activeRooms; /**< Dynamic array of rooms with ≥1 member. */
    int activeRoomCount;
    int activeRoomCapacity;
    struct DB *userDB; /**< Opaque DB handle (full def in database.h). */
    struct DB *chatDB;
    struct DB *roomDB;
    struct DB *gameDB;
    struct DB *serverDB;     /**< Server key-value store. */
    bool freshKeysGenerated; /**< True if keys were freshly generated (first
                                run). */
    volatile bool running;   /**< Event loop continues while true. */
    pthread_t serverThread;  /**< Background event-loop thread handle. */
    time_t startTime;        /**< Server launch timestamp (UNIX epoch). */
    uint8_t dekKey[AES_GCM_KEY_LEN];      /**< Decrypted DEK, available after
                                              serverInitKeys. */
    uint8_t userDbEncKey[DB_ENC_KEY_LEN]; /**< Decrypted UserDBKey, loaded at
                                              startup. */
    uint8_t chatDbEncKey[DB_ENC_KEY_LEN]; /**< Decrypted ChatHistoryDBKey. */
    uint8_t roomDbEncKey[DB_ENC_KEY_LEN]; /**< Decrypted RoomDBKey. */
    uint8_t gameDbEncKey[DB_ENC_KEY_LEN]; /**< Decrypted GameDBKey. */
} Server;

/* ─────────────────────────────── public API ─────────────────────────────── */

/**
 * @brief Initialise the server — creates listen socket, opens ServerDB,
 *        and runs the TUI unlock phase (blocks until MK is provided).
 *
 * @param server  Must be zero-initialised or freshly allocated.
 * @param port    TCP port to listen on.
 * @return @c SERVER_SUCC or @c SERVER_FAIL.
 */
int serverInit(Server *server, uint16_t port);

/**
 * @brief Launch the server event loop in a background thread.
 *
 * Opens encrypted databases, allocates session/room arrays, installs
 * signal handlers, and spawns the event-loop thread.
 *
 * @param server  A server that has completed the unlock phase.
 * @return @c SERVER_SUCC or @c SERVER_FAIL.
 */
int serverLaunch(Server *server);

/**
 * @brief Stop the background event-loop thread and wait for it to exit.
 *
 * Sets the running flag to false and joins the server thread.
 *
 * @param server  A launched server.
 */
void serverShutdown(Server *server);

/**
 * @brief Enter the server main page (TUI) and background event loop.
 *
 * Calls serverLaunch() to start the event loop in a background thread,
 * then enters the TUI main page (blocking). Returns after the user
 * issues the 'exit' command (which internally calls serverShutdown).
 *
 * @param server  A fully-initialised Server (unlock phase complete).
 */
void serverRun(Server *server);

/**
 * @brief Tear down the server — closes all sockets, frees sessions and
 *        rooms, and closes database handles.
 *
 * @param server  Server to clean up.
 */
void serverCleanup(Server *server);

#endif /* SERVER_H */
