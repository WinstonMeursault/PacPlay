/**
 * @file common.c
 * @brief Database lifecycle management for PacPlay server.
 *
 * Implements database initialization (dbInit), teardown (dbClose), and
 * key setting (dbSetDekKey, dbSetDbEncKey).  Schema initialization and
 * statement preparation are delegated to per-database modules (userDb.c,
 * chatDb.c, roomDb.c, serverDb.c).
 *
 * @date 2026-06-07
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

#include "crypto.h"
#include "db.h"
#include "log.h"
#include "server/database.h"
#include "server/database/internal.h"
#include "utils.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>

/** @brief SQLCipher key setter — not declared in standard sqlite3.h. */
int sqlite3_key(sqlite3 *db, const void *pKey, int nKey);

/** @brief Directory permission mode: rwx for owner, rx for group/others. */
#define DB_DIR_MODE 0755

/* ──────────────────────────── internal helpers ──────────────────────────── */

/**
 * @brief Ensure the database directory exists, creating it if necessary.
 *
 * Uses stat() to check existence, then mkdir() if needed. Cross-platform
 * via the PLATFORM_MKDIR macro.
 *
 * @return @c DB_SUCC if directory exists or was created, @c DB_FAIL on error.
 */
static int ensureDBDirectoryExists(void) {
    struct stat st;
    if (stat(DB_DIRECTORY, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return DB_SUCC;
        }
        LOG_ERROR("dbInit: path '%s' exists but is not a directory",
                  DB_DIRECTORY);
        return DB_FAIL;
    }

    if (PLATFORM_MKDIR(DB_DIRECTORY, DB_DIR_MODE) != 0) {
        LOG_ERROR("dbInit: failed to create directory '%s': %s (errno=%d)",
                  DB_DIRECTORY, strerror(errno), errno);
        return DB_FAIL;
    }

    LOG_INFO("dbInit: created database directory '%s'", DB_DIRECTORY);
    return DB_SUCC;
}

/* ───────────────────────── public API: lifecycle ────────────────────────── */

DB *dbInit(DBType dbType, const uint8_t *encKey) {
    const char *dbPath = NULL;

    switch (dbType) {
    case UserDB:
        dbPath = USER_DB_PATH;
        break;
    case ChatHistoryDB:
        dbPath = CHAT_HISTORY_DB_PATH;
        break;
    case RoomDB:
        dbPath = ROOM_DB_PATH;
        break;
    case GameDB:
        dbPath = GAME_DB_PATH;
        break;
    case ServerDB:
        dbPath = SERVER_DB_PATH;
        break;
    default:
        LOG_ERROR("dbInit: unknown DBType %d", (int)dbType);
        return NULL;
    }

    /* Ensure the parent directory exists */
    if (ensureDBDirectoryExists() != DB_SUCC) {
        return NULL;
    }

    /* Allocate the wrapper struct */
    DB *database = calloc(1, sizeof(DB));
    if (database == NULL) {
        LOG_ERROR("dbInit: calloc failed (errno=%d)", errno);
        return NULL;
    }
    database->type = dbType;

    /* Open (or create) the database file */
    int rc = sqlite3_open(dbPath, &database->handle);
    if (rc != SQLITE_OK) {
        LOG_ERROR("dbInit: sqlite3_open('%s') failed: %s (rc=%d)", dbPath,
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_close(database->handle);
        free(database);
        return NULL;
    }

    /* Apply encryption key for non-ServerDB databases — must be set before
     * any PRAGMA or schema operation so that newly created databases are
     * encrypted from the first byte written. */
    if (encKey != NULL) {
        rc = sqlite3_key(database->handle, encKey, (int)DB_ENC_KEY_LEN);
        if (rc != SQLITE_OK) {
            LOG_ERROR("dbInit: sqlite3_key('%s') failed: %s (rc=%d)", dbPath,
                      sqlite3_errmsg(database->handle), rc);
            sqlite3_close(database->handle);
            free(database);
            return NULL;
        }
        memcpy(database->dbEncKey, encKey, DB_ENC_KEY_LEN);
    }

    /* Enable WAL mode for better concurrent read performance */
    if (dbExec(database->handle, "PRAGMA journal_mode=WAL;",
               "PRAGMA journal_mode") != DB_SUCC) {
        LOG_WARN("dbInit: WAL mode not enabled, continuing with default");
    }

    /* Enable foreign key enforcement */
    if (dbExec(database->handle, "PRAGMA foreign_keys=ON;",
               "PRAGMA foreign_keys") != DB_SUCC) {
        LOG_WARN("dbInit: foreign_keys not enabled, continuing");
    }

    /* Initialize the appropriate schema */
    int schemaResult = DB_FAIL;
    switch (dbType) {
    case UserDB:
        schemaResult = initUserDBSchema(database->handle);
        break;
    case ChatHistoryDB:
        schemaResult = initChatHistoryDBSchema(database->handle);
        break;
    case RoomDB:
        schemaResult = initRoomDBSchema(database->handle);
        break;
    case GameDB:
        schemaResult = initGameDBSchema(database->handle);
        break;
    case ServerDB:
        schemaResult = initServerDBSchema(database->handle);
        break;
    default:
        break;
    }

    if (schemaResult != DB_SUCC) {
        LOG_ERROR("dbInit: schema initialization failed for '%s'", dbPath);
        sqlite3_close(database->handle);
        free(database);
        return NULL;
    }

    /* Prepare cached statements for this database type */
    int stmtResult = DB_FAIL;
    switch (dbType) {
    case UserDB:
        stmtResult = prepareUserStmts(database);
        break;
    case ChatHistoryDB:
        stmtResult = prepareChatGlobalStmts(database);
        if (stmtResult == DB_SUCC) {
            /* Allocate the room statement cache */
            database->roomCache = calloc(1, sizeof(RoomStmtCache));
            if (database->roomCache == NULL) {
                LOG_ERROR("dbInit: roomCache calloc failed (errno=%d)", errno);
                stmtResult = DB_FAIL;
            }
        }
        break;
    case RoomDB:
        stmtResult = prepareRoomDBStmts(database);
        break;
    case GameDB:
        stmtResult = prepareGameDBStmts(database);
        break;
    case ServerDB:
        stmtResult = prepareServerDBStmts(database);
        break;
    default:
        break;
    }

    if (stmtResult != DB_SUCC) {
        LOG_ERROR("dbInit: statement preparation failed for '%s'", dbPath);
        dbFinalize(&database->stmtInsert);
        dbFinalize(&database->stmtDelete);
        dbFinalize(&database->stmtSelect);
        dbFinalize(&database->stmtRoomExists);
        dbFinalize(&database->stmtUidCheck);
        dbFinalize(&database->stmtSetTotpSecret);
        dbFinalize(&database->stmtGetTOTPSecret);
        dbFinalize(&database->stmtGetCDBKey);
        dbFinalize(&database->stmtSetKey);
        dbFinalize(&database->stmtGetKey);
        dbFinalize(&database->stmtSeq);
        dbFinalize(&database->stmtGameInsert);
        dbFinalize(&database->stmtGameDelete);
        dbFinalize(&database->stmtGameUpdate);
        dbFinalize(&database->stmtGameSelectById);
        dbFinalize(&database->stmtGameSelectByName);
        dbFinalize(&database->stmtGameList);
        dbFinalize(&database->stmtGameGetKey);
        dbFinalize(&database->stmtPlatformInsert);
        dbFinalize(&database->stmtPlatformSelect);
        dbFinalize(&database->stmtPlatformList);
        roomCacheDestroy(database->roomCache);
        sqlite3_close(database->handle);
        free(database);
        return NULL;
    }

    LOG_INFO("dbInit: database '%s' opened successfully", dbPath);
    return database;
}

void dbClose(DB *database) {
    if (database == NULL) {
        return;
    }

    /* Finalize UserDB cached statements */
    dbFinalize(&database->stmtInsert);
    dbFinalize(&database->stmtDelete);
    dbFinalize(&database->stmtSelect);
    dbFinalize(&database->stmtRoomExists);
    dbFinalize(&database->stmtUidCheck);
    dbFinalize(&database->stmtSetTotpSecret);
    dbFinalize(&database->stmtGetTOTPSecret);
    dbFinalize(&database->stmtGetCDBKey);

    /* Finalize ServerDB cached statements */
    dbFinalize(&database->stmtSetKey);
    dbFinalize(&database->stmtGetKey);

    /* Finalize GameDB cached statements */
    dbFinalize(&database->stmtGameInsert);
    dbFinalize(&database->stmtGameDelete);
    dbFinalize(&database->stmtGameUpdate);
    dbFinalize(&database->stmtGameSelectById);
    dbFinalize(&database->stmtGameSelectByName);
    dbFinalize(&database->stmtGameList);
    dbFinalize(&database->stmtGameGetKey);
    dbFinalize(&database->stmtPlatformInsert);
    dbFinalize(&database->stmtPlatformSelect);
    dbFinalize(&database->stmtPlatformList);

    /* Finalize ChatHistoryDB cached statements */
    dbFinalize(&database->stmtSeq);
    roomCacheDestroy(database->roomCache);

    /* Close the sqlite3 connection */
    int rc = sqlite3_close(database->handle);
    if (rc != SQLITE_OK) {
        LOG_ERROR("dbClose: sqlite3_close failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
    }

    OPENSSL_cleanse(database->dekKey, sizeof(database->dekKey));
    OPENSSL_cleanse(database->dbEncKey, sizeof(database->dbEncKey));
    free(database);
}

void dbSetDekKey(DB *database, const uint8_t *dekKey) {
    if (database == NULL) {
        return;
    }
    if (dekKey != NULL) {
        memcpy(database->dekKey, dekKey, AES_GCM_KEY_LEN);
    } else {
        memset(database->dekKey, 0, sizeof(database->dekKey));
    }
}

void dbSetDbEncKey(DB *database, const uint8_t *key) {
    if (database == NULL) {
        return;
    }
    if (key != NULL) {
        memcpy(database->dbEncKey, key, DB_ENC_KEY_LEN);
    } else {
        memset(database->dbEncKey, 0, sizeof(database->dbEncKey));
    }
}
