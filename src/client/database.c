/**
 * @file database.c
 * @brief Encrypted client-side SQLCipher database for local game library.
 *
 * Implements an encrypted database whose schema is the gameList table.
 * All operations use cached prepared statements to prevent SQL injection
 * and minimise runtime overhead.
 *
 * @date 2026-06-01
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

#include "client/database.h"
#include "client.h"
#include "db.h"
#include "log.h"
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

/* ───────────────────────── SQL schema definitions ───────────────────────── */

#define SQL_CREATE_GAMELIST                                                    \
    "CREATE TABLE IF NOT EXISTS gameList ("                                    \
    "gameId INTEGER PRIMARY KEY, "                                             \
    "gameName TEXT NOT NULL, "                                                 \
    "gamePath TEXT NOT NULL, "                                                 \
    "gameVersion TEXT NOT NULL DEFAULT '', "                                   \
    "platform TEXT NOT NULL DEFAULT '', "                                      \
    "fileHash TEXT NOT NULL DEFAULT '', "                                      \
    "playTime INTEGER NOT NULL DEFAULT 0"                                      \
    ");"

/* ────────────────────────────── prepared SQL ────────────────────────────── */

/** @brief INSERT a game record. Params: ?1=gameId, ?2=gameName, ?3=gamePath,
    ?4=gameVersion, ?5=platform, ?6=fileHash. */
#define SQL_INSERT_GAME                                                        \
    "INSERT INTO gameList (gameId, gameName, gamePath, gameVersion, "          \
    "platform, fileHash, playTime) "                                           \
    "VALUES (?, ?, ?, ?, ?, ?, 0);"

/** @brief SELECT all games ordered by gameName. */
#define SQL_SELECT_ALL_GAMES                                                   \
    "SELECT gameId, gameName, gamePath, gameVersion, platform, fileHash, "     \
    "playTime FROM gameList "                                                  \
    "ORDER BY gameName ASC;"

/** @brief SELECT a single game by gameId. Params: ?1=gameId. */
#define SQL_SELECT_GAME_BY_ID                                                  \
    "SELECT gameId, gameName, gamePath, gameVersion, platform, fileHash, "     \
    "playTime FROM gameList "                                                  \
    "WHERE gameId = ?;"

/** @brief DELETE a game by gameId. Params: ?1=gameId. */
#define SQL_DELETE_GAME "DELETE FROM gameList WHERE gameId = ?;"

/** @brief UPDATE playTime for a game. Params: ?1=playTime, ?2=gameId. */
#define SQL_UPDATE_PLAY_TIME                                                   \
    "UPDATE gameList SET playTime = ? WHERE gameId = ?;"

/* ───────────────────────────── misc constants ───────────────────────────── */

#define DB_DIR_MODE 0755

/* ──────────────────────────────── helpers ───────────────────────────────── */

/**
 * @brief Execute a single SQL statement with no bound parameters.
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
/**
 * @brief Prepare and cache all statements for the gameList table.
 */
static int prepareGameListStmts(ClientDB *db) {
    int rc;

    rc = sqlite3_prepare_v2(db->handle, SQL_INSERT_GAME, -1, &db->stmtInsert,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameListStmts: INSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_prepare_v2(db->handle, SQL_SELECT_ALL_GAMES, -1,
                            &db->stmtSelectAll, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameListStmts: SELECT ALL prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_prepare_v2(db->handle, SQL_SELECT_GAME_BY_ID, -1,
                            &db->stmtSelectById, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR(
            "prepareGameListStmts: SELECT BY ID prepare failed: %s (rc=%d)",
            sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_prepare_v2(db->handle, SQL_DELETE_GAME, -1, &db->stmtDelete,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameListStmts: DELETE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_prepare_v2(db->handle, SQL_UPDATE_PLAY_TIME, -1,
                            &db->stmtUpdatePlayTime, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameListStmts: UPDATE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    return CLIENT_DB_SUCC;
}

/* ───────────────────────── public API: lifecycle ────────────────────────── */

int clientInitDB(Client *client) {
    if (client == NULL || client->db != NULL) {
        LOG_ERROR("clientInitDB: client=%p, client->db=%p", (void *)client,
                  client != NULL ? (void *)client->db : NULL);
        return CLIENT_DB_FAIL;
    }

    /* Ensure the parent directory exists */
    struct stat st;
    if (stat(CLIENT_DB_DIR, &st) != 0) {
        if (PLATFORM_MKDIR(CLIENT_DB_DIR, DB_DIR_MODE) != 0) {
            LOG_ERROR("clientInitDB: mkdir '%s' failed: %s (errno=%d)",
                      CLIENT_DB_DIR, strerror(errno), errno);
            return CLIENT_DB_FAIL;
        }
        LOG_INFO("clientInitDB: created directory '%s'", CLIENT_DB_DIR);
    } else if (!S_ISDIR(st.st_mode)) {
        LOG_ERROR("clientInitDB: '%s' exists but is not a directory",
                  CLIENT_DB_DIR);
        return CLIENT_DB_FAIL;
    }

    ClientDB *db = calloc(1, sizeof(ClientDB));
    if (db == NULL) {
        LOG_ERROR("clientInitDB: calloc failed (errno=%d)", errno);
        return CLIENT_DB_FAIL;
    }

    memcpy(db->dbEncKey, client->cdbkey, CLIENT_DB_KEY_LEN);

    int rc = sqlite3_open(CLIENT_DB_PATH, &db->handle);
    if (rc != SQLITE_OK) {
        LOG_ERROR("clientInitDB: sqlite3_open failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        sqlite3_close(db->handle);
        OPENSSL_cleanse(db->dbEncKey, sizeof(db->dbEncKey));
        free(db);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_key(db->handle, db->dbEncKey, (int)CLIENT_DB_KEY_LEN);
    if (rc != SQLITE_OK) {
        LOG_ERROR("clientInitDB: sqlite3_key failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        sqlite3_close(db->handle);
        OPENSSL_cleanse(db->dbEncKey, sizeof(db->dbEncKey));
        free(db);
        return CLIENT_DB_FAIL;
    }

    if (dbExec(db->handle, "PRAGMA journal_mode=WAL;", "PRAGMA journal_mode") !=
        CLIENT_DB_SUCC) {
        LOG_WARN("clientInitDB: WAL mode not enabled, continuing");
    }

    if (dbExec(db->handle, "PRAGMA foreign_keys=ON;", "PRAGMA foreign_keys") !=
        CLIENT_DB_SUCC) {
        LOG_WARN("clientInitDB: foreign_keys not enabled, continuing");
    }

    if (dbExec(db->handle, SQL_CREATE_GAMELIST, "CREATE TABLE gameList") !=
        CLIENT_DB_SUCC) {
        LOG_ERROR("clientInitDB: schema creation failed");
        sqlite3_close(db->handle);
        OPENSSL_cleanse(db->dbEncKey, sizeof(db->dbEncKey));
        free(db);
        return CLIENT_DB_FAIL;
    }

    if (prepareGameListStmts(db) != CLIENT_DB_SUCC) {
        LOG_ERROR("clientInitDB: statement preparation failed");
        sqlite3_close(db->handle);
        OPENSSL_cleanse(db->dbEncKey, sizeof(db->dbEncKey));
        free(db);
        return CLIENT_DB_FAIL;
    }

    client->db = db;
    LOG_INFO("clientInitDB: opened '%s' successfully", CLIENT_DB_PATH);
    return CLIENT_DB_SUCC;
}

void clientCloseDB(Client *client) {
    if (client == NULL || client->db == NULL) {
        return;
    }

    ClientDB *db = client->db;

    dbFinalize(&db->stmtInsert);
    dbFinalize(&db->stmtSelectAll);
    dbFinalize(&db->stmtSelectById);
    dbFinalize(&db->stmtDelete);
    dbFinalize(&db->stmtUpdatePlayTime);

    int rc = sqlite3_close(db->handle);
    if (rc != SQLITE_OK) {
        LOG_ERROR("clientCloseDB: sqlite3_close failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
    }

    OPENSSL_cleanse(db->dbEncKey, sizeof(db->dbEncKey));
    free(db);
    client->db = NULL;
    LOG_INFO("clientCloseDB: database closed");
}

/* ────────────────────── public API: game operations ─────────────────────── */

int addGame(Client *client, uint32_t gameId, const char *gameName,
            const char *gamePath, const char *gameVersion,
            const char *platform, const char *fileHash) {
    if (client == NULL || client->db == NULL) {
        LOG_ERROR("addGame: NULL client or uninitialised database");
        return CLIENT_DB_FAIL;
    }
    if (gameName == NULL || gamePath == NULL) {
        LOG_ERROR("addGame: gameName=%p, gamePath=%p", (void *)gameName,
                  (void *)gamePath);
        return CLIENT_DB_FAIL;
    }

    const char *ver = gameVersion != NULL ? gameVersion : "";
    const char *plat = platform != NULL ? platform : "";
    const char *hash = fileHash != NULL ? fileHash : "";

    ClientDB *db = client->db;
    sqlite3_stmt *stmt = db->stmtInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("addGame: bind gameId failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 2, gameName, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("addGame: bind gameName failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 3, gamePath, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("addGame: bind gamePath failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    enum { BindGameVersion = 4, BindPlatform = 5, BindFileHash = 6 };

    rc = sqlite3_bind_text(stmt, BindGameVersion, ver, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("addGame: bind gameVersion failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, BindPlatform, plat, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("addGame: bind platform failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, BindFileHash, hash, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("addGame: bind fileHash failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("addGame: step failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    return CLIENT_DB_SUCC;
}

int listGames(Client *client, GameRecord ***outRecords, size_t *count) {
    if (client == NULL || client->db == NULL) {
        LOG_ERROR("listGames: NULL client or uninitialised database");
        return CLIENT_DB_FAIL;
    }
    if (outRecords == NULL || count == NULL) {
        LOG_ERROR("listGames: outRecords=%p, count=%p", (void *)outRecords,
                  (void *)count);
        return CLIENT_DB_FAIL;
    }

    *outRecords = NULL;
    *count = 0;

    ClientDB *db = client->db;
    sqlite3_stmt *stmt = db->stmtSelectAll;
    sqlite3_reset(stmt);

    enum { InitialCapacity = 8 };
    size_t capacity = InitialCapacity;
    size_t n = 0;
    GameRecord **results =
        (GameRecord **)malloc(capacity * sizeof(GameRecord *));
    if (results == NULL) {
        LOG_ERROR("listGames: malloc failed (errno=%d)", errno);
        return CLIENT_DB_FAIL;
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            GameRecord **tmp = (GameRecord **)realloc(
                (void *)results, newCapacity * sizeof(GameRecord *));
            if (tmp == NULL) {
                LOG_ERROR("listGames: realloc failed (errno=%d)", errno);
                for (size_t i = 0; i < n; i++) {
                    free(results[i]->gameName);
                    free(results[i]->gamePath);
                    free(results[i]->gameVersion);
                    free(results[i]->platform);
                    free(results[i]->fileHash);
                    free(results[i]);
                }
                free((void *)results);
                return CLIENT_DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        GameRecord *rec = calloc(1, sizeof(GameRecord));
        if (rec == NULL) {
            LOG_ERROR("listGames: calloc failed (errno=%d)", errno);
            for (size_t i = 0; i < n; i++) {
                free(results[i]->gameName);
                free(results[i]->gamePath);
                free(results[i]->gameVersion);
                free(results[i]->platform);
                free(results[i]->fileHash);
                free(results[i]);
            }
            free((void *)results);
            return CLIENT_DB_FAIL;
        }

        rec->gameId = (uint32_t)sqlite3_column_int64(stmt, 0);

        enum {
            ColName = 1,
            ColPath = 2,
            ColVersion = 3,
            ColPlatform = 4,
            ColHash = 5,
            ColPlayTime = 6
        };

        const char *nameStr = (const char *)sqlite3_column_text(stmt, ColName);
        const char *pathStr = (const char *)sqlite3_column_text(stmt, ColPath);
        if (nameStr == NULL || pathStr == NULL) {
            LOG_ERROR("listGames: NULL column at row %zu", n);
            free(rec);
            for (size_t i = 0; i < n; i++) {
                free(results[i]->gameName);
                free(results[i]->gamePath);
                free(results[i]->gameVersion);
                free(results[i]->platform);
                free(results[i]->fileHash);
                free(results[i]);
            }
            free((void *)results);
            return CLIENT_DB_FAIL;
        }

        const char *verStr =
            (const char *)sqlite3_column_text(stmt, ColVersion);
        const char *platStr =
            (const char *)sqlite3_column_text(stmt, ColPlatform);
        const char *hashStr =
            (const char *)sqlite3_column_text(stmt, ColHash);

        rec->gameName = strdup(nameStr);
        rec->gamePath = strdup(pathStr);
        rec->gameVersion = strdup(verStr != NULL ? verStr : "");
        rec->platform = strdup(platStr != NULL ? platStr : "");
        rec->fileHash = strdup(hashStr != NULL ? hashStr : "");
        if (rec->gameName == NULL || rec->gamePath == NULL ||
            rec->gameVersion == NULL || rec->platform == NULL ||
            rec->fileHash == NULL) {
            LOG_ERROR("listGames: strdup failed (errno=%d)", errno);
            free(rec->gameName);
            free(rec->gamePath);
            free(rec->gameVersion);
            free(rec->platform);
            free(rec->fileHash);
            free(rec);
            for (size_t i = 0; i < n; i++) {
                free(results[i]->gameName);
                free(results[i]->gamePath);
                free(results[i]->gameVersion);
                free(results[i]->platform);
                free(results[i]->fileHash);
                free(results[i]);
            }
            free((void *)results);
            return CLIENT_DB_FAIL;
        }

        rec->playTime = (uint64_t)sqlite3_column_int64(stmt, ColPlayTime);
        results[n] = rec;
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("listGames: step failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        for (size_t i = 0; i < n; i++) {
            free(results[i]->gameName);
            free(results[i]->gamePath);
            free(results[i]->gameVersion);
            free(results[i]->platform);
            free(results[i]->fileHash);
            free(results[i]);
        }
        free((void *)results);
        return CLIENT_DB_FAIL;
    }

    if (n == 0) {
        free((void *)results);
        return CLIENT_DB_SUCC;
    }

    *outRecords = results;
    *count = n;
    return CLIENT_DB_SUCC;
}

int deleteGame(Client *client, uint32_t gameId) {
    if (client == NULL || client->db == NULL) {
        LOG_ERROR("deleteGame: NULL client or uninitialised database");
        return CLIENT_DB_FAIL;
    }

    ClientDB *db = client->db;
    sqlite3_stmt *stmt = db->stmtDelete;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("deleteGame: bind gameId failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("deleteGame: step failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    if (sqlite3_changes(db->handle) == 0) {
        LOG_WARN("deleteGame: gameId %u not found", gameId);
        return CLIENT_DB_FAIL;
    }

    return CLIENT_DB_SUCC;
}

int updatePlayTime(Client *client, uint32_t gameId, uint64_t playTime) {
    if (client == NULL || client->db == NULL) {
        LOG_ERROR("updatePlayTime: NULL client or uninitialised database");
        return CLIENT_DB_FAIL;
    }

    ClientDB *db = client->db;
    sqlite3_stmt *stmt = db->stmtUpdatePlayTime;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)playTime);
    if (rc != SQLITE_OK) {
        LOG_ERROR("updatePlayTime: bind playTime failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)gameId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("updatePlayTime: bind gameId failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("updatePlayTime: step failed: %s (rc=%d)",
                  sqlite3_errmsg(db->handle), rc);
        return CLIENT_DB_FAIL;
    }

    if (sqlite3_changes(db->handle) == 0) {
        LOG_WARN("updatePlayTime: gameId %u not found", gameId);
        return CLIENT_DB_FAIL;
    }

    return CLIENT_DB_SUCC;
}
