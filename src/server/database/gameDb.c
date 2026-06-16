/**
 * @file gameDb.c
 * @brief Game metadata (registry) database operations for PacPlay server.
 *
 * Implements CRUD operations for the platform game registry with a
 * dual-table schema: games + game_platforms.
 *
 * @date 2026-06-16
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

#include "db.h"
#include "log.h"
#include "server/database.h"
#include "server/database/internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ───────────────────────── SQL schema definitions ───────────────────────── */

#define SQL_CREATE_GAMES_TABLE                                                 \
    "CREATE TABLE IF NOT EXISTS games ("                                       \
    "gameId INTEGER PRIMARY KEY AUTOINCREMENT, "                               \
    "name TEXT NOT NULL UNIQUE, "                                              \
    "version TEXT NOT NULL, "                                                  \
    "description TEXT NOT NULL DEFAULT '', "                                   \
    "encKey BLOB NOT NULL, "                                                   \
    "createdAt INTEGER NOT NULL, "                                             \
    "updatedAt INTEGER NOT NULL"                                               \
    ");"

#define SQL_CREATE_PLATFORMS_TABLE                                             \
    "CREATE TABLE IF NOT EXISTS game_platforms ("                              \
    "gameId INTEGER NOT NULL, "                                                \
    "platform TEXT NOT NULL, "                                                 \
    "fileName TEXT NOT NULL, "                                                 \
    "hash TEXT NOT NULL, "                                                     \
    "fileSize INTEGER NOT NULL, "                                              \
    "role TEXT NOT NULL DEFAULT 'client', "                                    \
    "PRIMARY KEY (gameId, platform, role), "                                   \
    "FOREIGN KEY (gameId) REFERENCES games(gameId) ON DELETE CASCADE"          \
    ");"

/* ──────────────────────── GameDB prepared SQL ───────────────────────────── */

#define SQL_INSERT_GAME                                                        \
    "INSERT INTO games (name, version, description, encKey, createdAt, "       \
    "updatedAt) VALUES (?, ?, ?, ?, ?, ?);"

#define SQL_DELETE_GAME "DELETE FROM games WHERE gameId = ?;"

#define SQL_UPDATE_GAME                                                        \
    "UPDATE games SET version = ?, updatedAt = ? WHERE gameId = ?;"

#define SQL_SELECT_GAME_BY_ID                                                  \
    "SELECT gameId, name, version, description, createdAt, updatedAt "         \
    "FROM games WHERE gameId = ?;"

#define SQL_SELECT_GAME_BY_NAME                                                \
    "SELECT gameId, name, version, description, createdAt, updatedAt "         \
    "FROM games WHERE name = ?;"

#define SQL_LIST_GAMES                                                         \
    "SELECT gameId, name, version, description, createdAt, updatedAt "         \
    "FROM games ORDER BY gameId ASC;"

#define SQL_LIST_GAME_BRIEF_ALL                                                \
    "SELECT gameId, name, version, description, createdAt, updatedAt "         \
    "FROM games ORDER BY gameId ASC;"

#define SQL_LIST_GAME_BRIEF_RANGE                                              \
    "SELECT gameId, name, version, description, createdAt, updatedAt "         \
    "FROM games WHERE gameId >= ? AND gameId <= ? ORDER BY gameId ASC;"

#define SQL_LIST_GAME_BRIEF_PLAT_ALL                                           \
    "SELECT DISTINCT g.gameId, g.name, g.version, g.description, "             \
    "g.createdAt, g.updatedAt "                                                \
    "FROM games g INNER JOIN game_platforms p ON g.gameId = p.gameId "         \
    "WHERE p.platform = ? ORDER BY g.gameId ASC;"

#define SQL_LIST_GAME_BRIEF_PLAT_RANGE                                         \
    "SELECT DISTINCT g.gameId, g.name, g.version, g.description, "             \
    "g.createdAt, g.updatedAt "                                                \
    "FROM games g INNER JOIN game_platforms p ON g.gameId = p.gameId "         \
    "WHERE g.gameId >= ? AND g.gameId <= ? AND p.platform = ? "                \
    "ORDER BY g.gameId ASC;"

#define SQL_GET_ENC_KEY "SELECT encKey FROM games WHERE gameId = ?;"

#define SQL_INSERT_PLATFORM                                                    \
    "INSERT OR REPLACE INTO game_platforms "                                   \
    "(gameId, platform, fileName, hash, fileSize, role) "                      \
    "VALUES (?, ?, ?, ?, ?, ?);"

#define SQL_SELECT_PLATFORM                                                    \
    "SELECT platform, fileName, hash, fileSize, role "                         \
    "FROM game_platforms WHERE gameId = ? AND platform = ? AND role = ?;"

#define SQL_LIST_PLATFORMS                                                     \
    "SELECT platform, fileName, hash, fileSize, role "                         \
    "FROM game_platforms WHERE gameId = ?;"

/* ─────────────────── column indices ────────────────────── */

enum {
    ColGameId = 0,
    ColName = 1,
    ColVersion = 2,
    ColDescription = 3,
    ColCreatedAt = 4,
    ColUpdatedAt = 5
};

enum {
    ColPlatPlatform = 0,
    ColPlatFileName = 1,
    ColPlatHash = 2,
    ColPlatFileSize = 3,
    ColPlatRole = 4
};

/* ────────────────────────── schema init helper ──────────────────────────── */

int initGameDBSchema(sqlite3 *dbHandle) {
    if (dbExec(dbHandle, SQL_CREATE_GAMES_TABLE, "CREATE TABLE games") !=
        DB_EXEC_SUCC) {
        return DB_FAIL;
    }
    if (dbExec(dbHandle, SQL_CREATE_PLATFORMS_TABLE,
               "CREATE TABLE game_platforms") != DB_EXEC_SUCC) {
        return DB_FAIL;
    }
    return DB_SUCC;
}

/* ──────────────────────── GameDB stmt preparation ───────────────────────── */

int prepareGameDBStmts(DB *database) {
    int rc;
    sqlite3 *h = database->handle;

    rc = sqlite3_prepare_v2(h, SQL_INSERT_GAME, -1, &database->stmtGameInsert,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: INSERT game failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_DELETE_GAME, -1, &database->stmtGameDelete,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: DELETE game failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_UPDATE_GAME, -1, &database->stmtGameUpdate,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: UPDATE game failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_SELECT_GAME_BY_ID, -1,
                            &database->stmtGameSelectById, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: SELECT-by-id failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_SELECT_GAME_BY_NAME, -1,
                            &database->stmtGameSelectByName, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: SELECT-by-name failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_LIST_GAMES, -1, &database->stmtGameList,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: LIST games failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_LIST_GAME_BRIEF_ALL, -1,
                            &database->stmtGameListAll, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: LIST brief all failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_LIST_GAME_BRIEF_RANGE, -1,
                            &database->stmtGameListRange, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: LIST brief range failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_LIST_GAME_BRIEF_PLAT_ALL, -1,
                            &database->stmtGameListPlatformAll, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: LIST brief plat all failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_LIST_GAME_BRIEF_PLAT_RANGE, -1,
                            &database->stmtGameListPlatformRange, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: LIST brief plat range failed: %s "
                  "(rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_GET_ENC_KEY, -1, &database->stmtGameGetKey,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: GET enc key failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_INSERT_PLATFORM, -1,
                            &database->stmtPlatformInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: INSERT platform failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_SELECT_PLATFORM, -1,
                            &database->stmtPlatformSelect, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: SELECT platform failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(h, SQL_LIST_PLATFORMS, -1,
                            &database->stmtPlatformList, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: LIST platforms failed: %s (rc=%d)",
                  sqlite3_errmsg(h), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────── internal: populate GameInfo from row ──────────────── */

static int populateGameInfo(sqlite3_stmt *stmt, GameInfo *out) {
    out->gameId = (uint32_t)sqlite3_column_int(stmt, ColGameId);
    const char *n = (const char *)sqlite3_column_text(stmt, ColName);
    const char *v = (const char *)sqlite3_column_text(stmt, ColVersion);
    const char *d = (const char *)sqlite3_column_text(stmt, ColDescription);
    if (n == NULL || v == NULL) {
        LOG_ERROR("populateGameInfo: unexpected NULL column");
        return DB_FAIL;
    }
    out->name = strdup(n);
    out->version = strdup(v);
    out->description = strdup(d != NULL ? d : "");
    if (out->name == NULL || out->version == NULL || out->description == NULL) {
        LOG_ERROR("populateGameInfo: strdup failed (errno=%d)", errno);
        free(out->name);
        free(out->version);
        free(out->description);
        memset(out, 0, sizeof(*out));
        return DB_FAIL;
    }
    out->platforms = NULL;
    out->platformCount = 0;
    out->createdAt = (time_t)sqlite3_column_int64(stmt, ColCreatedAt);
    out->updatedAt = (time_t)sqlite3_column_int64(stmt, ColUpdatedAt);
    return DB_SUCC;
}

/* ──────────────────── free helpers ──────────────────────────────────────── */

void gamePlatformInfoFree(GamePlatformInfo *info) {
    if (info == NULL) {
        return;
    }
    free(info->fileName);
    free(info->hash);
    info->fileName = NULL;
    info->hash = NULL;
}

void gamePlatformInfoArrayFree(GamePlatformInfo *arr, size_t count) {
    if (arr == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        gamePlatformInfoFree(&arr[i]);
    }
    free(arr);
}

void gameInfoFree(GameInfo *info) {
    if (info == NULL) {
        return;
    }
    free(info->name);
    free(info->version);
    free(info->description);
    info->name = NULL;
    info->version = NULL;
    info->description = NULL;
    if (info->platforms != NULL) {
        gamePlatformInfoArrayFree(info->platforms, info->platformCount);
        info->platforms = NULL;
        info->platformCount = 0;
    }
}

void gameInfoArrayFree(GameInfo *arr, size_t count) {
    if (arr == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        gameInfoFree(&arr[i]);
    }
    free(arr);
}

/* ──────────────────── public API: platform operations ──────────────────── */

int listGamePlatforms(DB *database, uint32_t gameId, GamePlatformInfo **out,
                      size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR("listGamePlatforms: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("listGamePlatforms: wrong database type %d",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    sqlite3_stmt *stmt = database->stmtPlatformList;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    if (sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameId) != SQLITE_OK) {
        LOG_ERROR("listGamePlatforms: bind failed: %s",
                  sqlite3_errmsg(database->handle));
        return DB_FAIL;
    }

    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    GamePlatformInfo *results = malloc(capacity * sizeof(GamePlatformInfo));
    if (results == NULL) {
        LOG_ERROR("listGamePlatforms: malloc failed (errno=%d)", errno);
        return DB_FAIL;
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("listGamePlatforms: result limit reached");
            break;
        }
        if (n >= capacity) {
            size_t newCap = capacity * 2;
            GamePlatformInfo *tmp =
                realloc(results, newCap * sizeof(GamePlatformInfo));
            if (tmp == NULL) {
                LOG_ERROR("listGamePlatforms: realloc failed (errno=%d)",
                          errno);
                gamePlatformInfoArrayFree(results, n);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCap;
        }

        memset(&results[n], 0, sizeof(GamePlatformInfo));
        const char *plat =
            (const char *)sqlite3_column_text(stmt, ColPlatPlatform);
        const char *fn =
            (const char *)sqlite3_column_text(stmt, ColPlatFileName);
        const char *h = (const char *)sqlite3_column_text(stmt, ColPlatHash);
        const char *r =
            (const char *)sqlite3_column_text(stmt, ColPlatRole);
        if (plat == NULL || fn == NULL || h == NULL || r == NULL) {
            LOG_ERROR("listGamePlatforms: unexpected NULL column");
            gamePlatformInfoArrayFree(results, n);
            return DB_FAIL;
        }
        strncpy(results[n].platform, plat, PLATFORM_NAME_LEN - 1);
        results[n].platform[PLATFORM_NAME_LEN - 1] = '\0';
        results[n].fileName = strdup(fn);
        results[n].hash = strdup(h);
        strncpy(results[n].role, r, sizeof(results[n].role) - 1);
        results[n].role[sizeof(results[n].role) - 1] = '\0';
        results[n].fileSize =
            (uint64_t)sqlite3_column_int64(stmt, ColPlatFileSize);
        if (results[n].fileName == NULL || results[n].hash == NULL) {
            LOG_ERROR("listGamePlatforms: strdup failed (errno=%d)", errno);
            gamePlatformInfoFree(&results[n]);
            gamePlatformInfoArrayFree(results, n);
            return DB_FAIL;
        }
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("listGamePlatforms: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        gamePlatformInfoArrayFree(results, n);
        return DB_FAIL;
    }

    if (n == 0) {
        free(results);
        *out = NULL;
        *count = 0;
        return DB_SUCC;
    }

    *out = results;
    *count = n;
    return DB_SUCC;
}

int registerGamePlatform(DB *database, uint32_t gameId,
                         const GamePlatformInfo *platform) {
    if (database == NULL || platform == NULL) {
        LOG_ERROR("registerGamePlatform: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("registerGamePlatform: wrong database type %d",
                  (int)database->type);
        return DB_FAIL;
    }
    if (platform->fileName == NULL || platform->hash == NULL) {
        LOG_ERROR("registerGamePlatform: NULL string field");
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtPlatformInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    enum {
        ParamGameId = 1,
        ParamPlatform = 2,
        ParamFileName = 3,
        ParamHash = 4,
        ParamFileSize = 5,
        ParamRole = 6
    };

    if (sqlite3_bind_int64(stmt, ParamGameId, (sqlite3_int64)gameId) !=
            SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamPlatform, platform->platform, -1,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamFileName, platform->fileName, -1,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamHash, platform->hash, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_int64(stmt, ParamFileSize,
                           (sqlite3_int64)platform->fileSize) != SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamRole, platform->role, -1,
                          SQLITE_STATIC) != SQLITE_OK) {
        LOG_ERROR("registerGamePlatform: bind failed: %s",
                  sqlite3_errmsg(database->handle));
        return DB_FAIL;
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("registerGamePlatform: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int getGamePlatform(DB *database, uint32_t gameId, const char *platform,
                    const char *role, GamePlatformInfo *out) {
    if (database == NULL || platform == NULL || role == NULL || out == NULL) {
        LOG_ERROR("getGamePlatform: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("getGamePlatform: wrong database type %d",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtPlatformSelect;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    enum { ParamGameId = 1, ParamPlatform = 2, ParamRole = 3 };

    if (sqlite3_bind_int64(stmt, ParamGameId, (sqlite3_int64)gameId) !=
            SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamPlatform, platform, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamRole, role, -1, SQLITE_STATIC) !=
            SQLITE_OK) {
        LOG_ERROR("getGamePlatform: bind failed: %s",
                  sqlite3_errmsg(database->handle));
        return DB_FAIL;
    }

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        const char *plat =
            (const char *)sqlite3_column_text(stmt, ColPlatPlatform);
        const char *fn =
            (const char *)sqlite3_column_text(stmt, ColPlatFileName);
        const char *h = (const char *)sqlite3_column_text(stmt, ColPlatHash);
        const char *r =
            (const char *)sqlite3_column_text(stmt, ColPlatRole);
        if (plat == NULL || fn == NULL || h == NULL || r == NULL) {
            LOG_ERROR("getGamePlatform: unexpected NULL column");
            return DB_FAIL;
        }
        strncpy(out->platform, plat, PLATFORM_NAME_LEN - 1);
        out->platform[PLATFORM_NAME_LEN - 1] = '\0';
        out->fileName = strdup(fn);
        out->hash = strdup(h);
        strncpy(out->role, r, sizeof(out->role) - 1);
        out->role[sizeof(out->role) - 1] = '\0';
        out->fileSize = (uint64_t)sqlite3_column_int64(stmt, ColPlatFileSize);
        if (out->fileName == NULL || out->hash == NULL) {
            LOG_ERROR("getGamePlatform: strdup failed (errno=%d)", errno);
            gamePlatformInfoFree(out);
            return DB_FAIL;
        }
        return DB_SUCC;
    }
    if (rc == SQLITE_DONE) {
        return DB_FAIL;
    }
    LOG_ERROR("getGamePlatform: step failed: %s (rc=%d)",
              sqlite3_errmsg(database->handle), rc);
    return DB_FAIL;
}

/* ──────────────────── public API: game operations ──────────────────────── */

int registerGame(DB *database, GameInfo *game, const uint8_t *encKeyEnvelope,
                 size_t envelopeLen) {
    if (database == NULL || game == NULL || encKeyEnvelope == NULL) {
        LOG_ERROR("registerGame: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("registerGame: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (game->name == NULL || game->version == NULL) {
        LOG_ERROR("registerGame: NULL string field");
        return DB_FAIL;
    }

    time_t now = time(NULL);

    sqlite3_stmt *stmt = database->stmtGameInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    enum {
        ParamName = 1,
        ParamVersion = 2,
        ParamDescription = 3,
        ParamEncKey = 4,
        ParamCreatedAt = 5,
        ParamUpdatedAt = 6
    };

    const char *desc = (game->description != NULL) ? game->description : "";

    if (sqlite3_bind_text(stmt, ParamName, game->name, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamVersion, game->version, -1,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamDescription, desc, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_blob(stmt, ParamEncKey, encKeyEnvelope, (int)envelopeLen,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, ParamCreatedAt, (sqlite3_int64)now) !=
            SQLITE_OK ||
        sqlite3_bind_int64(stmt, ParamUpdatedAt, (sqlite3_int64)now) !=
            SQLITE_OK) {
        LOG_ERROR("registerGame: bind failed: %s",
                  sqlite3_errmsg(database->handle));
        return DB_FAIL;
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("registerGame: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    game->gameId = (uint32_t)sqlite3_last_insert_rowid(database->handle);
    game->createdAt = now;
    game->updatedAt = now;

    return DB_SUCC;
}

int unregisterGame(DB *database, uint32_t gameId) {
    if (database == NULL) {
        LOG_ERROR("unregisterGame: NULL database");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("unregisterGame: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtGameDelete;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("unregisterGame: bind gameId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("unregisterGame: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("unregisterGame: gameId %u not found", gameId);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int updateGameVersion(DB *database, uint32_t gameId, const char *version) {
    if (database == NULL) {
        LOG_ERROR("updateGameVersion: NULL database");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("updateGameVersion: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (version == NULL) {
        LOG_ERROR("updateGameVersion: NULL version");
        return DB_FAIL;
    }

    time_t now = time(NULL);

    sqlite3_stmt *stmt = database->stmtGameUpdate;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    enum { ParamVersion = 1, ParamUpdatedAt = 2, ParamGameId = 3 };

    if (sqlite3_bind_text(stmt, ParamVersion, version, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_int64(stmt, ParamUpdatedAt, (sqlite3_int64)now) !=
            SQLITE_OK ||
        sqlite3_bind_int64(stmt, ParamGameId, (sqlite3_int64)gameId) !=
            SQLITE_OK) {
        LOG_ERROR("updateGameVersion: bind failed: %s",
                  sqlite3_errmsg(database->handle));
        return DB_FAIL;
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("updateGameVersion: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("updateGameVersion: gameId %u not found", gameId);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int getGameById(DB *database, uint32_t gameId, GameInfo *out) {
    if (database == NULL || out == NULL) {
        LOG_ERROR("getGameById: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("getGameById: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtGameSelectById;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("getGameById: bind gameId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        if (populateGameInfo(stmt, out) != DB_SUCC) {
            return DB_FAIL;
        }
        return listGamePlatforms(database, out->gameId, &out->platforms,
                                 &out->platformCount);
    }
    if (rc == SQLITE_DONE) {
        return DB_FAIL;
    }
    LOG_ERROR("getGameById: step failed: %s (rc=%d)",
              sqlite3_errmsg(database->handle), rc);
    return DB_FAIL;
}

int getGameByName(DB *database, const char *name, GameInfo *out) {
    if (database == NULL || name == NULL || out == NULL) {
        LOG_ERROR("getGameByName: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("getGameByName: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtGameSelectByName;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("getGameByName: bind name failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        if (populateGameInfo(stmt, out) != DB_SUCC) {
            return DB_FAIL;
        }
        return listGamePlatforms(database, out->gameId, &out->platforms,
                                 &out->platformCount);
    }
    if (rc == SQLITE_DONE) {
        return DB_FAIL;
    }
    LOG_ERROR("getGameByName: step failed: %s (rc=%d)",
              sqlite3_errmsg(database->handle), rc);
    return DB_FAIL;
}

int listRegisteredGames(DB *database, GameInfo **out, size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR("listRegisteredGames: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR(
            "listRegisteredGames: wrong database type %d (expected GameDB)",
            (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    sqlite3_stmt *stmt = database->stmtGameList;
    sqlite3_reset(stmt);

    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    GameInfo *results = malloc(capacity * sizeof(GameInfo));
    if (results == NULL) {
        LOG_ERROR("listRegisteredGames: malloc failed (errno=%d)", errno);
        return DB_FAIL;
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("listRegisteredGames: result limit reached");
            break;
        }

        if (n >= capacity) {
            size_t newCap = capacity * 2;
            GameInfo *tmp = realloc(results, newCap * sizeof(GameInfo));
            if (tmp == NULL) {
                LOG_ERROR("listRegisteredGames: realloc failed (errno=%d)",
                          errno);
                gameInfoArrayFree(results, n);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCap;
        }

        memset(&results[n], 0, sizeof(GameInfo));
        if (populateGameInfo(stmt, &results[n]) != DB_SUCC) {
            gameInfoArrayFree(results, n);
            return DB_FAIL;
        }
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("listRegisteredGames: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        gameInfoArrayFree(results, n);
        return DB_FAIL;
    }

    if (n == 0) {
        free(results);
        *out = NULL;
        *count = 0;
        return DB_SUCC;
    }

    *out = results;
    *count = n;
    return DB_SUCC;
}

int getGameEncKey(DB *database, uint32_t gameId, uint8_t **outEnvelope,
                  size_t *outLen) {
    if (database == NULL || outEnvelope == NULL || outLen == NULL) {
        LOG_ERROR("getGameEncKey: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("getGameEncKey: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *outEnvelope = NULL;
    *outLen = 0;

    sqlite3_stmt *stmt = database->stmtGameGetKey;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    if (sqlite3_bind_int64(stmt, 1, (sqlite3_int64)gameId) != SQLITE_OK) {
        LOG_ERROR("getGameEncKey: bind failed: %s",
                  sqlite3_errmsg(database->handle));
        return DB_FAIL;
    }

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blobLen = sqlite3_column_bytes(stmt, 0);
        if (blob == NULL || blobLen <= 0) {
            LOG_ERROR("getGameEncKey: empty or NULL encKey for gameId %u",
                      gameId);
            return DB_FAIL;
        }
        uint8_t *copy = malloc((size_t)blobLen);
        if (copy == NULL) {
            LOG_ERROR("getGameEncKey: malloc failed (errno=%d)", errno);
            return DB_FAIL;
        }
        memcpy(copy, blob, (size_t)blobLen);
        *outEnvelope = copy;
        *outLen = (size_t)blobLen;
        return DB_SUCC;
    }
    if (rc == SQLITE_DONE) {
        LOG_WARN("getGameEncKey: gameId %u not found", gameId);
        return DB_FAIL;
    }
    LOG_ERROR("getGameEncKey: step failed: %s (rc=%d)",
              sqlite3_errmsg(database->handle), rc);
    return DB_FAIL;
}

int listGameBrief(DB *database, uint32_t rangeStart, uint32_t rangeEnd,
                  const char *platform, GameInfoEntry **out, size_t *count) {
    if (database == NULL || out == NULL || count == NULL || platform == NULL) {
        LOG_ERROR("listGameBrief: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("listGameBrief: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    bool useAll = (rangeStart == 0 && rangeEnd == 0);
    bool filterPlatform = (platform[0] != '\0');

    if (!useAll && rangeStart > rangeEnd && rangeEnd != 0) {
        return DB_SUCC;
    }

    sqlite3_stmt *stmt;
    if (filterPlatform) {
        stmt = useAll ? database->stmtGameListPlatformAll
                      : database->stmtGameListPlatformRange;
    } else {
        stmt = useAll ? database->stmtGameListAll : database->stmtGameListRange;
    }

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    if (filterPlatform) {
        if (useAll) {
            enum { ParamPlatform = 1 };
            if (sqlite3_bind_text(stmt, ParamPlatform, platform, -1,
                                  SQLITE_STATIC) != SQLITE_OK) {
                LOG_ERROR("listGameBrief: bind platform failed: %s",
                          sqlite3_errmsg(database->handle));
                return DB_FAIL;
            }
        } else {
            enum { ParamRangeStart = 1, ParamRangeEnd = 2, ParamPlatform = 3 };
            if (sqlite3_bind_int64(stmt, ParamRangeStart,
                                   (sqlite3_int64)rangeStart) != SQLITE_OK ||
                sqlite3_bind_int64(stmt, ParamRangeEnd,
                                   (sqlite3_int64)rangeEnd) != SQLITE_OK ||
                sqlite3_bind_text(stmt, ParamPlatform, platform, -1,
                                  SQLITE_STATIC) != SQLITE_OK) {
                LOG_ERROR("listGameBrief: bind platform range failed: %s",
                          sqlite3_errmsg(database->handle));
                return DB_FAIL;
            }
        }
    } else if (!useAll) {
        enum { ParamRangeStart = 1, ParamRangeEnd = 2 };
        if (sqlite3_bind_int64(stmt, ParamRangeStart,
                               (sqlite3_int64)rangeStart) != SQLITE_OK ||
            sqlite3_bind_int64(stmt, ParamRangeEnd, (sqlite3_int64)rangeEnd) !=
                SQLITE_OK) {
            LOG_ERROR("listGameBrief: bind failed: %s",
                      sqlite3_errmsg(database->handle));
            return DB_FAIL;
        }
    }

    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    GameInfoEntry *results = malloc(capacity * sizeof(GameInfoEntry));
    if (results == NULL) {
        LOG_ERROR("listGameBrief: malloc failed (errno=%d)", errno);
        return DB_FAIL;
    }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("listGameBrief: result limit reached");
            break;
        }
        if (n >= capacity) {
            size_t newCap = capacity * 2;
            GameInfoEntry *tmp =
                realloc(results, newCap * sizeof(GameInfoEntry));
            if (tmp == NULL) {
                LOG_ERROR("listGameBrief: realloc failed (errno=%d)", errno);
                free(results);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCap;
        }

        memset(&results[n], 0, sizeof(GameInfoEntry));
        results[n].gameId = (uint32_t)sqlite3_column_int(stmt, ColGameId);

        const char *nameStr = (const char *)sqlite3_column_text(stmt, ColName);
        const char *verStr =
            (const char *)sqlite3_column_text(stmt, ColVersion);
        const char *descStr =
            (const char *)sqlite3_column_text(stmt, ColDescription);

        if (nameStr != NULL) {
            strncpy(results[n].name, nameStr, GAME_NAME_LEN - 1);
            results[n].name[GAME_NAME_LEN - 1] = '\0';
        }
        if (verStr != NULL) {
            strncpy(results[n].version, verStr, GAME_VERSION_LEN - 1);
            results[n].version[GAME_VERSION_LEN - 1] = '\0';
        }
        if (descStr != NULL) {
            strncpy(results[n].description, descStr, GAME_DESC_LEN - 1);
            results[n].description[GAME_DESC_LEN - 1] = '\0';
        }

        results[n].createdAt = sqlite3_column_int64(stmt, ColCreatedAt);
        results[n].updatedAt = sqlite3_column_int64(stmt, ColUpdatedAt);
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("listGameBrief: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        free(results);
        return DB_FAIL;
    }

    if (n == 0) {
        free(results);
        return DB_SUCC;
    }

    *out = results;
    *count = n;
    return DB_SUCC;
}
