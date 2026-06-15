/**
 * @file gameDb.c
 * @brief Game metadata (registry) database operations for PacPlay server.
 *
 * Implements CRUD operations for the platform game registry.  Games are
 * stored in the games table and survive server restarts.
 *
 * @date 2026-06-15
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

/** @brief CREATE the games table for GameDB. */
#define SQL_CREATE_GAMES_TABLE                                                 \
    "CREATE TABLE IF NOT EXISTS games ("                                       \
    "gameId INTEGER PRIMARY KEY, "                                             \
    "name TEXT NOT NULL UNIQUE, "                                               \
    "version TEXT NOT NULL, "                                                   \
    "hash TEXT NOT NULL, "                                                      \
    "path TEXT NOT NULL, "                                                      \
    "createdAt INTEGER NOT NULL, "                                             \
    "updatedAt INTEGER NOT NULL"                                               \
    ");"

/* ──────────────────────── GameDB prepared SQL ───────────────────────────── */

/** @brief INSERT a game. Params: ?1..?7. */
#define SQL_INSERT_GAME                                                        \
    "INSERT INTO games (gameId, name, version, hash, path, createdAt, "       \
    "updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?);"

/** @brief DELETE a game by gameId. Params: ?1=gameId. */
#define SQL_DELETE_GAME "DELETE FROM games WHERE gameId = ?;"

/** @brief UPDATE version and hash. Params: ?1=version, ?2=hash, ?3=updatedAt, ?4=gameId. */
#define SQL_UPDATE_GAME                                                        \
    "UPDATE games SET version = ?, hash = ?, updatedAt = ? WHERE gameId = ?;"

/** @brief SELECT a game by gameId. Params: ?1=gameId. */
#define SQL_SELECT_GAME_BY_ID                                                  \
    "SELECT gameId, name, version, hash, path, createdAt, updatedAt "         \
    "FROM games WHERE gameId = ?;"

/** @brief SELECT a game by name. Params: ?1=name. */
#define SQL_SELECT_GAME_BY_NAME                                                \
    "SELECT gameId, name, version, hash, path, createdAt, updatedAt "         \
    "FROM games WHERE name = ?;"

/** @brief SELECT all games ordered by gameId ascending. */
#define SQL_LIST_GAMES                                                         \
    "SELECT gameId, name, version, hash, path, createdAt, updatedAt "         \
    "FROM games ORDER BY gameId ASC;"

/* ─────────────────── column / bind-parameter indices ────────────────────── */

enum {
    ColGameId = 0,
    ColName = 1,
    ColVersion = 2,
    ColHash = 3,
    ColPath = 4,
    ColCreatedAt = 5,
    ColUpdatedAt = 6
};

/* ────────────────────────── schema init helper ──────────────────────────── */

int initGameDBSchema(sqlite3 *dbHandle) {
    return dbExec(dbHandle, SQL_CREATE_GAMES_TABLE, "CREATE TABLE games");
}

/* ──────────────────────── GameDB stmt preparation ───────────────────────── */

int prepareGameDBStmts(DB *database) {
    int rc;

    rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_GAME, -1,
                            &database->stmtInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: INSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_DELETE_GAME, -1,
                            &database->stmtDelete, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: DELETE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_UPDATE_GAME, -1,
                            &database->stmtUpdate, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: UPDATE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_GAME_BY_ID, -1,
                            &database->stmtSelectById, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: SELECT-by-id prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_GAME_BY_NAME, -1,
                            &database->stmtSelectByName, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR(
            "prepareGameDBStmts: SELECT-by-name prepare failed: %s (rc=%d)",
            sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_LIST_GAMES, -1,
                            &database->stmtSelect, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGameDBStmts: SELECT-all prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────── internal: populate GameInfo from row ──────────────── */

static int populateGameInfo(sqlite3_stmt *stmt, GameInfo *out) {
    out->gameId = (uint32_t)sqlite3_column_int(stmt, ColGameId);
    const char *n = (const char *)sqlite3_column_text(stmt, ColName);
    const char *v = (const char *)sqlite3_column_text(stmt, ColVersion);
    const char *h = (const char *)sqlite3_column_text(stmt, ColHash);
    const char *p = (const char *)sqlite3_column_text(stmt, ColPath);
    if (n == NULL || v == NULL || h == NULL || p == NULL) {
        LOG_ERROR("populateGameInfo: unexpected NULL column");
        return DB_FAIL;
    }
    out->name = strdup(n);
    out->version = strdup(v);
    out->hash = strdup(h);
    out->path = strdup(p);
    if (out->name == NULL || out->version == NULL || out->hash == NULL ||
        out->path == NULL) {
        LOG_ERROR("populateGameInfo: strdup failed (errno=%d)", errno);
        gameInfoFree(out);
        memset(out, 0, sizeof(*out));
        return DB_FAIL;
    }
    out->createdAt = (time_t)sqlite3_column_int64(stmt, ColCreatedAt);
    out->updatedAt = (time_t)sqlite3_column_int64(stmt, ColUpdatedAt);
    return DB_SUCC;
}

/* ──────────────────── public API: game registry operations ──────────────── */

void gameInfoFree(GameInfo *info) {
    if (info == NULL) {
        return;
    }
    free(info->name);
    free(info->version);
    free(info->hash);
    free(info->path);
    info->name = NULL;
    info->version = NULL;
    info->hash = NULL;
    info->path = NULL;
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

int registerGame(DB *database, GameInfo *game) {
    if (database == NULL || game == NULL) {
        LOG_ERROR("registerGame: NULL argument");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("registerGame: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (game->gameId == 0) {
        LOG_ERROR("registerGame: gameId zero is reserved");
        return DB_FAIL;
    }
    if (game->name == NULL || game->version == NULL || game->hash == NULL ||
        game->path == NULL) {
        LOG_ERROR("registerGame: NULL string field");
        return DB_FAIL;
    }

    time_t now = time(NULL);

    sqlite3_stmt *stmt = database->stmtInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    enum {
        ParamGameId = 1,
        ParamName = 2,
        ParamVersion = 3,
        ParamHash = 4,
        ParamPath = 5,
        ParamCreatedAt = 6,
        ParamUpdatedAt = 7
    };

    if (sqlite3_bind_int64(stmt, ParamGameId,
                           (sqlite3_int64)game->gameId) != SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamName, game->name, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamVersion, game->version, -1,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamHash, game->hash, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamPath, game->path, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
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

    sqlite3_stmt *stmt = database->stmtDelete;
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

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int updateGameVersion(DB *database, uint32_t gameId, const char *version,
                      const char *hash) {
    if (database == NULL) {
        LOG_ERROR("updateGameVersion: NULL database");
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR(
            "updateGameVersion: wrong database type %d (expected GameDB)",
            (int)database->type);
        return DB_FAIL;
    }
    if (version == NULL || hash == NULL) {
        LOG_ERROR("updateGameVersion: NULL string argument");
        return DB_FAIL;
    }

    time_t now = time(NULL);

    sqlite3_stmt *stmt = database->stmtUpdate;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    enum {
        ParamVersion = 1,
        ParamHash = 2,
        ParamUpdatedAt = 3,
        ParamGameId = 4
    };

    if (sqlite3_bind_text(stmt, ParamVersion, version, -1, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_text(stmt, ParamHash, hash, -1, SQLITE_STATIC) !=
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

    sqlite3_stmt *stmt = database->stmtSelectById;
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
        return populateGameInfo(stmt, out);
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

    sqlite3_stmt *stmt = database->stmtSelectByName;
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
        return populateGameInfo(stmt, out);
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
        LOG_ERROR("listRegisteredGames: NULL argument (database=%p, out=%p, count=%p)",
                  (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != GameDB) {
        LOG_ERROR("listRegisteredGames: wrong database type %d (expected GameDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    sqlite3_stmt *stmt = database->stmtSelect;
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
            LOG_WARN("listRegisteredGames: result limit reached (%d)",
                     QUERY_MAX_RESULTS);
            break;
        }

        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            GameInfo *tmp =
                realloc(results, newCapacity * sizeof(GameInfo));
            if (tmp == NULL) {
                LOG_ERROR("listRegisteredGames: realloc failed (errno=%d)", errno);
                gameInfoArrayFree(results, n);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
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
