/**
 * @file serverDb.c
 * @brief Server key-value database operations for PacPlay server.
 *
 * Implements CRUD operations for the server_keys table, which stores
 * MK-encrypted key envelopes (DEK, per-database encryption keys).
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

#include "db.h"
#include "log.h"
#include "server/database.h"
#include "server/database/internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ───────────────────────── SQL schema definitions ───────────────────────── */

/** @brief CREATE the server keys table. */
#define SQL_CREATE_SERVER_KEYS_TABLE                                           \
    "CREATE TABLE IF NOT EXISTS server_keys ("                                 \
    "key_name TEXT PRIMARY KEY, "                                              \
    "key_value BLOB NOT NULL, "                                                \
    "created_at INTEGER NOT NULL"                                              \
    ");"

/* ──────────────────────── ServerDB prepared SQL ─────────────────────────── */

/** @brief INSERT OR REPLACE a server key. Params: ?1=key_name, ?2=key_value,
    ?3=created_at. */
#define SQL_UPSERT_SERVER_KEY                                                  \
    "INSERT OR REPLACE INTO server_keys (key_name, key_value, created_at) "    \
    "VALUES (?, ?, ?);"

/** @brief SELECT key_value by key name. Params: ?1=key_name.
    Columns: 0=key_value. */
#define SQL_SELECT_SERVER_KEY                                                  \
    "SELECT key_value FROM server_keys WHERE key_name = ?;"

/* ────────────────────────── schema init helper ──────────────────────────── */

int initServerDBSchema(sqlite3 *dbHandle) {
    return dbExec(dbHandle, SQL_CREATE_SERVER_KEYS_TABLE,
                  "CREATE TABLE server_keys");
}

/* ──────────────────────── ServerDB stmt preparation ─────────────────────── */

int prepareServerDBStmts(DB *database) {
    int rc;

    rc = sqlite3_prepare_v2(database->handle, SQL_UPSERT_SERVER_KEY, -1,
                            &database->stmtSetKey, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareServerDBStmts: UPSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_SERVER_KEY, -1,
                            &database->stmtGetKey, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareServerDBStmts: SELECT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ───────────────────────── public API: server keys ──────────────────────── */

int setServerKey(DB *database, const char *keyName, const uint8_t *value,
                 size_t valueLen) {
    if (database == NULL || keyName == NULL) {
        LOG_ERROR("setServerKey: NULL argument (database=%p, keyName=%p)",
                  (void *)database, (const void *)keyName);
        return DB_FAIL;
    }
    if (keyName[0] == '\0') {
        LOG_ERROR("setServerKey: keyName is empty");
        return DB_FAIL;
    }
    if (database->type != ServerDB) {
        LOG_ERROR("setServerKey: wrong database type %d (expected ServerDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (valueLen > 0 && value == NULL) {
        LOG_ERROR("setServerKey: value is NULL with positive valueLen (%zu)",
                  valueLen);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtSetKey;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_text(stmt, 1, keyName, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("setServerKey: bind key_name failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (valueLen > 0) {
        rc = sqlite3_bind_blob(stmt, 2, value, (int)valueLen, SQLITE_STATIC);
    } else {
        rc = sqlite3_bind_zeroblob(stmt, 2, 0);
    }
    if (rc != SQLITE_OK) {
        LOG_ERROR("setServerKey: bind key_value failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));
    if (rc != SQLITE_OK) {
        LOG_ERROR("setServerKey: bind created_at failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("setServerKey: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int getServerKey(DB *database, const char *keyName, uint8_t **outValue,
                 size_t *outLen) {
    *outValue = NULL;
    *outLen = 0;

    if (database == NULL || keyName == NULL || outValue == NULL ||
        outLen == NULL) {
        LOG_ERROR("getServerKey: NULL argument "
                  "(database=%p, keyName=%p, outValue=%p, outLen=%p)",
                  (void *)database, (const void *)keyName, (void *)outValue,
                  (void *)outLen);
        return DB_FAIL;
    }
    if (keyName[0] == '\0') {
        LOG_ERROR("getServerKey: keyName is empty");
        return DB_FAIL;
    }
    if (database->type != ServerDB) {
        LOG_ERROR("getServerKey: wrong database type %d (expected ServerDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtGetKey;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_text(stmt, 1, keyName, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("getServerKey: bind key_name failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        /* Key not found — not an error, output stays NULL/0 */
        return DB_SUCC;
    }
    if (rc != SQLITE_ROW) {
        LOG_ERROR("getServerKey: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Column 0 = key_value (BLOB) */
    int blobLen = sqlite3_column_bytes(stmt, 0);
    const void *blobData = sqlite3_column_blob(stmt, 0);

    if (blobLen > 0) {
        uint8_t *copy = malloc((size_t)blobLen);
        if (copy == NULL) {
            LOG_ERROR("getServerKey: malloc failed (errno=%d)", errno);
            return DB_FAIL;
        }
        if (blobData != NULL) {
            memcpy(copy, blobData, (size_t)blobLen);
        }
        *outValue = copy;
        *outLen = (size_t)blobLen;
    }

    return DB_SUCC;
}
