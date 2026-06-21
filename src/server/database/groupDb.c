/**
 * @file groupDb.c
 * @brief Group database operations for PacPlay server.
 *
 * Implements CRUD operations for groups, group membership, and group chat
 * history.  Each group has its own chat table (group_<groupId>) created on
 * demand.  A global sequence table (msg_sequence) provides unique,
 * monotonically increasing message IDs across all groups.  Prepared
 * statements are cached per-group in a hash table and finalized
 * collectively at shutdown.
 *
 * @date 2026-06-21
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
#include "server/server.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ───────────────────────── SQL schema definitions ───────────────────────── */

/** @brief SQL to create the groups table. */
#define SQL_CREATE_GROUPS                                                      \
    "CREATE TABLE IF NOT EXISTS groups ("                                      \
    "groupId INTEGER PRIMARY KEY, "                                            \
    "groupName TEXT NOT NULL, "                                                \
    "ownerUid INTEGER NOT NULL, "                                              \
    "maxMembers INTEGER NOT NULL DEFAULT 50, "                                 \
    "createdAt INTEGER NOT NULL"                                               \
    ");"

/** @brief SQL to create the group_members table. */
#define SQL_CREATE_GROUP_MEMBERS                                               \
    "CREATE TABLE IF NOT EXISTS group_members ("                               \
    "groupId INTEGER NOT NULL, "                                               \
    "uid INTEGER NOT NULL, "                                                   \
    "joinedAt INTEGER NOT NULL, "                                              \
    "PRIMARY KEY(groupId, uid)"                                                \
    ");"

/** @brief SQL to create the group message sequence table. */
#define SQL_CREATE_GROUP_MSG_SEQUENCE                                          \
    "CREATE TABLE IF NOT EXISTS msg_sequence ("                                \
    "id INTEGER PRIMARY KEY AUTOINCREMENT"                                     \
    ");"

/* ──────────────────────── GroupDB prepared SQL ──────────────────────────── */

/** @brief INSERT into group sequence to generate next msgId. */
#define SQL_INSERT_GROUP_SEQUENCE "INSERT INTO msg_sequence DEFAULT VALUES;"

/** @brief INSERT into groups. ?1=groupId, ?2=groupName, ?3=ownerUid,
 *         ?4=createdAt. */
#define SQL_GROUP_INSERT                                                       \
    "INSERT INTO groups (groupId, groupName, ownerUid, createdAt) "            \
    "VALUES (?, ?, ?, ?);"

/** @brief DELETE from groups by groupId. ?1=groupId. */
#define SQL_GROUP_DELETE "DELETE FROM groups WHERE groupId = ?;"

/** @brief SELECT group info by groupId. ?1=groupId. */
#define SQL_GROUP_SELECT                                                       \
    "SELECT groupId, groupName, ownerUid, createdAt FROM groups "              \
    "WHERE groupId = ?;"

/** @brief SELECT all groups with member counts via LEFT JOIN. */
#define SQL_GROUP_LIST_ALL                                                     \
    "SELECT g.groupId, g.groupName, g.ownerUid, g.createdAt, "                 \
    "COUNT(m.uid) as memberCount "                                             \
    "FROM groups g LEFT JOIN group_members m ON g.groupId = m.groupId "        \
    "GROUP BY g.groupId ORDER BY g.groupId ASC;"

/** @brief INSERT into group_members. ?1=groupId, ?2=uid, ?3=joinedAt. */
#define SQL_MEMBER_INSERT                                                      \
    "INSERT INTO group_members (groupId, uid, joinedAt) VALUES (?, ?, ?);"

/** @brief DELETE from group_members. ?1=groupId, ?2=uid. */
#define SQL_MEMBER_DELETE                                                      \
    "DELETE FROM group_members WHERE groupId = ? AND uid = ?;"

/** @brief DELETE all members of a group. ?1=groupId. */
#define SQL_MEMBER_DELETE_ALL "DELETE FROM group_members WHERE groupId = ?;"

/** @brief SELECT 1 from group_members to check membership.
 *         ?1=groupId, ?2=uid. */
#define SQL_MEMBER_EXISTS                                                      \
    "SELECT 1 FROM group_members WHERE groupId = ? AND uid = ?;"

/** @brief SELECT uid from group_members for a given group. ?1=groupId. */
#define SQL_MEMBER_LIST                                                        \
    "SELECT uid FROM group_members WHERE groupId = ? ORDER BY uid ASC;"

/** @brief SELECT count of members for a group. ?1=groupId. */
#define SQL_MEMBER_COUNT "SELECT COUNT(*) FROM group_members WHERE groupId = ?;"

/* ──────────────────── group chat stmt cache management ──────────────────── */

/**
 * @brief Generate the table name for a given groupId.
 *
 * Writes "group_<groupId>" into the provided buffer.
 *
 * @param groupId  The group identifier.
 * @param buf      Output buffer (must be at least TABLE_NAME_BUF_SIZE bytes).
 */
static void groupTableName(uint32_t groupId, char buf[TABLE_NAME_BUF_SIZE]) {
    snprintf(buf, TABLE_NAME_BUF_SIZE, "group_%u", groupId);
}

/**
 * @brief Compute hash bucket index for a groupId.
 */
static unsigned int groupHashIndex(uint32_t groupId) {
    return groupId % GROUP_STMT_BUCKETS;
}

/**
 * @brief Look up a cached GroupStmtEntry by groupId.
 *
 * @param cache    The group statement cache.
 * @param groupId  Group to look up.
 * @return The entry if found, or NULL if not cached.
 */
static GroupStmtEntry *groupCacheLookup(GroupStmtCache *cache,
                                        uint32_t groupId) {
    unsigned int idx = groupHashIndex(groupId);
    GroupStmtEntry *entry = cache->buckets[idx];
    while (entry != NULL) {
        if (entry->groupId == groupId) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

/**
 * @brief Create the group chat table and indices if they do not exist.
 *
 * @param dbHandle   Raw sqlite3 handle.
 * @param tableName  Group table name (e.g., "group_1001").
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int createGroupChatTable(sqlite3 *dbHandle, const char *tableName) {
    char sql[SQL_BUF_SIZE];

    snprintf(sql, sizeof(sql),
             "CREATE TABLE IF NOT EXISTS %s ("
             "msgId INTEGER PRIMARY KEY, "
             "uid INTEGER NOT NULL, "
             "message TEXT NOT NULL, "
             "timestamp INTEGER NOT NULL"
             ");",
             tableName);
    if (dbExec(dbHandle, sql, "CREATE group chat table") != DB_SUCC) {
        return DB_FAIL;
    }

    snprintf(sql, sizeof(sql),
             "CREATE INDEX IF NOT EXISTS idx_%s_ts ON %s(timestamp);",
             tableName, tableName);
    if (dbExec(dbHandle, sql, "CREATE group chat ts index") != DB_SUCC) {
        return DB_FAIL;
    }

    snprintf(sql, sizeof(sql),
             "CREATE INDEX IF NOT EXISTS idx_%s_uid_ts ON %s(uid, timestamp);",
             tableName, tableName);
    if (dbExec(dbHandle, sql, "CREATE group chat uid_ts index") != DB_SUCC) {
        return DB_FAIL;
    }

    return DB_SUCC;
}

/**
 * @brief Prepare and cache all statements for a group.
 *
 * Creates the group chat table if it does not exist, compiles the recurring
 * SQL statements, and inserts a new GroupStmtEntry into the cache.
 *
 * @param database  The DB handle (GroupDB).
 * @param groupId   Group to prepare statements for.
 * @return The newly created entry, or NULL on failure.
 */
static GroupStmtEntry *groupCacheCreate(DB *database, uint32_t groupId) {
    char tableName[TABLE_NAME_BUF_SIZE];
    groupTableName(groupId, tableName);

    if (createGroupChatTable(database->handle, tableName) != DB_SUCC) {
        return NULL;
    }

    char sql[SQL_BUF_SIZE];
    GroupStmtEntry *entry = calloc(1, sizeof(GroupStmtEntry));
    if (entry == NULL) {
        LOG_ERROR("groupCacheCreate: calloc failed (errno=%d)", errno);
        return NULL;
    }
    entry->groupId = groupId;

    int rc;

    /* INSERT: ?1=msgId, ?2=uid, ?3=message, ?4=timestamp */
    snprintf(sql, sizeof(sql),
             "INSERT INTO %s (msgId, uid, message, timestamp) "
             "VALUES (?, ?, ?, ?);",
             tableName);
    rc =
        sqlite3_prepare_v2(database->handle, sql, -1, &entry->stmtInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupCacheCreate: INSERT prepare failed for %s: %s (rc=%d)",
                  tableName, sqlite3_errmsg(database->handle), rc);
        free(entry);
        return NULL;
    }

    /* SELECT chat history: ?1=beforeMsgId, ?2=limit.
     * Returns messages with msgId < beforeMsgId in chronological (ASC) order. */
    snprintf(sql, sizeof(sql),
             "SELECT msgId, uid, message, timestamp FROM %s "
             "WHERE msgId < ? ORDER BY msgId ASC LIMIT ?;",
             tableName);
    rc = sqlite3_prepare_v2(database->handle, sql, -1, &entry->stmtChatHistory,
                            NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupCacheCreate: chat history prepare failed for %s: "
                  "%s (rc=%d)",
                  tableName, sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(entry->stmtInsert);
        free(entry);
        return NULL;
    }

    /* SELECT last timestamp: no params */
    snprintf(sql, sizeof(sql), "SELECT MAX(timestamp) FROM %s;", tableName);
    rc =
        sqlite3_prepare_v2(database->handle, sql, -1, &entry->stmtLastTs, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupCacheCreate: last ts prepare failed for %s: %s (rc=%d)",
                  tableName, sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(entry->stmtInsert);
        sqlite3_finalize(entry->stmtChatHistory);
        free(entry);
        return NULL;
    }

    /* Insert into hash table at the head of the chain */
    unsigned int idx = groupHashIndex(groupId);
    entry->next = database->groupCache->buckets[idx];
    database->groupCache->buckets[idx] = entry;

    return entry;
}

/**
 * @brief Get or create cached statements for a group.
 *
 * Looks up the group in the cache; if not found, creates the chat table
 * and prepares all statements.
 *
 * @param database  The DB handle (GroupDB).
 * @param groupId   Group to get statements for.
 * @return The GroupStmtEntry, or NULL on failure.
 */
static GroupStmtEntry *getOrCreateGroupStmts(DB *database, uint32_t groupId) {
    GroupStmtEntry *entry = groupCacheLookup(database->groupCache, groupId);
    if (entry != NULL) {
        return entry;
    }
    return groupCacheCreate(database, groupId);
}

/**
 * @brief Free all entries in the group statement cache.
 *
 * Finalizes all prepared statements and frees all allocated memory.
 *
 * @param cache  The group statement cache to destroy (may be NULL).
 */
void groupCacheDestroy(GroupStmtCache *cache) {
    if (cache == NULL) {
        return;
    }
    for (unsigned int i = 0; i < GROUP_STMT_BUCKETS; i++) {
        GroupStmtEntry *entry = cache->buckets[i];
        while (entry != NULL) {
            GroupStmtEntry *next = entry->next;
            dbFinalize(&entry->stmtInsert);
            dbFinalize(&entry->stmtChatHistory);
            dbFinalize(&entry->stmtLastTs);
            free(entry);
            entry = next;
        }
    }
    free(cache);
}

/* ────────────────────────── schema init helper ──────────────────────────── */

int initGroupDBSchema(sqlite3 *dbHandle) {
    if (dbExec(dbHandle, SQL_CREATE_GROUPS, "CREATE TABLE groups") != DB_SUCC) {
        return DB_FAIL;
    }
    if (dbExec(dbHandle, SQL_CREATE_GROUP_MEMBERS,
               "CREATE TABLE group_members") != DB_SUCC) {
        return DB_FAIL;
    }
    return dbExec(dbHandle, SQL_CREATE_GROUP_MSG_SEQUENCE,
                  "CREATE TABLE msg_sequence");
}

/* ─────────────────────── GroupDB stmt preparation ───────────────────────── */

int prepareGroupGlobalStmts(DB *database) {
    int rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_GROUP_SEQUENCE, -1,
                                &database->stmtGroupSeq, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareGroupGlobalStmts: sequence prepare failed: "
                  "%s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ───────────────────────── private helpers ─────────────────────────────────
 */

/**
 * @brief Generate the next globally unique message ID for groups.
 *
 * @param database  An open GroupDB handle.
 * @param outMsgId  Output: the generated message ID.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int generateGroupMsgId(DB *database, uint64_t *outMsgId) {
    sqlite3_stmt *stmt = database->stmtGroupSeq;
    sqlite3_reset(stmt);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("generateGroupMsgId: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    *outMsgId = (uint64_t)sqlite3_last_insert_rowid(database->handle);
    return DB_SUCC;
}

/**
 * @brief Get the member count for a group via a COUNT query.
 *
 * @param database  An open GroupDB handle.
 * @param groupId   The group identifier.
 * @param outCount  Output: number of members.
 * @return @c DB_SUCC on success, @c DB_FAIL on failure.
 */
static int groupMemberCount(DB *database, uint32_t groupId,
                            uint32_t *outCount) {
    sqlite3_stmt *stmt = NULL;
    int rc =
        sqlite3_prepare_v2(database->handle, SQL_MEMBER_COUNT, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupMemberCount: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupMemberCount: bind groupId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        LOG_ERROR("groupMemberCount: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    *outCount = (uint32_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return DB_SUCC;
}

/* ───────────────────────── public API: groups ──────────────────────────────
 */

int groupCreate(DB *database, uint32_t groupId, const char *groupName,
                uint32_t ownerUid) {
    if (database == NULL || groupName == NULL || groupName[0] == '\0') {
        LOG_ERROR("groupCreate: NULL or empty argument (database=%p, "
                  "groupName=%p)",
                  (void *)database, (const void *)groupName);
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupCreate: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (groupId == 0 || ownerUid == 0) {
        LOG_ERROR("groupCreate: groupId and ownerUid must be non-zero "
                  "(groupId=%u, ownerUid=%u)",
                  groupId, ownerUid);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc =
        sqlite3_prepare_v2(database->handle, SQL_GROUP_INSERT, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupCreate: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupCreate: bind groupId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 2, groupName, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupCreate: bind groupName failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)ownerUid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupCreate: bind ownerUid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupCreate: bind createdAt failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("groupCreate: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int groupDelete(DB *database, uint32_t groupId) {
    if (database == NULL) {
        LOG_ERROR("groupDelete: NULL database");
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupDelete: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (groupId == 0) {
        LOG_ERROR("groupDelete: groupId must be non-zero");
        return DB_FAIL;
    }

    /* Drop the group chat table if it exists */
    char tableName[TABLE_NAME_BUF_SIZE];
    groupTableName(groupId, tableName);
    char sql[SQL_BUF_SIZE];
    snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS %s;", tableName);
    if (dbExec(database->handle, sql, "DROP group chat table") != DB_SUCC) {
        return DB_FAIL;
    }

    /* Delete all members */
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_MEMBER_DELETE_ALL, -1,
                                &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupDelete: prepare member delete all failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }
    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupDelete: bind groupId for members failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /* Delete the group itself */
    rc =
        sqlite3_prepare_v2(database->handle, SQL_GROUP_DELETE, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupDelete: prepare group delete failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }
    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupDelete: bind groupId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("groupDelete: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────────── public API: membership ───────────────────────────
 */

int groupAddMember(DB *database, uint32_t groupId, uint32_t uid) {
    if (database == NULL) {
        LOG_ERROR("groupAddMember: NULL database");
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupAddMember: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (groupId == 0 || uid == 0) {
        LOG_ERROR("groupAddMember: groupId and uid must be non-zero "
                  "(groupId=%u, uid=%u)",
                  groupId, uid);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_MEMBER_INSERT, -1, &stmt,
                                NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupAddMember: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupAddMember: bind groupId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupAddMember: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupAddMember: bind joinedAt failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("groupAddMember: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int groupRemoveMember(DB *database, uint32_t groupId, uint32_t uid) {
    if (database == NULL) {
        LOG_ERROR("groupRemoveMember: NULL database");
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR(
            "groupRemoveMember: wrong database type %d (expected GroupDB)",
            (int)database->type);
        return DB_FAIL;
    }
    if (groupId == 0 || uid == 0) {
        LOG_ERROR("groupRemoveMember: groupId and uid must be non-zero "
                  "(groupId=%u, uid=%u)",
                  groupId, uid);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_MEMBER_DELETE, -1, &stmt,
                                NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupRemoveMember: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupRemoveMember: bind groupId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupRemoveMember: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("groupRemoveMember: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int groupIsMember(DB *database, uint32_t groupId, uint32_t uid) {
    if (database == NULL) {
        LOG_ERROR("groupIsMember: NULL database");
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupIsMember: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (groupId == 0 || uid == 0) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_MEMBER_EXISTS, -1, &stmt,
                                NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupIsMember: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupIsMember: bind groupId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupIsMember: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_ROW) {
        return DB_SUCC;
    }
    if (rc == SQLITE_DONE) {
        return DB_FAIL;
    }

    LOG_ERROR("groupIsMember: step failed: %s (rc=%d)",
              sqlite3_errmsg(database->handle), rc);
    return DB_FAIL;
}

int groupMemberList(DB *database, uint32_t groupId, uint32_t **outUids,
                    size_t *count) {
    if (database == NULL || outUids == NULL || count == NULL) {
        LOG_ERROR("groupMemberList: NULL argument (database=%p, outUids=%p, "
                  "count=%p)",
                  (void *)database, (void *)outUids, (void *)count);
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupMemberList: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *outUids = NULL;
    *count = 0;

    if (groupId == 0) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc =
        sqlite3_prepare_v2(database->handle, SQL_MEMBER_LIST, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupMemberList: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupMemberList: bind groupId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    uint32_t *uids = malloc(capacity * sizeof(uint32_t));
    if (uids == NULL) {
        LOG_ERROR("groupMemberList: malloc failed (errno=%d)", errno);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("groupMemberList: result limit reached (%d)",
                     QUERY_MAX_RESULTS);
            break;
        }
        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            uint32_t *tmp = realloc(uids, newCapacity * sizeof(uint32_t));
            if (tmp == NULL) {
                LOG_ERROR("groupMemberList: realloc failed (errno=%d)", errno);
                free(uids);
                sqlite3_finalize(stmt);
                return DB_FAIL;
            }
            uids = tmp;
            capacity = newCapacity;
        }
        uids[n] = (uint32_t)sqlite3_column_int64(stmt, 0);
        n++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("groupMemberList: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        free(uids);
        return DB_FAIL;
    }

    if (n == 0) {
        free(uids);
        *outUids = NULL;
        *count = 0;
        return DB_SUCC;
    }

    *outUids = uids;
    *count = n;
    return DB_SUCC;
}

/* ──────────────────────── public API: group info ───────────────────────────
 */

int groupListAll(DB *database, GroupInfo **out, size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR("groupListAll: NULL argument (database=%p, out=%p, count=%p)",
                  (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupListAll: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(database->handle, SQL_GROUP_LIST_ALL, -1, &stmt,
                                NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupListAll: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    GroupInfo *results = malloc(capacity * sizeof(GroupInfo));
    if (results == NULL) {
        LOG_ERROR("groupListAll: malloc failed (errno=%d)", errno);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("groupListAll: result limit reached (%d)",
                     QUERY_MAX_RESULTS);
            break;
        }
        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            GroupInfo *tmp = realloc(results, newCapacity * sizeof(GroupInfo));
            if (tmp == NULL) {
                LOG_ERROR("groupListAll: realloc failed (errno=%d)", errno);
                free(results);
                sqlite3_finalize(stmt);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        results[n].groupId = (uint32_t)sqlite3_column_int64(stmt, 0);

        const char *nameText = (const char *)sqlite3_column_text(stmt, 1);
        if (nameText == NULL) {
            nameText = "";
        }
        /* NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy) */
        strncpy(results[n].groupName, nameText, GROUP_NAME_LEN - 1);
        results[n].groupName[GROUP_NAME_LEN - 1] = '\0';

        results[n].ownerUid = (uint32_t)sqlite3_column_int64(stmt, 2);
        results[n].createdAt = (uint64_t)sqlite3_column_int64(stmt, 3);
        results[n].memberCount =
            (uint32_t)sqlite3_column_int64(stmt, 4);

        n++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("groupListAll: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        free(results);
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

int groupGetInfo(DB *database, uint32_t groupId, GroupInfo *out) {
    if (database == NULL || out == NULL) {
        LOG_ERROR("groupGetInfo: NULL argument (database=%p, out=%p)",
                  (void *)database, (void *)out);
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupGetInfo: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (groupId == 0) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = NULL;
    int rc =
        sqlite3_prepare_v2(database->handle, SQL_GROUP_SELECT, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupGetInfo: prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)groupId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupGetInfo: bind groupId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }
    if (rc != SQLITE_ROW) {
        LOG_ERROR("groupGetInfo: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        sqlite3_finalize(stmt);
        return DB_FAIL;
    }

    out->groupId = (uint32_t)sqlite3_column_int64(stmt, 0);

    const char *nameText = (const char *)sqlite3_column_text(stmt, 1);
    if (nameText == NULL) {
        nameText = "";
    }
    /* NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy) */
    strncpy(out->groupName, nameText, GROUP_NAME_LEN - 1);
    out->groupName[GROUP_NAME_LEN - 1] = '\0';

    out->ownerUid = (uint32_t)sqlite3_column_int64(stmt, 2);
    out->createdAt = (uint64_t)sqlite3_column_int64(stmt, 3);

    uint32_t memberCnt = 0;
    if (groupMemberCount(database, groupId, &memberCnt) == DB_SUCC) {
        out->memberCount = memberCnt;
    } else {
        out->memberCount = 0;
    }

    sqlite3_finalize(stmt);
    return DB_SUCC;
}

/* ──────────────────────── public API: group chat ───────────────────────────
 */

int groupStoreChat(DB *database, uint32_t groupId, uint32_t uid,
                   const char *message, int64_t timestamp, uint64_t *outMsgId) {
    if (database == NULL || message == NULL || outMsgId == NULL) {
        LOG_ERROR("groupStoreChat: NULL argument (database=%p, message=%p, "
                  "outMsgId=%p)",
                  (void *)database, (const void *)message, (void *)outMsgId);
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupStoreChat: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (message[0] == '\0') {
        LOG_ERROR("groupStoreChat: message is empty");
        return DB_FAIL;
    }

    uint64_t msgId = 0;
    if (generateGroupMsgId(database, &msgId) != DB_SUCC) {
        return DB_FAIL;
    }

    GroupStmtEntry *entry = getOrCreateGroupStmts(database, groupId);
    if (entry == NULL) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = entry->stmtInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)msgId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupStoreChat: bind msgId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupStoreChat: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 3, message, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupStoreChat: bind message failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 4, timestamp);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupStoreChat: bind timestamp failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("groupStoreChat: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    *outMsgId = msgId;
    return DB_SUCC;
}

int groupChatHistory(DB *database, uint32_t groupId, uint32_t beforeMsgId,
                     uint32_t limit, Chat **out, size_t *count) {
    if (database == NULL || out == NULL || count == NULL) {
        LOG_ERROR("groupChatHistory: NULL argument "
                  "(database=%p, out=%p, count=%p)",
                  (void *)database, (void *)out, (void *)count);
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupChatHistory: wrong database type %d (expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    *out = NULL;
    *count = 0;

    if (limit == 0) {
        return DB_SUCC;
    }

    GroupStmtEntry *entry = getOrCreateGroupStmts(database, groupId);
    if (entry == NULL) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = entry->stmtChatHistory;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)beforeMsgId);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupChatHistory: bind beforeMsgId failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Bind limit, clamped to QUERY_MAX_RESULTS */
    uint32_t clampedLimit = limit;
    if (clampedLimit > QUERY_MAX_RESULTS) {
        clampedLimit = (uint32_t)QUERY_MAX_RESULTS;
    }
    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)clampedLimit);
    if (rc != SQLITE_OK) {
        LOG_ERROR("groupChatHistory: bind limit failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Iterate rows and build output array. Results are already in
     * chronological (ASC) msgId order from the query.
     */
    size_t capacity = QUERY_INITIAL_CAPACITY;
    size_t n = 0;
    Chat *results = malloc(capacity * sizeof(Chat));
    if (results == NULL) {
        LOG_ERROR("groupChatHistory: malloc failed (errno=%d)", errno);
        return DB_FAIL;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= QUERY_MAX_RESULTS) {
            LOG_WARN("groupChatHistory: result limit reached (%d)",
                     QUERY_MAX_RESULTS);
            break;
        }
        if (n >= capacity) {
            size_t newCapacity = capacity * 2;
            Chat *tmp = realloc(results, newCapacity * sizeof(Chat));
            if (tmp == NULL) {
                LOG_ERROR("groupChatHistory: realloc failed (errno=%d)", errno);
                for (size_t i = 0; i < n; i++) {
                    free(results[i].message);
                }
                free(results);
                return DB_FAIL;
            }
            results = tmp;
            capacity = newCapacity;
        }

        results[n].msgId = (uint64_t)sqlite3_column_int64(stmt, 0);
        results[n].uid = (uint32_t)sqlite3_column_int64(stmt, 1);

        const char *msgText = (const char *)sqlite3_column_text(stmt, 2);
        if (msgText == NULL) {
            LOG_ERROR("groupChatHistory: message column is NULL at row %zu", n);
            for (size_t i = 0; i < n; i++) {
                free(results[i].message);
            }
            free(results);
            return DB_FAIL;
        }
        results[n].message = strdup(msgText);
        if (results[n].message == NULL) {
            LOG_ERROR("groupChatHistory: strdup failed (errno=%d)", errno);
            for (size_t i = 0; i < n; i++) {
                free(results[i].message);
            }
            free(results);
            return DB_FAIL;
        }

        results[n].timestamp = (time_t)sqlite3_column_int64(stmt, 3);
        n++;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("groupChatHistory: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        for (size_t i = 0; i < n; i++) {
            free(results[i].message);
        }
        free(results);
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

int groupLastMsgTimestamp(DB *database, uint32_t groupId, uint64_t *outTs) {
    if (database == NULL || outTs == NULL) {
        LOG_ERROR(
            "groupLastMsgTimestamp: NULL argument (database=%p, outTs=%p)",
            (void *)database, (void *)outTs);
        return DB_FAIL;
    }
    if (database->type != GroupDB) {
        LOG_ERROR("groupLastMsgTimestamp: wrong database type %d "
                  "(expected GroupDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    GroupStmtEntry *entry = getOrCreateGroupStmts(database, groupId);
    if (entry == NULL) {
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = entry->stmtLastTs;
    sqlite3_reset(stmt);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (rc == SQLITE_DONE) {
            *outTs = 0;
            return DB_SUCC;
        }
        LOG_ERROR("groupLastMsgTimestamp: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
        *outTs = 0;
    } else {
        *outTs = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    return DB_SUCC;
}
