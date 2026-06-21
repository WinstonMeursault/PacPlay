/**
 * @file userDb.c
 * @brief User database operations for PacPlay server.
 *
 * Implements CRUD operations for the users table, including TOTP secret
 * encryption/decryption (AES-256-GCM via DEK) and CDBKey management.
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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

/* ───────────────────────── SQL schema definitions ───────────────────────── */

/** @brief SQL statement to create the users table.
 *
 * uid is server-assigned via random generation with uniqueness check;
 * AUTOINCREMENT is intentionally not used so that the server controls
 * the ID space. */
#define SQL_CREATE_USERS_TABLE                                                 \
    "CREATE TABLE IF NOT EXISTS users ("                                       \
    "uid INTEGER PRIMARY KEY, "                                                \
    "username TEXT UNIQUE NOT NULL, "                                          \
    "nickname TEXT NOT NULL, "                                                 \
    "password TEXT NOT NULL, "                                                 \
    "totp_secret BLOB, "                                                       \
    "cdbkey BLOB"                                                              \
    ");"

/* ────────────────────────── UserDB prepared SQL ─────────────────────────── */

/** @brief INSERT a user record. Params: ?1=uid, ?2=username, ?3=nickname,
    ?4=password. uid is server-generated and validated as unique before insert.
 */
#define SQL_INSERT_USER                                                        \
    "INSERT INTO users (uid, username, nickname, password, totp_secret, "      \
    "cdbkey) VALUES (?, ?, ?, ?, ?, ?);"

/** @brief DELETE a user by uid. Params: ?1=uid. */
#define SQL_DELETE_USER "DELETE FROM users WHERE uid = ?;"

/** @brief SELECT uid, nickname, password by username (uid is no longer
    required for authentication — the server assigns it on registration and
    returns it on login). Params: ?1=username.
    Columns: 0=uid, 1=nickname, 2=password. */
#define SQL_SELECT_USER_PASSWORD                                               \
    "SELECT uid, nickname, password, totp_secret FROM users WHERE username = " \
    "?;"

/** @brief Check whether a uid already exists. Params: ?1=uid. */
#define SQL_UID_CHECK "SELECT 1 FROM users WHERE uid = ?;"

/** @brief UPDATE totp_secret for a user. Params: ?1=secret, ?2=uid. */
#define SQL_SET_TOTP_SECRET "UPDATE users SET totp_secret = ? WHERE uid = ?;"

/** @brief SELECT totp_secret by uid. Params: ?1=uid. Columns: 0=totp_secret. */
#define SQL_SELECT_TOTP_BY_UID "SELECT totp_secret FROM users WHERE uid = ?;"

/** @brief SELECT cdbkey by uid. Params: ?1=uid. Columns: 0=cdbkey. */
#define SQL_SELECT_CDBKEY_BY_UID "SELECT cdbkey FROM users WHERE uid = ?;"

/* ────────────────────────── schema init helper ──────────────────────────── */

int initUserDBSchema(sqlite3 *dbHandle) {
    return dbExec(dbHandle, SQL_CREATE_USERS_TABLE, "CREATE TABLE users");
}

/* ──────────────────────── UserDB stmt preparation ───────────────────────── */

int prepareUserStmts(DB *database) {
    int rc;

    rc = sqlite3_prepare_v2(database->handle, SQL_INSERT_USER, -1,
                            &database->stmtInsert, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: INSERT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_DELETE_USER, -1,
                            &database->stmtDelete, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: DELETE prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_USER_PASSWORD, -1,
                            &database->stmtSelect, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: SELECT prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_UID_CHECK, -1,
                            &database->stmtUidCheck, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: UID check prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SET_TOTP_SECRET, -1,
                            &database->stmtSetTotpSecret, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR(
            "prepareUserStmts: SET totp_secret prepare failed: %s (rc=%d)",
            sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_TOTP_BY_UID, -1,
                            &database->stmtGetTOTPSecret, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR(
            "prepareUserStmts: SELECT totp_secret prepare failed: %s (rc=%d)",
            sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_prepare_v2(database->handle, SQL_SELECT_CDBKEY_BY_UID, -1,
                            &database->stmtGetCDBKey, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("prepareUserStmts: SELECT cdbkey prepare failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

/* ──────────────────── DEK AES-256-GCM envelope helpers ──────────────────── */

/**
 * @brief Encrypt arbitrary data with the DEK via AES-256-GCM.
 *
 * Returns a heap-allocated BLOB in the format
 * @c nonce(12) @c || @c ciphertext(n) @c || @c tag(16).
 * The caller must @c free() the returned pointer.
 *
 * @param data     Pointer to plaintext data.
 * @param dataLen  Length of @p data in bytes.
 * @param dekKey   Pointer to 32-byte DEK.
 * @param outLen   Receives the total encrypted blob length.
 * @return Heap-allocated encrypted blob, or NULL on failure.
 */
static uint8_t *encryptBlob(const uint8_t *data, size_t dataLen,
                            const uint8_t *dekKey, size_t *outLen) {
    AESGCMKey key;
    memcpy(key.key, dekKey, AES_GCM_KEY_LEN);
    if (cryptoRandomBytes(key.nonce, AES_GCM_NONCE_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("encryptBlob: nonce generation failed");
        return NULL;
    }

    AESGCMBuffer pt = {.data = (uint8_t *)(uintptr_t)data,
                       .len = dataLen,
                       .capacity = dataLen};
    AESGCMCipher ct;
    if (aesGCMBufferInit(&ct.buffer, dataLen) != CRYPTO_SUCC) {
        return NULL;
    }

    if (encryptAESGCM(&pt, NULL, &key, &ct) != CRYPTO_SUCC) {
        LOG_ERROR("encryptBlob: encryption failed");
        aesGCMBufferDeinit(&ct.buffer);
        return NULL;
    }

    size_t total = AES_GCM_NONCE_LEN + dataLen + AES_GCM_TAG_LEN;
    uint8_t *blob = malloc(total);
    if (blob == NULL) {
        LOG_ERROR("encryptBlob: malloc failed (errno=%d)", errno);
        aesGCMBufferDeinit(&ct.buffer);
        return NULL;
    }

    memcpy(blob, key.nonce, AES_GCM_NONCE_LEN);
    memcpy(blob + AES_GCM_NONCE_LEN, ct.buffer.data, dataLen);
    memcpy(blob + AES_GCM_NONCE_LEN + dataLen, ct.tag, AES_GCM_TAG_LEN);
    *outLen = total;

    aesGCMBufferDeinit(&ct.buffer);
    return blob;
}

/**
 * @brief Decrypt a DEK-encrypted envelope via AES-256-GCM.
 *
 * Parses the @c nonce @c || @c ciphertext @c || @c tag BLOB, decrypts,
 * and returns the heap-allocated plaintext.  The caller must @c free()
 * the returned pointer.
 *
 * @param blob      Encrypted BLOB (nonce + CT + tag).
 * @param blobLen   Total length of @p blob.
 * @param dekKey    Pointer to 32-byte DEK.
 * @param outLen    Receives the plaintext length in bytes.
 * @return Heap-allocated plaintext, or NULL on failure.
 */
static uint8_t *decryptBlob(const uint8_t *blob, size_t blobLen,
                            const uint8_t *dekKey, size_t *outLen) {
    if (blobLen < AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN) {
        LOG_ERROR("decryptBlob: blob too short (%zu bytes)", blobLen);
        return NULL;
    }

    size_t ctLen = blobLen - AES_GCM_NONCE_LEN - AES_GCM_TAG_LEN;
    AESGCMKey key;
    memcpy(key.key, dekKey, AES_GCM_KEY_LEN);
    memcpy(key.nonce, blob, AES_GCM_NONCE_LEN);

    AESGCMCipher ct;
    ct.buffer.data = (uint8_t *)(uintptr_t)(blob + AES_GCM_NONCE_LEN);
    ct.buffer.len = ctLen;
    ct.buffer.capacity = ctLen;
    memcpy(ct.tag, blob + AES_GCM_NONCE_LEN + ctLen, AES_GCM_TAG_LEN);

    AESGCMBuffer pt;
    if (aesGCMBufferInit(&pt, ctLen) != CRYPTO_SUCC) {
        return NULL;
    }

    int ret = decryptAESGCM(&ct, NULL, &key, &pt);
    if (ret != CRYPTO_SUCC) {
        aesGCMBufferDeinit(&pt);
        if (ret == CRYPTO_AUTH_FAIL) {
            LOG_ERROR("decryptBlob: authentication failed — wrong DEK?");
        }
        return NULL;
    }

    uint8_t *result = malloc(pt.len);
    if (result == NULL) {
        LOG_ERROR("decryptBlob: malloc failed (errno=%d)", errno);
        aesGCMBufferDeinit(&pt);
        return NULL;
    }
    memcpy(result, pt.data, pt.len);
    *outLen = pt.len;
    aesGCMBufferDeinit(&pt);
    return result;
}

/* ────────────────────── TOTP / CDBKey thin wrappers ─────────────────────── */

static uint8_t *encryptTOTP(const char *secret, const uint8_t *dekKey,
                            size_t *outLen) {
    return encryptBlob((const uint8_t *)secret, strlen(secret), dekKey, outLen);
}

static char *decryptTOTP(const uint8_t *blob, size_t blobLen,
                         const uint8_t *dekKey) {
    size_t ptLen = 0;
    uint8_t *pt = decryptBlob(blob, blobLen, dekKey, &ptLen);
    if (pt == NULL) {
        return NULL;
    }
    char *result = malloc(ptLen + 1);
    if (result == NULL) {
        LOG_ERROR("decryptTOTP: malloc failed (errno=%d)", errno);
        free(pt);
        return NULL;
    }
    memcpy(result, pt, ptLen);
    result[ptLen] = '\0';
    free(pt);
    return result;
}

static int decryptCDBKey(const uint8_t *blob, size_t blobLen,
                         const uint8_t *dekKey,
                         uint8_t outKey[DB_ENC_KEY_LEN]) {
    size_t ptLen = 0;
    uint8_t *pt = decryptBlob(blob, blobLen, dekKey, &ptLen);
    if (pt == NULL) {
        return DB_FAIL;
    }
    if (ptLen != DB_ENC_KEY_LEN) {
        LOG_ERROR("decryptCDBKey: wrong plaintext length (%zu, expected %d)",
                  ptLen, DB_ENC_KEY_LEN);
        free(pt);
        return DB_FAIL;
    }
    memcpy(outKey, pt, DB_ENC_KEY_LEN);
    free(pt);
    return DB_SUCC;
}

/* ────────────────────── public API: user operations ─────────────────────── */

int createUser(DB *database, User *user) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("createUser: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("createUser: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (user->password == NULL || user->password[0] == '\0') {
        LOG_ERROR("createUser: password is NULL or empty");
        return DB_FAIL;
    }
    if (user->username[0] == '\0') {
        LOG_ERROR("createUser: username is empty");
        return DB_FAIL;
    }
    if (user->nickname[0] == '\0') {
        LOG_ERROR("createUser: nickname is empty");
        return DB_FAIL;
    }

    /* Generate a unique random uid.  Loop with a hard limit to prevent
     * theoretical infinite spinning when the ID space is nearly exhausted. */
    enum { MaxAttempts = 10 };
    int found = 0;
    for (int attempt = 0; attempt < MaxAttempts; attempt++) {
        uint32_t candidate = 0;
        /* RAND_bytes is cryptographically strong and seeded by the OS. */
        if (RAND_bytes((unsigned char *)&candidate, (int)sizeof(candidate)) !=
            1) {
            LOG_ERROR("createUser: RAND_bytes failed on attempt %d", attempt);
            continue;
        }
        /* uid 0 is reserved for the "no user" sentinel. */
        if (candidate == 0) {
            continue;
        }

        sqlite3_stmt *checkStmt = database->stmtUidCheck;
        sqlite3_reset(checkStmt);
        sqlite3_clear_bindings(checkStmt);
        int rc = sqlite3_bind_int64(checkStmt, 1, (sqlite3_int64)candidate);
        if (rc != SQLITE_OK) {
            LOG_ERROR("createUser: bind uid check failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
            continue;
        }
        rc = sqlite3_step(checkStmt);
        if (rc == SQLITE_DONE) {
            /* No row returned — uid is unique. */
            user->uid = candidate;
            found = 1;
            break;
        }
        if (rc != SQLITE_ROW) {
            LOG_ERROR("createUser: uid check step failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
        }
        /* UID collision — loop and try another random value. */
    }

    if (!found) {
        LOG_ERROR("createUser: failed to generate unique uid after %d attempts",
                  MaxAttempts);
        return DB_FAIL;
    }

    /* Generate a 256-bit per-user CDBKey (Client Database Key). */
    uint8_t cdbKey[DB_ENC_KEY_LEN];
    if (cryptoRandomBytes(cdbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("createUser: CDBKey generation failed");
        return DB_FAIL;
    }

    /* Hash the plaintext password for secure storage */
    char *hashed = hashPassword(user->password);
    if (hashed == NULL) {
        LOG_ERROR("createUser: hashPassword failed");
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtInsert;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 2, user->username, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind username failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 3, user->nickname, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind nickname failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    rc = sqlite3_bind_text(stmt, 4, hashed, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind password failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    enum { TotpBindIndex = 5, CdbkeyBindIndex = 6 };
    if (user->totpSecret != NULL) {
        size_t encLen = 0;
        uint8_t *enc = encryptTOTP(user->totpSecret, database->dekKey, &encLen);
        if (enc == NULL) {
            OPENSSL_cleanse(hashed, strlen(hashed));
            free(hashed);
            OPENSSL_cleanse(cdbKey, sizeof(cdbKey));
            return DB_FAIL;
        }
        rc = sqlite3_bind_blob(stmt, TotpBindIndex, enc, (int)encLen, free);
    } else {
        rc = sqlite3_bind_null(stmt, TotpBindIndex);
    }
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind totp_secret failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        OPENSSL_cleanse(cdbKey, sizeof(cdbKey));
        return DB_FAIL;
    }

    size_t cdbkeyEncLen = 0;
    uint8_t *cdbkeyEnc =
        encryptBlob(cdbKey, DB_ENC_KEY_LEN, database->dekKey, &cdbkeyEncLen);
    OPENSSL_cleanse(cdbKey, sizeof(cdbKey));
    if (cdbkeyEnc == NULL) {
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }
    rc = sqlite3_bind_blob(stmt, CdbkeyBindIndex, cdbkeyEnc, (int)cdbkeyEncLen,
                           free);
    if (rc != SQLITE_OK) {
        LOG_ERROR("createUser: bind cdbkey failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        OPENSSL_cleanse(hashed, strlen(hashed));
        free(hashed);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);

    /* Securely wipe the hashed password from memory */
    OPENSSL_cleanse(hashed, strlen(hashed));
    free(hashed);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("createUser: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int deleteUser(DB *database, User *user) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("deleteUser: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("deleteUser: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtDelete;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("deleteUser: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("deleteUser: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    /* Strict mode: fail if no rows were affected */
    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("deleteUser: uid %u not found in database", user->uid);
        return DB_FAIL;
    }

    return DB_SUCC;
}

int verifyUser(DB *database, User *user) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("verifyUser: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("verifyUser: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }
    if (user->password == NULL || user->password[0] == '\0') {
        LOG_ERROR("verifyUser: password is NULL or empty");
        return DB_FAIL;
    }
    if (user->username[0] == '\0') {
        LOG_ERROR("verifyUser: username is empty");
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtSelect;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Look up by username only — UID is server-assigned and the client
     * does not know it before a successful login. */
    int rc = sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        LOG_ERROR("verifyUser: bind username failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (rc != SQLITE_DONE) {
            LOG_ERROR("verifyUser: step failed: %s (rc=%d)",
                      sqlite3_errmsg(database->handle), rc);
        }
        return DB_FAIL;
    }

    /* Columns: 0=uid, 1=nickname, 2=password, 3=totp_secret */
    user->uid = (uint32_t)sqlite3_column_int64(stmt, 0);

    const char *storedNickname = (const char *)sqlite3_column_text(stmt, 1);
    if (storedNickname == NULL) {
        LOG_ERROR("verifyUser: stored nickname is NULL");
        return DB_FAIL;
    }

    const char *storedHash = (const char *)sqlite3_column_text(stmt, 2);
    if (storedHash == NULL) {
        LOG_ERROR("verifyUser: stored password hash is NULL");
        return DB_FAIL;
    }

    int result = verifyPassword(user->password, storedHash);
    if (result != CRYPTO_SUCC) {
        return DB_FAIL;
    }

    const void *storedTotpBlob = sqlite3_column_blob(stmt, 3);
    int storedTotpLen = sqlite3_column_bytes(stmt, 3);
    if (storedTotpBlob != NULL && storedTotpLen > 0) {
        user->totpSecret = decryptTOTP((const uint8_t *)storedTotpBlob,
                                       (size_t)storedTotpLen, database->dekKey);
        if (user->totpSecret == NULL) {
            return DB_FAIL;
        }
    } else {
        user->totpSecret = NULL;
    }

    strncpy(user->nickname, storedNickname, NICKNAME_MAX_LEN - 1);
    user->nickname[NICKNAME_MAX_LEN - 1] = '\0';
    return DB_SUCC;
}

/* ──────────────────── public API: TOTP / CDBKey operations ──────────────── */

/**
 * @brief Read and decrypt the TOTP secret for a user.
 *
 * @param database  UserDB handle with DEK set.
 * @param user      User whose @c uid identifies the row.
 * @return Heap-allocated plaintext Base32 secret, or NULL.
 */
char *getTOTPSecret(DB *database, User *user) {
    sqlite3_stmt *stmt = database->stmtGetTOTPSecret;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("getTOTPSecret: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return NULL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        return NULL;
    }
    if (rc != SQLITE_ROW) {
        return NULL;
    }

    const void *blobData = sqlite3_column_blob(stmt, 0);
    int blobLen = sqlite3_column_bytes(stmt, 0);
    if (blobData == NULL || blobLen == 0) {
        return NULL;
    }

    return decryptTOTP((const uint8_t *)blobData, (size_t)blobLen,
                       database->dekKey);
}

int getCDBKey(DB *database, uint32_t uid, uint8_t outKey[DB_ENC_KEY_LEN]) {
    if (database == NULL) {
        LOG_ERROR("getCDBKey: NULL database");
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("getCDBKey: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtGetCDBKey;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("getCDBKey: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        LOG_ERROR("getCDBKey: uid %u not found or has no cdbkey", uid);
        return DB_FAIL;
    }
    if (rc != SQLITE_ROW) {
        LOG_ERROR("getCDBKey: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    const void *blobData = sqlite3_column_blob(stmt, 0);
    int blobLen = sqlite3_column_bytes(stmt, 0);
    if (blobData == NULL || blobLen == 0) {
        LOG_ERROR("getCDBKey: uid %u has NULL or empty cdbkey", uid);
        return DB_FAIL;
    }

    return decryptCDBKey((const uint8_t *)blobData, (size_t)blobLen,
                         database->dekKey, outKey);
}

int setTOTPSecret(DB *database, User *user, const char *secret) {
    if (database == NULL || user == NULL) {
        LOG_ERROR("setTOTPSecret: NULL argument (database=%p, user=%p)",
                  (void *)database, (void *)user);
        return DB_FAIL;
    }
    if (database->type != UserDB) {
        LOG_ERROR("setTOTPSecret: wrong database type %d (expected UserDB)",
                  (int)database->type);
        return DB_FAIL;
    }

    sqlite3_stmt *stmt = database->stmtSetTotpSecret;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    int rc;
    if (secret != NULL && secret[0] != '\0') {
        size_t encLen = 0;
        uint8_t *enc = encryptTOTP(secret, database->dekKey, &encLen);
        if (enc == NULL) {
            return DB_FAIL;
        }
        rc = sqlite3_bind_blob(stmt, 1, enc, (int)encLen, free);
    } else {
        rc = sqlite3_bind_null(stmt, 1);
    }
    if (rc != SQLITE_OK) {
        LOG_ERROR("setTOTPSecret: bind secret failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64)user->uid);
    if (rc != SQLITE_OK) {
        LOG_ERROR("setTOTPSecret: bind uid failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("setTOTPSecret: step failed: %s (rc=%d)",
                  sqlite3_errmsg(database->handle), rc);
        return DB_FAIL;
    }

    if (sqlite3_changes(database->handle) == 0) {
        LOG_WARN("setTOTPSecret: uid %u not found in database", user->uid);
        return DB_FAIL;
    }

    return DB_SUCC;
}
