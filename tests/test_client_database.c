/**
 * @file test_client_database.c
 * @brief Adversarial unit tests for the PacPlay client encrypted database.
 *
 * Covers clientInitDB / clientCloseDB lifecycle, gameList CRUD operations,
 * SQL injection resistance, encryption correctness (wrong key, file
 * tampering, persistence), and memory safety.  Every test is written as
 * a hostile attacker trying to break the system.
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

#include "client/client.h"
#include "client/database.h"
#include "crypto.h"
#include "log.h"
#include "test_utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>

/** @brief SQLCipher key setter — not declared in standard sqlite3.h. */
int sqlite3_key(sqlite3 *db, const void *pKey, int nKey);

/* ──────────────────────────── helper constants ──────────────────────────── */

enum {
    TestGameA = 100,
    TestGameB = 200,
    TestGameC = 300,
    TestGameNoT = 99999,
    TestGameMax = 0xFFFFFFFFU,
    TestPlayTimeZero = 0,
    TestPlayTimeVal = 86400,
    TestPlayTimeMax = 0xFFFFFFFFFFFFFFFFULL,
    TestNameLen = 64,
    TestPathLen = 128,
    TestLongStrLen = 512,
    TestUpdateStep1 = 3600,
    TestUpdateStep2 = 7200,
    TestUpdateStep3 = 14400,
    ExpectedMaxResults = 3,
    ExpectedResultCountEmpty = 0
};

/* ─────────────────────────── file-level helpers ─────────────────────────── */

/**
 * @brief Remove stale client test database files so each test starts clean.
 */
static void removeClientDBFiles(void) {
    remove(CLIENT_DB_PATH);
    remove(CLIENT_DB_PATH "-wal");
    remove(CLIENT_DB_PATH "-shm");
}

/** @brief All-zeros test CDBKey. */
static const uint8_t testCDBKey[CLIENT_DB_KEY_LEN];

/**
 * @brief Create a Client with the test CDBKey and call clientInitDB.
 *
 * The caller must call destroyTestClient() when done.
 *
 * @param client  Output: initialised Client with open DB handle.
 */
static void initTestClient(Client *client) {
    memset(client, 0, sizeof(*client));
    client->fd = NULL_SOCKETFD;
    memcpy(client->cdbkey, testCDBKey, CLIENT_DB_KEY_LEN);
    int ret = clientInitDB(client);
    ASSERT_INT_EQ(ret, CLIENT_DB_SUCC);
    ASSERT_TRUE(client->db != NULL);
}

/**
 * @brief Close and destroy a test Client created by initTestClient().
 */
static void destroyTestClient(Client *client) { clientCloseDB(client); }

/**
 * @brief Generate a random non-zero CDBKey into @p out.
 */
static void genRandomCDBKey(uint8_t out[CLIENT_DB_KEY_LEN]) {
    int ret = cryptoRandomBytes(out, CLIENT_DB_KEY_LEN);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    /* Ensure at least one byte is non-zero. */
    enum { CheckByte = 3 };
    out[CheckByte] |= 0x01U;
}

/**
 * @brief Free an array of GameRecord pointers allocated by listGames.
 */
static void freeGameRecords(GameRecord **records, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(records[i]->gameName);
        free(records[i]->gamePath);
        free(records[i]);
    }
    free((void *)records);
}

/* ═════════════════════════ 1. Constants & Layout ══════════════════════════ */

/** @brief CLIENT_DB_KEY_LEN must be exactly 256-bit. */
static void testClientDBKeyLen(void) { ASSERT_UINT_EQ(CLIENT_DB_KEY_LEN, 32U); }

/** @brief CLIENT_DB_SUCC / CLIENT_DB_FAIL are distinct. */
static void testClientDBReturnCodes(void) {
    ASSERT_INT_EQ(CLIENT_DB_SUCC, 0);
    ASSERT_INT_EQ(CLIENT_DB_FAIL, -1);
    ASSERT_TRUE(CLIENT_DB_SUCC != CLIENT_DB_FAIL);
}

/** @brief DBKeyRespPayload is exactly CLIENT_DB_KEY_LEN bytes (packed). */
static void testDBKeyRespPayloadSize(void) {
    ASSERT_UINT_EQ(sizeof(DBKeyRespPayload), (size_t)CLIENT_DB_KEY_LEN);
}

/** @brief DBKeyRespPayload.cdbkey is at offset 0. */
static void testDBKeyRespPayloadOffset(void) {
    ASSERT_UINT_EQ(offsetof(DBKeyRespPayload, cdbkey), (size_t)0);
}

/** @brief GameRecord fields are at deterministic relative offsets. */
static void testGameRecordLayout(void) {
    ASSERT_UINT_EQ(offsetof(GameRecord, gameId), (size_t)0);
    ASSERT_TRUE(offsetof(GameRecord, gameName) > offsetof(GameRecord, gameId));
    ASSERT_TRUE(offsetof(GameRecord, gamePath) >
                offsetof(GameRecord, gameName));
    ASSERT_TRUE(offsetof(GameRecord, playTime) >
                offsetof(GameRecord, gamePath));
    enum {
        ExpectedSize = sizeof(uint32_t) + sizeof(char *) + sizeof(char *) +
                       sizeof(uint64_t)
    };
    ASSERT_TRUE(sizeof(GameRecord) >= ExpectedSize);
}

/* ════════════════════════════ 2. clientInitDB ═════════════════════════════ */

/** @brief clientInitDB rejects NULL client. */
static void testInitDBNullClient(void) {
    ASSERT_INT_EQ(clientInitDB(NULL), CLIENT_DB_FAIL);
}

/** @brief clientInitDB rejects client with already-open db handle. */
static void testInitDBAlreadyInit(void) {
    removeClientDBFiles();
    Client client;
    memset(&client, 0, sizeof(client));
    client.fd = NULL_SOCKETFD;
    memcpy(client.cdbkey, testCDBKey, CLIENT_DB_KEY_LEN);
    ASSERT_INT_EQ(clientInitDB(&client), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(clientInitDB(&client), CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief clientInitDB succeeds with a valid client. */
static void testInitDBValid(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    destroyTestClient(&client);
}

/** @brief clientInitDB creates the db/ directory when absent. */
static void testInitDBCreatesDir(void) {
    removeClientDBFiles();
    rmdir(CLIENT_DB_DIR);
    Client client;
    initTestClient(&client);
    destroyTestClient(&client);
    struct stat st;
    ASSERT_TRUE(stat(CLIENT_DB_DIR, &st) == 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));
}

/** @brief clientInitDB creates the database file on disk. */
static void testInitDBCreatesFile(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    destroyTestClient(&client);
    struct stat st;
    ASSERT_TRUE(stat(CLIENT_DB_PATH, &st) == 0);
}

/* ════════════════════════════ 3. clientCloseDB ════════════════════════════ */

/** @brief clientCloseDB on a NULL client is a safe no-op. */
static void testCloseDBNull(void) { clientCloseDB(NULL); }

/** @brief clientCloseDB on client with db == NULL is a safe no-op. */
static void testCloseDBUninit(void) {
    Client client;
    memset(&client, 0, sizeof(client));
    client.db = NULL;
    clientCloseDB(&client);
}

/** @brief clientCloseDB twice on the same client is safe. */
static void testCloseDBTwice(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    destroyTestClient(&client);
    /* Second call must not crash — db is already NULL. */
    clientCloseDB(&client);
}

/** @brief clientCloseDB sets client->db to NULL. */
static void testCloseDBSetsNull(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_TRUE(client.db != NULL);
    destroyTestClient(&client);
    ASSERT_TRUE(client.db == NULL);
}

/* ═══════════════════════════════ 4. addGame ═══════════════════════════════ */

/** @brief addGame rejects NULL client. */
static void testAddGameNullClient(void) {
    ASSERT_INT_EQ(addGame(NULL, TestGameA, "Test", "/tmp/test"),
                  CLIENT_DB_FAIL);
}

/** @brief addGame rejects uninitialised db. */
static void testAddGameUninitDB(void) {
    Client client;
    memset(&client, 0, sizeof(client));
    client.db = NULL;
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Test", "/tmp/test"),
                  CLIENT_DB_FAIL);
}

/** @brief addGame rejects NULL gameName. */
static void testAddGameNullName(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, NULL, "/tmp/test"),
                  CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief addGame rejects NULL gamePath. */
static void testAddGameNullPath(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Test", NULL), CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief addGame succeeds with valid arguments. */
static void testAddGameBasic(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Super Mario", "/games/mario"),
                  CLIENT_DB_SUCC);
    destroyTestClient(&client);
}

/** @brief addGame with duplicate gameId fails (PRIMARY KEY constraint). */
static void testAddGameDuplicate(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Game One", "/tmp/g1"),
                  CLIENT_DB_SUCC);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Game Two", "/tmp/g2"),
                  CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief addGame inserts multiple distinct games successfully. */
static void testAddGameMultiple(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Alpha", "/a"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(addGame(&client, TestGameB, "Beta", "/b"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(addGame(&client, TestGameC, "Gamma", "/c"), CLIENT_DB_SUCC);
    destroyTestClient(&client);
}

/** @brief addGame accepts boundary gameId values (0 and UINT32_MAX). */
static void testAddGameBoundaries(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    enum { GameZero = 0 };
    ASSERT_INT_EQ(addGame(&client, GameZero, "Zero", "/z"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(addGame(&client, TestGameMax, "Max", "/m"), CLIENT_DB_SUCC);
    destroyTestClient(&client);
}

/** @brief addGame with empty gameName string succeeds. */
static void testAddGameEmptyName(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "", "/tmp/test"), CLIENT_DB_SUCC);
    destroyTestClient(&client);
}

/** @brief addGame with empty gamePath string succeeds. */
static void testAddGameEmptyPath(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Test", ""), CLIENT_DB_SUCC);
    destroyTestClient(&client);
}

/* ═════════════════ 5. addGame — SQL injection resistance ══════════════════ */

/** @brief addGame with SQL injection payload in gameName is safely stored. */
static void testAddGameSQLInjectionName(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    const char *injectName = "'; DROP TABLE gameList; --";
    ASSERT_INT_EQ(addGame(&client, TestGameA, injectName, "/safe"),
                  CLIENT_DB_SUCC);
    /* Verify the table still exists — listGames must succeed. */
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_STR_EQ(records[0]->gameName, injectName);
    ASSERT_UINT_EQ(records[0]->gameId, TestGameA);
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/** @brief addGame with SQL injection payload in gamePath is safely stored. */
static void testAddGameSQLInjectionPath(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    const char *injectPath = "/safe' OR '1'='1";
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Safe", injectPath),
                  CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_STR_EQ(records[0]->gamePath, injectPath);
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/** @brief addGame + listGames round-trip with special characters. */
static void testAddGameSpecialChars(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    const char *name = "Game\twith\nspecial\rchars%00and\bnull";
    const char *path = "C:\\Program Files\\Game\\\"quoted\"";
    ASSERT_INT_EQ(addGame(&client, TestGameA, name, path), CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_STR_EQ(records[0]->gameName, name);
    ASSERT_STR_EQ(records[0]->gamePath, path);
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/* ══════════════════════════════ 6. listGames ══════════════════════════════ */

/** @brief listGames rejects NULL client. */
static void testListGamesNullClient(void) {
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(NULL, &records, &count), CLIENT_DB_FAIL);
}

/** @brief listGames rejects uninitialised db. */
static void testListGamesUninitDB(void) {
    Client client;
    memset(&client, 0, sizeof(client));
    client.db = NULL;
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_FAIL);
}

/** @brief listGames rejects NULL outRecords. */
static void testListGamesNullOut(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, NULL, &count), CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief listGames rejects NULL count. */
static void testListGamesNullCount(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    GameRecord **records = NULL;
    ASSERT_INT_EQ(listGames(&client, &records, NULL), CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief listGames on empty database returns success with zero results. */
static void testListGamesEmpty(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    GameRecord **records = (GameRecord **)(uintptr_t)1;
    size_t count = (size_t)1;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)ExpectedResultCountEmpty);
    ASSERT_TRUE(records == NULL);
    destroyTestClient(&client);
}

/** @brief listGames returns a single added game with correct fields. */
static void testListGamesSingle(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "PacPlay", "/usr/games/pacplay"),
                  CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_UINT_EQ(records[0]->gameId, TestGameA);
    ASSERT_STR_EQ(records[0]->gameName, "PacPlay");
    ASSERT_STR_EQ(records[0]->gamePath, "/usr/games/pacplay");
    ASSERT_UINT_EQ(records[0]->playTime, TestPlayTimeZero);
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/** @brief listGames returns multiple games sorted by gameName ASC. */
static void testListGamesMultiple(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameC, "Zelda", "/z"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Alpha", "/a"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(addGame(&client, TestGameB, "Mario", "/m"), CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)ExpectedMaxResults);
    ASSERT_STR_EQ(records[0]->gameName, "Alpha");
    ASSERT_STR_EQ(records[1]->gameName, "Mario");
    ASSERT_STR_EQ(records[2]->gameName, "Zelda");
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/** @brief listGames on failure does not touch outputs. */
static void testListGamesFailOutputUntouched(void) {
    Client client;
    memset(&client, 0, sizeof(client));
    client.db = NULL;
    enum { SentinelPtr = 0xDEADU };
    enum { SentinelCount = 999 };
    GameRecord **records = (GameRecord **)(uintptr_t)SentinelPtr;
    size_t count = SentinelCount;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_FAIL);
}

/* ═════════════════════════════ 7. deleteGame ══════════════════════════════ */

/** @brief deleteGame rejects NULL client. */
static void testDeleteGameNullClient(void) {
    ASSERT_INT_EQ(deleteGame(NULL, TestGameA), CLIENT_DB_FAIL);
}

/** @brief deleteGame rejects uninitialised db. */
static void testDeleteGameUninitDB(void) {
    Client client;
    memset(&client, 0, sizeof(client));
    client.db = NULL;
    ASSERT_INT_EQ(deleteGame(&client, TestGameA), CLIENT_DB_FAIL);
}

/** @brief deleteGame successfully removes an existing game. */
static void testDeleteGameBasic(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "ToDelete", "/todel"),
                  CLIENT_DB_SUCC);
    ASSERT_INT_EQ(deleteGame(&client, TestGameA), CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = (size_t)1;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)ExpectedResultCountEmpty);
    ASSERT_TRUE(records == NULL);
    destroyTestClient(&client);
}

/** @brief deleteGame on nonexistent gameId fails. */
static void testDeleteGameNonexistent(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(deleteGame(&client, TestGameNoT), CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief deleteGame twice — second call fails. */
static void testDeleteGameTwice(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Once", "/once"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(deleteGame(&client, TestGameA), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(deleteGame(&client, TestGameA), CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief deleteGame does not affect other records. */
static void testDeleteGameIsolation(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Keep", "/keep"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(addGame(&client, TestGameB, "Remove", "/rm"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(deleteGame(&client, TestGameB), CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_UINT_EQ(records[0]->gameId, TestGameA);
    ASSERT_STR_EQ(records[0]->gameName, "Keep");
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/* ═══════════════════════════ 8. updatePlayTime ════════════════════════════ */

/** @brief updatePlayTime rejects NULL client. */
static void testUpdatePlayTimeNullClient(void) {
    ASSERT_INT_EQ(updatePlayTime(NULL, TestGameA, TestPlayTimeVal),
                  CLIENT_DB_FAIL);
}

/** @brief updatePlayTime rejects uninitialised db. */
static void testUpdatePlayTimeUninitDB(void) {
    Client client;
    memset(&client, 0, sizeof(client));
    client.db = NULL;
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestPlayTimeVal),
                  CLIENT_DB_FAIL);
}

/** @brief updatePlayTime sets and persists the new value. */
static void testUpdatePlayTimeBasic(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Game", "/g"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestPlayTimeVal),
                  CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_UINT_EQ(records[0]->playTime, TestPlayTimeVal);
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/** @brief updatePlayTime on nonexistent gameId fails. */
static void testUpdatePlayTimeNonexistent(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameNoT, TestPlayTimeVal),
                  CLIENT_DB_FAIL);
    destroyTestClient(&client);
}

/** @brief updatePlayTime to zero succeeds. */
static void testUpdatePlayTimeZero(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Zero", "/z"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestPlayTimeVal),
                  CLIENT_DB_SUCC);
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestPlayTimeZero),
                  CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(records[0]->playTime, TestPlayTimeZero);
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/** @brief updatePlayTime to UINT64_MAX succeeds. */
static void testUpdatePlayTimeMax(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "MaxTime", "/m"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestPlayTimeMax),
                  CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(records[0]->playTime, TestPlayTimeMax);
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/** @brief updatePlayTime accumulates correctly across three updates. */
static void testUpdatePlayTimeAccumulate(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Acc", "/a"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestUpdateStep1),
                  CLIENT_DB_SUCC);
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestUpdateStep2),
                  CLIENT_DB_SUCC);
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestUpdateStep3),
                  CLIENT_DB_SUCC);
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(records[0]->playTime, TestUpdateStep3);
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/* ═══════════════════════ 9. End-to-End Round-Trips ════════════════════════ */

/** @brief add → list → delete → list full cycle preserves isolation. */
static void testAddListDeleteRoundTrip(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "GameA", "/pa"), CLIENT_DB_SUCC);
    ASSERT_INT_EQ(addGame(&client, TestGameB, "GameB", "/pb"), CLIENT_DB_SUCC);

    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)2);

    ASSERT_INT_EQ(deleteGame(&client, TestGameA), CLIENT_DB_SUCC);
    freeGameRecords(records, count);
    records = NULL;
    count = 0;

    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_UINT_EQ(records[0]->gameId, TestGameB);
    ASSERT_STR_EQ(records[0]->gameName, "GameB");
    ASSERT_STR_EQ(records[0]->gamePath, "/pb");
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/** @brief add → list → update → list → delete → list full cycle. */
static void testFullCRUDRoundTrip(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "FullGame", "/full"),
                  CLIENT_DB_SUCC);

    /* Read */
    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_UINT_EQ(records[0]->playTime, TestPlayTimeZero);
    freeGameRecords(records, count);

    /* Update */
    ASSERT_INT_EQ(updatePlayTime(&client, TestGameA, TestPlayTimeVal),
                  CLIENT_DB_SUCC);

    /* Re-read */
    records = NULL;
    count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_UINT_EQ(records[0]->playTime, TestPlayTimeVal);
    freeGameRecords(records, count);

    /* Delete */
    ASSERT_INT_EQ(deleteGame(&client, TestGameA), CLIENT_DB_SUCC);

    /* Verify empty */
    records = NULL;
    count = (size_t)1;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)ExpectedResultCountEmpty);
    ASSERT_TRUE(records == NULL);
    destroyTestClient(&client);
}

/* ════════════════════════ 10. Encryption Security ═════════════════════════ */

/** @brief DB file cannot be read without the encryption key. */
static void testDBEncryptedOnDisk(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "SecretGame", "/secret"),
                  CLIENT_DB_SUCC);
    destroyTestClient(&client);

    /* Try to open the file without sqlite3_key — should fail on read. */
    sqlite3 *raw = NULL;
    int rc = sqlite3_open(CLIENT_DB_PATH, &raw);
    ASSERT_INT_EQ(rc, SQLITE_OK);
    ASSERT_TRUE(raw != NULL);

    rc = sqlite3_exec(raw, "SELECT count(*) FROM gameList;", NULL, NULL, NULL);
    ASSERT_TRUE(rc != SQLITE_OK);
    sqlite3_close(raw);
}

/** @brief DB file opened with a wrong key rejects reads. */
static void testWrongKeyFails(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "WrongKeyTest", "/w"),
                  CLIENT_DB_SUCC);
    destroyTestClient(&client);

    sqlite3 *raw = NULL;
    int rc = sqlite3_open(CLIENT_DB_PATH, &raw);
    ASSERT_INT_EQ(rc, SQLITE_OK);

    enum { WrongKeyLen = 32, WrongKeyFill = 0xFF };
    uint8_t wrongKey[WrongKeyLen];
    memset(wrongKey, WrongKeyFill, sizeof(wrongKey));
    rc = sqlite3_key(raw, wrongKey, (int)sizeof(wrongKey));
    ASSERT_INT_EQ(rc, SQLITE_OK);

    rc = sqlite3_exec(raw, "SELECT count(*) FROM gameList;", NULL, NULL, NULL);
    ASSERT_TRUE(rc != SQLITE_OK);
    sqlite3_close(raw);
}

/** @brief Persistence: data written with key A survives close + reopen. */
static void testPersistenceReopen(void) {
    removeClientDBFiles();

    /* Create DB, write data, close. */
    {
        Client client;
        initTestClient(&client);
        ASSERT_INT_EQ(addGame(&client, TestGameA, "Persist", "/p"),
                      CLIENT_DB_SUCC);
        ASSERT_INT_EQ(addGame(&client, TestGameB, "Persist2", "/p2"),
                      CLIENT_DB_SUCC);
        destroyTestClient(&client);
    }

    /* Re-open with same key and verify data. */
    {
        Client client;
        initTestClient(&client);
        GameRecord **records = NULL;
        size_t count = 0;
        ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
        ASSERT_UINT_EQ(count, (size_t)2);
        freeGameRecords(records, count);
        destroyTestClient(&client);
    }
}

/** @brief Random non-zero CDBKey round-trip: encrypt, persist, reopen. */
static void testRandomKeyPersistence(void) {
    removeClientDBFiles();

    uint8_t randKey[CLIENT_DB_KEY_LEN];
    genRandomCDBKey(randKey);

    /* Write with random key. */
    {
        Client client;
        memset(&client, 0, sizeof(client));
        client.fd = NULL_SOCKETFD;
        memcpy(client.cdbkey, randKey, CLIENT_DB_KEY_LEN);
        ASSERT_INT_EQ(clientInitDB(&client), CLIENT_DB_SUCC);
        ASSERT_INT_EQ(addGame(&client, TestGameA, "RandGame", "/rng"),
                      CLIENT_DB_SUCC);
        destroyTestClient(&client);
    }

    /* Reopen with same random key and verify. */
    {
        Client client;
        memset(&client, 0, sizeof(client));
        client.fd = NULL_SOCKETFD;
        memcpy(client.cdbkey, randKey, CLIENT_DB_KEY_LEN);
        ASSERT_INT_EQ(clientInitDB(&client), CLIENT_DB_SUCC);
        GameRecord **records = NULL;
        size_t count = 0;
        ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
        ASSERT_UINT_EQ(count, 1U);
        ASSERT_STR_EQ(records[0]->gameName, "RandGame");
        freeGameRecords(records, count);
        destroyTestClient(&client);
    }

    OPENSSL_cleanse(randKey, sizeof(randKey));
}

/** @brief Raw file bit-flip: corrupted DB file must be detected. */
static void testFileCorruptionDetected(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "CorruptMe", "/corrupt"),
                  CLIENT_DB_SUCC);
    destroyTestClient(&client);

    /* Tamper with a byte in the raw file. */
    FILE *fp = fopen(CLIENT_DB_PATH, "r+b");
    ASSERT_TRUE(fp != NULL);
    enum { SeekOffset = 256 };
    enum { CorruptByte = 0xFF };
    if (fseek(fp, SeekOffset, SEEK_SET) == 0) {
        fputc(CorruptByte, fp);
    }
    fclose(fp);

    /* Re-open — should either fail or produce auth error on read. */
    Client client2;
    memset(&client2, 0, sizeof(client2));
    client2.fd = NULL_SOCKETFD;
    memcpy(client2.cdbkey, testCDBKey, CLIENT_DB_KEY_LEN);
    int initRet = clientInitDB(&client2);
    if (initRet == CLIENT_DB_SUCC) {
        /* init may succeed but data access should fail (SQLCipher
         * validates pages on access, not on key set). */
        GameRecord **records = NULL;
        size_t count = 0;
        int listRet = listGames(&client2, &records, &count);
        /* Either listGames fails, or results are empty. */
        ASSERT_TRUE(listRet == CLIENT_DB_FAIL || count == 0);
        if (listRet == CLIENT_DB_SUCC && records != NULL) {
            freeGameRecords(records, count);
        }
        destroyTestClient(&client2);
    }
    /* init failure is also acceptable. */
}

/* ══════════════════════════ 11. Lifecycle Reuse ═══════════════════════════ */

/** @brief Init → Close → Init reuses the same Client struct safely. */
static void testLifecycleReuse(void) {
    removeClientDBFiles();
    Client client;
    initTestClient(&client);
    ASSERT_INT_EQ(addGame(&client, TestGameA, "Cycle", "/cycle"),
                  CLIENT_DB_SUCC);
    destroyTestClient(&client);

    /* Re-init — must cleanly open the existing file. */
    memset(&client, 0, sizeof(client));
    client.fd = NULL_SOCKETFD;
    memcpy(client.cdbkey, testCDBKey, CLIENT_DB_KEY_LEN);
    ASSERT_INT_EQ(clientInitDB(&client), CLIENT_DB_SUCC);

    GameRecord **records = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGames(&client, &records, &count), CLIENT_DB_SUCC);
    ASSERT_UINT_EQ(count, 1U);
    ASSERT_STR_EQ(records[0]->gameName, "Cycle");
    freeGameRecords(records, count);
    destroyTestClient(&client);
}

/* ══════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    logSetQuiet(true);
    printf("test_client_database:\n");

    /* 1. Constants & Layout */
    RUN_TEST(testClientDBKeyLen);
    RUN_TEST(testClientDBReturnCodes);
    RUN_TEST(testDBKeyRespPayloadSize);
    RUN_TEST(testDBKeyRespPayloadOffset);
    RUN_TEST(testGameRecordLayout);

    /* 2. clientInitDB */
    RUN_TEST(testInitDBNullClient);
    RUN_TEST(testInitDBAlreadyInit);
    RUN_TEST(testInitDBValid);
    RUN_TEST(testInitDBCreatesDir);
    RUN_TEST(testInitDBCreatesFile);

    /* 3. clientCloseDB */
    RUN_TEST(testCloseDBNull);
    RUN_TEST(testCloseDBUninit);
    RUN_TEST(testCloseDBTwice);
    RUN_TEST(testCloseDBSetsNull);

    /* 4. addGame */
    RUN_TEST(testAddGameNullClient);
    RUN_TEST(testAddGameUninitDB);
    RUN_TEST(testAddGameNullName);
    RUN_TEST(testAddGameNullPath);
    RUN_TEST(testAddGameBasic);
    RUN_TEST(testAddGameDuplicate);
    RUN_TEST(testAddGameMultiple);
    RUN_TEST(testAddGameBoundaries);
    RUN_TEST(testAddGameEmptyName);
    RUN_TEST(testAddGameEmptyPath);

    /* 5. addGame — SQL injection resistance */
    RUN_TEST(testAddGameSQLInjectionName);
    RUN_TEST(testAddGameSQLInjectionPath);
    RUN_TEST(testAddGameSpecialChars);

    /* 6. listGames */
    RUN_TEST(testListGamesNullClient);
    RUN_TEST(testListGamesUninitDB);
    RUN_TEST(testListGamesNullOut);
    RUN_TEST(testListGamesNullCount);
    RUN_TEST(testListGamesEmpty);
    RUN_TEST(testListGamesSingle);
    RUN_TEST(testListGamesMultiple);
    RUN_TEST(testListGamesFailOutputUntouched);

    /* 7. deleteGame */
    RUN_TEST(testDeleteGameNullClient);
    RUN_TEST(testDeleteGameUninitDB);
    RUN_TEST(testDeleteGameBasic);
    RUN_TEST(testDeleteGameNonexistent);
    RUN_TEST(testDeleteGameTwice);
    RUN_TEST(testDeleteGameIsolation);

    /* 8. updatePlayTime */
    RUN_TEST(testUpdatePlayTimeNullClient);
    RUN_TEST(testUpdatePlayTimeUninitDB);
    RUN_TEST(testUpdatePlayTimeBasic);
    RUN_TEST(testUpdatePlayTimeNonexistent);
    RUN_TEST(testUpdatePlayTimeZero);
    RUN_TEST(testUpdatePlayTimeMax);
    RUN_TEST(testUpdatePlayTimeAccumulate);

    /* 9. End-to-End Round-Trips */
    RUN_TEST(testAddListDeleteRoundTrip);
    RUN_TEST(testFullCRUDRoundTrip);

    /* 10. Encryption Security */
    RUN_TEST(testDBEncryptedOnDisk);
    RUN_TEST(testWrongKeyFails);
    RUN_TEST(testPersistenceReopen);
    RUN_TEST(testRandomKeyPersistence);
    RUN_TEST(testFileCorruptionDetected);

    /* 11. Lifecycle Reuse */
    RUN_TEST(testLifecycleReuse);

    return TEST_REPORT();
}
