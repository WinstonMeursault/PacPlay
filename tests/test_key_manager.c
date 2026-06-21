/**
 * @file test_key_manager.c
 * @brief Unit tests for the server key management module (keyManager.c).
 *
 * Covers serverIsFirstRun, serverKeysAreComplete, serverGenerateFreshKeys,
 * and serverUnlockWithMK error paths and boundary conditions.
 *
 * @date 2026-06-15
 * @copyright GPLv3 License
 */

#include "server/database.h"
#include "server/keyManager.h"
#include "server/server.h"
#include "test_utils.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ────────────────────────── test-local constants ────────────────────────── */

enum {
    KeyLen = 32,
    HexMkLen = 64,
    EnvelopeLen = 12 + 32 + 16,
    HexMkBufSize = HexMkLen + 1,
    HalfHexLen = 32,
    DoubleHexLen = 128,
    FlipByteIdx = 20,
    FlipBit = 0x01
};

/* ───────────────────────────── test helpers ─────────────────────────────── */

static void removeDBFiles(void) {
    remove("./db/server.db");
    remove("./db/server.db-wal");
    remove("./db/server.db-shm");
    remove("./db/user.db");
    remove("./db/user.db-wal");
    remove("./db/user.db-shm");
    remove("./db/chatHistory.db");
    remove("./db/chatHistory.db-wal");
    remove("./db/chatHistory.db-shm");
    remove("./db/room.db");
    remove("./db/room.db-wal");
    remove("./db/room.db-shm");
    remove("./db/game.db");
    remove("./db/game.db-wal");
    remove("./db/game.db-shm");
    rmdir("./db");
}

static Server makeTestServerWithDB(void) {
    Server srv;
    memset(&srv, 0, sizeof(srv));
    srv.serverDB = dbInit(ServerDB, NULL);
    return srv;
}

static void cleanupServer(Server *srv) {
    OPENSSL_cleanse(srv->dekKey, sizeof(srv->dekKey));
    OPENSSL_cleanse(srv->userDbEncKey, sizeof(srv->userDbEncKey));
    OPENSSL_cleanse(srv->gameDbEncKey, sizeof(srv->gameDbEncKey));
    OPENSSL_cleanse(srv->gameRoomDbEncKey, sizeof(srv->gameRoomDbEncKey));
    OPENSSL_cleanse(srv->friendDbEncKey, sizeof(srv->friendDbEncKey));
    OPENSSL_cleanse(srv->privateChatDbEncKey, sizeof(srv->privateChatDbEncKey));
    OPENSSL_cleanse(srv->groupDbEncKey, sizeof(srv->groupDbEncKey));
    dbClose(srv->serverDB);
    srv->serverDB = NULL;
}

/* ──────────────────── serverIsFirstRun tests ────────────────────────────── */

static void testIsFirstRunOnFreshDB(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);
    ASSERT_TRUE(serverIsFirstRun(&srv));
    cleanupServer(&srv);
    removeDBFiles();
}

static void testIsFirstRunAfterKeysGenerated(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);
    ASSERT_FALSE(serverIsFirstRun(&srv));

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

/* ─────────────── serverKeysAreComplete tests ────────────────────────────── */

static void testKeysAreCompleteAllPresent(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);
    ASSERT_TRUE(serverKeysAreComplete(&srv));

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

static void testKeysAreCompleteMissingAll(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);
    ASSERT_FALSE(serverKeysAreComplete(&srv));
    cleanupServer(&srv);
    removeDBFiles();
}

static void testKeysAreCompleteMissingOne(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);

    uint8_t *val = NULL;
    size_t valLen = 0;
    ASSERT_INT_EQ(getServerKey(srv.serverDB, "GameDBKey", &val, &valLen),
                  DB_SUCC);
    ASSERT_NOT_NULL(val);
    free(val);

    sqlite3 *raw = srv.serverDB->handle;
    int rc =
        sqlite3_exec(raw, "DELETE FROM server_keys WHERE key_name='GameDBKey'",
                     NULL, NULL, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);

    ASSERT_FALSE(serverKeysAreComplete(&srv));

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

/* ──────────── serverUnlockWithMK error path tests ──────────────────────── */

static void testUnlockWithWrongMasterKey(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);

    char wrongHex[HexMkBufSize];
    memset(wrongHex, '0', HexMkLen);
    wrongHex[HexMkLen] = '\0';
    if (strcmp(wrongHex, mkHex) == 0) {
        wrongHex[0] = '1';
    }

    ASSERT_INT_EQ(serverUnlockWithMK(&srv, wrongHex), SERVER_FAIL);

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

static void testUnlockWithInvalidHexChars(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);

    char badHex[HexMkBufSize];
    memset(badHex, 'g', HexMkLen);
    badHex[HexMkLen] = '\0';

    ASSERT_INT_EQ(serverUnlockWithMK(&srv, badHex), SERVER_FAIL);

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

static void testUnlockWithTruncatedHex(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);

    char shortHex[HalfHexLen + 1];
    memcpy(shortHex, mkHex, HalfHexLen);
    shortHex[HalfHexLen] = '\0';

    ASSERT_INT_EQ(serverUnlockWithMK(&srv, shortHex), SERVER_FAIL);

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

static void testUnlockWithTooLongHex(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);

    char longHex[DoubleHexLen + 1];
    memset(longHex, 'a', DoubleHexLen);
    longHex[DoubleHexLen] = '\0';

    ASSERT_INT_EQ(serverUnlockWithMK(&srv, longHex), SERVER_FAIL);

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

static void testUnlockWithEmptyHex(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);

    ASSERT_INT_EQ(serverUnlockWithMK(&srv, ""), SERVER_FAIL);

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

static void testUnlockWithCorruptedEnvelope(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);

    uint8_t *dekEnv = NULL;
    size_t dekLen = 0;
    ASSERT_INT_EQ(getServerKey(srv.serverDB, "DEK", &dekEnv, &dekLen), DB_SUCC);
    ASSERT_NOT_NULL(dekEnv);
    ASSERT_UINT_EQ(dekLen, (size_t)EnvelopeLen);

    dekEnv[FlipByteIdx] ^= FlipBit;
    ASSERT_INT_EQ(setServerKey(srv.serverDB, "DEK", dekEnv, dekLen), DB_SUCC);
    free(dekEnv);

    ASSERT_INT_EQ(serverUnlockWithMK(&srv, mkHex), SERVER_FAIL);

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

/* ──── generate+unlock roundtrip: idempotency & distinctness ─────────────── */

static void testGenerateTwiceProducesDifferentKeys(void) {
    removeDBFiles();
    Server srv1 = makeTestServerWithDB();
    ASSERT_TRUE(srv1.serverDB != NULL);

    char *mk1 = serverGenerateFreshKeys(&srv1);
    ASSERT_NOT_NULL(mk1);
    ASSERT_INT_EQ(serverUnlockWithMK(&srv1, mk1), SERVER_SUCC);

    uint8_t savedDek1[KeyLen];
    memcpy(savedDek1, srv1.dekKey, KeyLen);

    free(mk1);
    cleanupServer(&srv1);
    removeDBFiles();

    Server srv2 = makeTestServerWithDB();
    ASSERT_TRUE(srv2.serverDB != NULL);

    char *mk2 = serverGenerateFreshKeys(&srv2);
    ASSERT_NOT_NULL(mk2);
    ASSERT_INT_EQ(serverUnlockWithMK(&srv2, mk2), SERVER_SUCC);

    ASSERT_TRUE(memcmp(savedDek1, srv2.dekKey, KeyLen) != 0);

    free(mk2);
    cleanupServer(&srv2);
    removeDBFiles();
}

static void testGenerateUnlockRoundtripKeysNonZero(void) {
    removeDBFiles();
    Server srv = makeTestServerWithDB();
    ASSERT_TRUE(srv.serverDB != NULL);

    char *mkHex = serverGenerateFreshKeys(&srv);
    ASSERT_NOT_NULL(mkHex);
    ASSERT_INT_EQ(serverUnlockWithMK(&srv, mkHex), SERVER_SUCC);

    static const uint8_t zeros[KeyLen];
    ASSERT_TRUE(memcmp(srv.dekKey, zeros, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, zeros, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, zeros, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameRoomDbEncKey, zeros, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.friendDbEncKey, zeros, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.privateChatDbEncKey, zeros, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.groupDbEncKey, zeros, KeyLen) != 0);

    ASSERT_TRUE(memcmp(srv.dekKey, srv.userDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.gameDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.gameRoomDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.friendDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.privateChatDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.dekKey, srv.groupDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.gameDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.gameRoomDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.friendDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.privateChatDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.userDbEncKey, srv.groupDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, srv.gameRoomDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, srv.friendDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, srv.privateChatDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameDbEncKey, srv.groupDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameRoomDbEncKey, srv.friendDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameRoomDbEncKey, srv.privateChatDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.gameRoomDbEncKey, srv.groupDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.friendDbEncKey, srv.privateChatDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.friendDbEncKey, srv.groupDbEncKey, KeyLen) != 0);
    ASSERT_TRUE(memcmp(srv.privateChatDbEncKey, srv.groupDbEncKey, KeyLen) != 0);

    free(mkHex);
    cleanupServer(&srv);
    removeDBFiles();
}

/* ════════════════════════════════════════════════════════════════════════
   main
   ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_key_manager:\n");

    RUN_TEST(testIsFirstRunOnFreshDB);
    RUN_TEST(testIsFirstRunAfterKeysGenerated);

    RUN_TEST(testKeysAreCompleteAllPresent);
    RUN_TEST(testKeysAreCompleteMissingAll);
    RUN_TEST(testKeysAreCompleteMissingOne);

    RUN_TEST(testUnlockWithWrongMasterKey);
    RUN_TEST(testUnlockWithInvalidHexChars);
    RUN_TEST(testUnlockWithTruncatedHex);
    RUN_TEST(testUnlockWithTooLongHex);
    RUN_TEST(testUnlockWithEmptyHex);
    RUN_TEST(testUnlockWithCorruptedEnvelope);

    RUN_TEST(testGenerateTwiceProducesDifferentKeys);
    RUN_TEST(testGenerateUnlockRoundtripKeysNonZero);

    return TEST_REPORT();
}
