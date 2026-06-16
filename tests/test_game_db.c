/**
 * @file test_game_db.c
 * @brief Adversarial unit tests for the GameDB dual-table schema.
 *
 * @date 2026-06-16
 * @copyright GPLv3 License
 */

#include "log.h"
#include "server/database.h"
#include "test_utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { TestEnvelopeLen = 32 };
enum { TestFileSize = 1048576 };
enum { TestFileSizeSmall = 512 };
enum { TestFileSizeLarge = 4294967295U };
enum { PlatformCount3 = 3 };
enum { SleepSec = 1 };

static const uint8_t testEnvelope[TestEnvelopeLen] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C};

static void removeGameDBFiles(void) {
    remove("./db/game.db");
    remove("./db/game.db-wal");
    remove("./db/game.db-shm");
}

static DB *openGameDB(void) {
    removeGameDBFiles();
    return dbInit(GameDB, NULL);
}

/* ═══════════════════════════════ Tests ═══════════════════════════════════ */

static void testGameDbSchemaCreation(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    int rc = sqlite3_exec(db->handle, "SELECT * FROM games LIMIT 0;", NULL,
                          NULL, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);

    rc = sqlite3_exec(db->handle, "SELECT * FROM game_platforms LIMIT 0;", NULL,
                      NULL, NULL);
    ASSERT_INT_EQ(rc, SQLITE_OK);

    dbClose(db);
}

static void testRegisterGame(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "TestGame", .version = "1.0.0"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);
    ASSERT_TRUE(g.gameId > 0);

    dbClose(db);
}

static void testRegisterDuplicateName(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g1 = {.gameId = 0, .name = "DupGame", .version = "1.0"};
    GameInfo g2 = {.gameId = 0, .name = "DupGame", .version = "2.0"};
    ASSERT_INT_EQ(registerGame(db, &g1, testEnvelope, TestEnvelopeLen),
                  DB_SUCC);
    ASSERT_INT_EQ(registerGame(db, &g2, testEnvelope, TestEnvelopeLen),
                  DB_FAIL);

    dbClose(db);
}

static void testGetGameById(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "ById", .version = "3.2.1"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GameInfo out;
    memset(&out, 0, sizeof(out));
    ASSERT_INT_EQ(getGameById(db, g.gameId, &out), DB_SUCC);
    ASSERT_UINT_EQ(out.gameId, g.gameId);
    ASSERT_STR_EQ(out.name, "ById");
    ASSERT_STR_EQ(out.version, "3.2.1");
    ASSERT_TRUE(out.createdAt > 0);
    ASSERT_TRUE(out.updatedAt > 0);

    gameInfoFree(&out);
    dbClose(db);
}

static void testGetGameByName(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "ByName", .version = "0.1"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GameInfo out;
    memset(&out, 0, sizeof(out));
    ASSERT_INT_EQ(getGameByName(db, "ByName", &out), DB_SUCC);
    ASSERT_UINT_EQ(out.gameId, g.gameId);
    ASSERT_STR_EQ(out.name, "ByName");
    ASSERT_STR_EQ(out.version, "0.1");

    gameInfoFree(&out);
    dbClose(db);
}

static void testUnregisterGameCascade(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "CascadeGame", .version = "1.0"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GamePlatformInfo plat = {
        .fileName = "game.exe", .hash = "abc123", .fileSize = TestFileSize};
    strncpy(plat.platform, "windows", PLATFORM_NAME_LEN - 1);
    plat.platform[PLATFORM_NAME_LEN - 1] = '\0';
    ASSERT_INT_EQ(registerGamePlatform(db, g.gameId, &plat), DB_SUCC);

    ASSERT_INT_EQ(unregisterGame(db, g.gameId), DB_SUCC);

    GamePlatformInfo pOut;
    memset(&pOut, 0, sizeof(pOut));
    ASSERT_INT_EQ(getGamePlatform(db, g.gameId, "windows", &pOut), DB_FAIL);

    dbClose(db);
}

static void testRegisterPlatform(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "PlatGame", .version = "1.0"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GamePlatformInfo plat = {.fileName = "game.bin",
                             .hash = "sha256hex",
                             .fileSize = TestFileSizeSmall};
    strncpy(plat.platform, "linux", PLATFORM_NAME_LEN - 1);
    plat.platform[PLATFORM_NAME_LEN - 1] = '\0';
    ASSERT_INT_EQ(registerGamePlatform(db, g.gameId, &plat), DB_SUCC);

    dbClose(db);
}

static void testGetPlatform(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "GetPlat", .version = "2.0"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GamePlatformInfo plat = {.fileName = "app.dmg",
                             .hash = "deadbeef",
                             .fileSize = TestFileSizeLarge};
    strncpy(plat.platform, "macos", PLATFORM_NAME_LEN - 1);
    plat.platform[PLATFORM_NAME_LEN - 1] = '\0';
    ASSERT_INT_EQ(registerGamePlatform(db, g.gameId, &plat), DB_SUCC);

    GamePlatformInfo out;
    memset(&out, 0, sizeof(out));
    ASSERT_INT_EQ(getGamePlatform(db, g.gameId, "macos", &out), DB_SUCC);
    ASSERT_STR_EQ(out.platform, "macos");
    ASSERT_STR_EQ(out.fileName, "app.dmg");
    ASSERT_STR_EQ(out.hash, "deadbeef");
    ASSERT_TRUE(out.fileSize == TestFileSizeLarge);

    gamePlatformInfoFree(&out);
    dbClose(db);
}

static void testListPlatforms(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "MultiPlat", .version = "1.0"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GamePlatformInfo p1 = {
        .fileName = "game.exe", .hash = "h1", .fileSize = TestFileSize};
    strncpy(p1.platform, "windows", PLATFORM_NAME_LEN - 1);
    p1.platform[PLATFORM_NAME_LEN - 1] = '\0';

    GamePlatformInfo p2 = {
        .fileName = "game.bin", .hash = "h2", .fileSize = TestFileSizeSmall};
    strncpy(p2.platform, "linux", PLATFORM_NAME_LEN - 1);
    p2.platform[PLATFORM_NAME_LEN - 1] = '\0';

    GamePlatformInfo p3 = {
        .fileName = "game.dmg", .hash = "h3", .fileSize = TestFileSizeLarge};
    strncpy(p3.platform, "macos", PLATFORM_NAME_LEN - 1);
    p3.platform[PLATFORM_NAME_LEN - 1] = '\0';

    ASSERT_INT_EQ(registerGamePlatform(db, g.gameId, &p1), DB_SUCC);
    ASSERT_INT_EQ(registerGamePlatform(db, g.gameId, &p2), DB_SUCC);
    ASSERT_INT_EQ(registerGamePlatform(db, g.gameId, &p3), DB_SUCC);

    GamePlatformInfo *arr = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGamePlatforms(db, g.gameId, &arr, &count), DB_SUCC);
    ASSERT_TRUE(count == PlatformCount3);

    gamePlatformInfoArrayFree(arr, count);
    dbClose(db);
}

static void testGetEncKey(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "KeyGame", .version = "1.0"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    uint8_t *envelope = NULL;
    size_t len = 0;
    ASSERT_INT_EQ(getGameEncKey(db, g.gameId, &envelope, &len), DB_SUCC);
    ASSERT_TRUE(len == TestEnvelopeLen);
    ASSERT_MEM_EQ(envelope, testEnvelope, TestEnvelopeLen);

    free(envelope);
    dbClose(db);
}

static void testListRegisteredGames(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g1 = {.gameId = 0, .name = "Game1", .version = "1.0"};
    GameInfo g2 = {.gameId = 0, .name = "Game2", .version = "2.0"};
    GameInfo g3 = {.gameId = 0, .name = "Game3", .version = "3.0"};
    ASSERT_INT_EQ(registerGame(db, &g1, testEnvelope, TestEnvelopeLen),
                  DB_SUCC);
    ASSERT_INT_EQ(registerGame(db, &g2, testEnvelope, TestEnvelopeLen),
                  DB_SUCC);
    ASSERT_INT_EQ(registerGame(db, &g3, testEnvelope, TestEnvelopeLen),
                  DB_SUCC);

    GameInfo *arr = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listRegisteredGames(db, &arr, &count), DB_SUCC);
    ASSERT_TRUE(count == PlatformCount3);
    ASSERT_TRUE(arr[0].gameId < arr[1].gameId);
    ASSERT_TRUE(arr[1].gameId < arr[2].gameId);
    ASSERT_STR_EQ(arr[0].name, "Game1");
    ASSERT_STR_EQ(arr[1].name, "Game2");
    ASSERT_STR_EQ(arr[2].name, "Game3");
    ASSERT_TRUE(arr[0].platforms == NULL);
    ASSERT_TRUE(arr[0].platformCount == 0);

    gameInfoArrayFree(arr, count);
    dbClose(db);
}

static void testGameInfoFreeNullSafe(void) {
    GameInfo info;
    memset(&info, 0, sizeof(info));
    gameInfoFree(&info);
    gameInfoFree(NULL);
}

static void testUpdateGameVersion(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "UpdGame", .version = "1.0"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);
    time_t origUpdated = g.updatedAt;

    sleep(SleepSec);

    ASSERT_INT_EQ(updateGameVersion(db, g.gameId, "2.0"), DB_SUCC);

    GameInfo out;
    memset(&out, 0, sizeof(out));
    ASSERT_INT_EQ(getGameById(db, g.gameId, &out), DB_SUCC);
    ASSERT_STR_EQ(out.version, "2.0");
    ASSERT_TRUE(out.updatedAt >= origUpdated);

    gameInfoFree(&out);
    dbClose(db);
}

/* ═══════════════════ listGameBrief / description tests ═══════════════════ */

enum { BriefGameCount = 5 };
enum { BriefRangeStart = 2 };
enum { BriefRangeEnd = 4 };
enum { BriefRangeExpected = 3 };

static void registerBriefGames(DB *db) {
    const char *names[] = {"BriefA", "BriefB", "BriefC", "BriefD", "BriefE"};
    const char *descs[] = {"Alpha desc", "Beta desc", "Gamma desc",
                           "Delta desc", "Epsilon desc"};
    for (int i = 0; i < BriefGameCount; i++) {
        GameInfo g;
        memset(&g, 0, sizeof(g));
        g.name = (char *)names[i];
        g.version = "1.0";
        g.description = (char *)descs[i];
        ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen),
                      DB_SUCC);
    }
}

static void testListGameBriefEmpty(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameBrief(db, 0, 0, "", &entries, &count), DB_SUCC);
    ASSERT_TRUE(count == 0);
    ASSERT_TRUE(entries == NULL);

    dbClose(db);
}

static void testListGameBriefAll(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameBrief(db, 0, 0, "", &entries, &count), DB_SUCC);
    ASSERT_TRUE(count == BriefGameCount);
    ASSERT_TRUE(entries != NULL);

    ASSERT_STR_EQ(entries[0].name, "BriefA");
    ASSERT_STR_EQ(entries[1].name, "BriefB");
    ASSERT_STR_EQ(entries[2].name, "BriefC");
    ASSERT_STR_EQ(entries[3].name, "BriefD");
    ASSERT_STR_EQ(entries[4].name, "BriefE");

    for (size_t i = 0; i < count; i++) {
        ASSERT_TRUE(entries[i].gameId > 0);
        ASSERT_TRUE(entries[i].createdAt > 0);
        ASSERT_TRUE(entries[i].updatedAt > 0);
    }

    free(entries);
    dbClose(db);
}

static void testListGameBriefRange(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        listGameBrief(db, BriefRangeStart, BriefRangeEnd, "", &entries, &count),
        DB_SUCC);
    ASSERT_TRUE(count == BriefRangeExpected);
    ASSERT_TRUE(entries != NULL);

    ASSERT_UINT_EQ(entries[0].gameId, BriefRangeStart);
    ASSERT_UINT_EQ(entries[count - 1].gameId, BriefRangeEnd);

    free(entries);
    dbClose(db);
}

static void testListGameBriefInvertedRange(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        listGameBrief(db, BriefRangeEnd, BriefRangeStart, "", &entries, &count),
        DB_SUCC);
    ASSERT_TRUE(count == 0);
    ASSERT_TRUE(entries == NULL);

    dbClose(db);
}

static void testListGameBriefDescription(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameBrief(db, 0, 0, "", &entries, &count), DB_SUCC);
    ASSERT_TRUE(count == BriefGameCount);

    ASSERT_STR_EQ(entries[0].description, "Alpha desc");
    ASSERT_STR_EQ(entries[1].description, "Beta desc");
    ASSERT_STR_EQ(entries[2].description, "Gamma desc");
    ASSERT_STR_EQ(entries[3].description, "Delta desc");
    ASSERT_STR_EQ(entries[4].description, "Epsilon desc");

    free(entries);
    dbClose(db);
}

static void testGetGameByIdDescription(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g;
    memset(&g, 0, sizeof(g));
    g.name = "DescGame";
    g.version = "2.0";
    g.description = "A very cool game";
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GameInfo out;
    memset(&out, 0, sizeof(out));
    ASSERT_INT_EQ(getGameById(db, g.gameId, &out), DB_SUCC);
    ASSERT_TRUE(out.description != NULL);
    ASSERT_STR_EQ(out.description, "A very cool game");

    gameInfoFree(&out);
    dbClose(db);
}

static void testRegisterGameNullDescription(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    GameInfo g = {.gameId = 0, .name = "NullDesc", .version = "1.0"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GameInfo out;
    memset(&out, 0, sizeof(out));
    ASSERT_INT_EQ(getGameById(db, g.gameId, &out), DB_SUCC);
    ASSERT_TRUE(out.description != NULL);
    ASSERT_STR_EQ(out.description, "");

    gameInfoFree(&out);
    dbClose(db);
}

static void testListGameBriefSingleElement(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameBrief(db, 1, 1, "", &entries, &count), DB_SUCC);
    ASSERT_TRUE(count == 1);
    ASSERT_TRUE(entries != NULL);
    ASSERT_UINT_EQ(entries[0].gameId, 1u);

    free(entries);
    dbClose(db);
}

static void testListGameBriefBoundaryRange(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameBrief(db, UINT32_MAX, UINT32_MAX, "", &entries, &count),
                  DB_SUCC);
    ASSERT_TRUE(count == 0);
    ASSERT_TRUE(entries == NULL);

    dbClose(db);
}

/* ════════════════ listGameBrief platform-filter tests ════════════════ */

enum { PlatFilterMatchCount = 3, PlatFilterNoMatchCount = 0, PlatIdxB = 1,
       PlatNameBufLen = 64 };

static void registerGameWithPlatform(DB *db, const char *gameName,
                                      const char *platformName) {
    GameInfo g = {.gameId = 0, .name = (char *)gameName, .version = "1.0",
                  .description = "has platform"};
    ASSERT_INT_EQ(registerGame(db, &g, testEnvelope, TestEnvelopeLen), DB_SUCC);

    GamePlatformInfo plat = {.fileName = "game.bin", .hash = "abc123",
                              .fileSize = TestFileSizeSmall};
    strncpy(plat.platform, platformName, PLATFORM_NAME_LEN - 1);
    plat.platform[PLATFORM_NAME_LEN - 1] = '\0';
    ASSERT_INT_EQ(registerGamePlatform(db, g.gameId, &plat), DB_SUCC);
}

static void testListGameBriefPlatformFilterMatch(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);
    for (int i = 0; i < PlatFilterMatchCount; i++) {
        char nameBuf[PlatNameBufLen];
        snprintf(nameBuf, sizeof(nameBuf), "PlatGame_%d", i);
        registerGameWithPlatform(db, nameBuf, "linux-x86_64");
    }

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        listGameBrief(db, 0, 0, "linux-x86_64", &entries, &count), DB_SUCC);
    ASSERT_TRUE(count == (size_t)PlatFilterMatchCount);
    ASSERT_TRUE(entries != NULL);
    ASSERT_STR_EQ(entries[0].name, "PlatGame_0");
    ASSERT_STR_EQ(entries[PlatIdxB].name, "PlatGame_1");
    ASSERT_STR_EQ(entries[PlatFilterMatchCount - 1].name, "PlatGame_2");

    free(entries);
    dbClose(db);
}

static void testListGameBriefPlatformNoMatch(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);
    registerGameWithPlatform(db, "LinuxOnly", "linux-x86_64");

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameBrief(db, 0, 0, "windows", &entries, &count),
                  DB_SUCC);
    ASSERT_TRUE(count == PlatFilterNoMatchCount);
    ASSERT_TRUE(entries == NULL);

    dbClose(db);
}

static void testListGameBriefPlatformEmptyFilter(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);
    registerGameWithPlatform(db, "WithPlat", "linux-x86_64");

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameBrief(db, 0, 0, "", &entries, &count), DB_SUCC);
    ASSERT_TRUE(count == BriefGameCount + 1);
    ASSERT_TRUE(entries != NULL);

    free(entries);
    dbClose(db);
}

static void testListGameBriefNullPlatform(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameBrief(db, 0, 0, NULL, &entries, &count), DB_FAIL);

    dbClose(db);
}

static void testListGameBriefGameWithNoPlatforms(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(
        listGameBrief(db, 0, 0, "linux-x86_64", &entries, &count), DB_SUCC);
    ASSERT_TRUE(count == PlatFilterNoMatchCount);
    ASSERT_TRUE(entries == NULL);

    dbClose(db);
}

static void testListGameBriefPlatformRangeFilter(void) {
    DB *db = openGameDB();
    ASSERT_TRUE(db != NULL);

    registerBriefGames(db);
    for (int i = 0; i < PlatFilterMatchCount; i++) {
        char nameBuf[PlatNameBufLen];
        snprintf(nameBuf, sizeof(nameBuf), "RangePlat_%d", i);
        registerGameWithPlatform(db, nameBuf, "linux-x86_64");
    }

    GameInfoEntry *entries = NULL;
    size_t count = 0;
    uint32_t startId = (uint32_t)(BriefGameCount + 1);
    uint32_t endId = (uint32_t)(BriefGameCount + 2);
    ASSERT_INT_EQ(
        listGameBrief(db, startId, endId, "linux-x86_64", &entries, &count),
        DB_SUCC);
    ASSERT_TRUE(count == 2u);
    ASSERT_TRUE(entries != NULL);
    ASSERT_STR_EQ(entries[0].name, "RangePlat_0");
    ASSERT_STR_EQ(entries[1].name, "RangePlat_1");

    free(entries);
    dbClose(db);
}

/* ═══════════════════════════════ main ════════════════════════════════════ */

int main(void) {
    logSetQuiet(true);

    RUN_TEST(testGameDbSchemaCreation);
    RUN_TEST(testRegisterGame);
    RUN_TEST(testRegisterDuplicateName);
    RUN_TEST(testGetGameById);
    RUN_TEST(testGetGameByName);
    RUN_TEST(testUnregisterGameCascade);
    RUN_TEST(testRegisterPlatform);
    RUN_TEST(testGetPlatform);
    RUN_TEST(testListPlatforms);
    RUN_TEST(testGetEncKey);
    RUN_TEST(testListRegisteredGames);
    RUN_TEST(testGameInfoFreeNullSafe);
    RUN_TEST(testUpdateGameVersion);
    RUN_TEST(testListGameBriefEmpty);
    RUN_TEST(testListGameBriefAll);
    RUN_TEST(testListGameBriefRange);
    RUN_TEST(testListGameBriefInvertedRange);
    RUN_TEST(testListGameBriefDescription);
    RUN_TEST(testGetGameByIdDescription);
    RUN_TEST(testRegisterGameNullDescription);
    RUN_TEST(testListGameBriefSingleElement);
    RUN_TEST(testListGameBriefBoundaryRange);
    RUN_TEST(testListGameBriefPlatformFilterMatch);
    RUN_TEST(testListGameBriefPlatformNoMatch);
    RUN_TEST(testListGameBriefPlatformEmptyFilter);
    RUN_TEST(testListGameBriefNullPlatform);
    RUN_TEST(testListGameBriefGameWithNoPlatforms);
    RUN_TEST(testListGameBriefPlatformRangeFilter);

    TEST_REPORT();
    return 0;
}
