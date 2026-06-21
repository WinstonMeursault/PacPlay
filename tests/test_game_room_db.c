/**
 * @file test_game_room_db.c
 * @brief Adversarial unit tests for the GameRoomDB CRUD layer.
 *
 * @date 2026-06-20
 * @copyright GPLv3 License
 */

#include "server/database.h"
#include "test_utils.h"

#include <stdint.h>
#include <stdlib.h>

enum { GameId1 = 100 };
enum { HostUid1 = 42 };
enum { RoomIdA = 1 };
enum { RoomIdB = 2 };
enum { RoomIdC = 3 };
enum { NonExistingRoom = 9999 };
enum { ListCount3 = 3 };

// NOLINTBEGIN(readability-magic-numbers)
static uint8_t testKey[DB_ENC_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
// NOLINTEND(readability-magic-numbers)

static void removeGameRoomDBFiles(void) {
    remove("./db/gameRoom.db");
    remove("./db/gameRoom.db-wal");
    remove("./db/gameRoom.db-shm");
}

static DB *openGameRoomDB(void) {
    removeGameRoomDBFiles();
    return dbInit(GameRoomDB, testKey);
}

/* ═══════════════════════════════ Tests ═══════════════════════════════════ */

static void testCreateBasic(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(gameRoomExists(db, RoomIdA), DB_SUCC);

    dbClose(db);
}

static void testCreateDuplicate(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_FAIL);

    dbClose(db);
}

static void testCreateZeroId(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, 0, GameId1, HostUid1), DB_FAIL);

    dbClose(db);
}

static void testDeleteExisting(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(deleteGameRoom(db, RoomIdA), DB_SUCC);
    ASSERT_INT_EQ(gameRoomExists(db, RoomIdA), DB_FAIL);

    dbClose(db);
}

static void testDeleteNonExisting(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(deleteGameRoom(db, NonExistingRoom), DB_FAIL);

    dbClose(db);
}

static void testListEmpty(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, 0);
    ASSERT_NULL(ids);

    dbClose(db);
}

static void testListMultiple(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, RoomIdC, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(createGameRoom(db, RoomIdB, GameId1, HostUid1), DB_SUCC);

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, ListCount3);
    ASSERT_NOT_NULL(ids);
    ASSERT_UINT_EQ(ids[0], RoomIdA);
    ASSERT_UINT_EQ(ids[1], RoomIdB);
    ASSERT_UINT_EQ(ids[2], RoomIdC);

    free(ids);
    dbClose(db);
}

static void testExistsNonExisting(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(gameRoomExists(db, NonExistingRoom), DB_FAIL);

    dbClose(db);
}

static void testExistsZeroId(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(gameRoomExists(db, 0), DB_FAIL);

    dbClose(db);
}

static void testNullDatabase(void) {
    ASSERT_INT_EQ(createGameRoom(NULL, RoomIdA, GameId1, HostUid1), DB_FAIL);
    ASSERT_INT_EQ(deleteGameRoom(NULL, RoomIdA), DB_FAIL);
    ASSERT_INT_EQ(gameRoomExists(NULL, RoomIdA), DB_FAIL);

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameRooms(NULL, &ids, &count), DB_FAIL);
}

static void testMaxId(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, UINT32_MAX, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(gameRoomExists(db, UINT32_MAX), DB_SUCC);

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, 1);
    ASSERT_UINT_EQ(ids[0], UINT32_MAX);

    free(ids);
    dbClose(db);
}

static void testWrongDbType(void) {
    DB *db = dbInit(ServerDB, NULL);
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_FAIL);
    ASSERT_INT_EQ(deleteGameRoom(db, RoomIdA), DB_FAIL);
    ASSERT_INT_EQ(gameRoomExists(db, RoomIdA), DB_FAIL);

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameRooms(db, &ids, &count), DB_FAIL);

    dbClose(db);
}

static void testDoubleDelete(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(deleteGameRoom(db, RoomIdA), DB_SUCC);
    ASSERT_INT_EQ(deleteGameRoom(db, RoomIdA), DB_FAIL);

    dbClose(db);
}

static void testCreateAfterDelete(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(deleteGameRoom(db, RoomIdA), DB_SUCC);
    ASSERT_INT_EQ(createGameRoom(db, RoomIdA, GameId1, HostUid1), DB_SUCC);
    ASSERT_INT_EQ(gameRoomExists(db, RoomIdA), DB_SUCC);

    dbClose(db);
}

/* ═════════════════════ Supplementary adversarial tests ═══════════════════ */

static void testListNullIds(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    size_t count = 0;
    ASSERT_INT_EQ(listGameRooms(db, NULL, &count), DB_FAIL);

    dbClose(db);
}

static void testListNullCount(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    uint32_t *ids = NULL;
    ASSERT_INT_EQ(listGameRooms(db, &ids, NULL), DB_FAIL);

    dbClose(db);
}

static void testListBothNull(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(listGameRooms(db, NULL, NULL), DB_FAIL);

    dbClose(db);
}

static void testStressManyRooms(void) {
    enum { StressCount = 50 };
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    for (uint32_t i = 1; i <= StressCount; i++) {
        ASSERT_INT_EQ(createGameRoom(db, i, GameId1, HostUid1), DB_SUCC);
    }

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, (size_t)StressCount);
    ASSERT_NOT_NULL(ids);

    for (uint32_t i = 0; i < StressCount; i++) {
        ASSERT_UINT_EQ(ids[i], i + 1);
    }

    free(ids);
    dbClose(db);
}

static void testRapidCreateDeleteCycles(void) {
    enum { CycleCount = 20 };
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    for (uint32_t cycle = 0; cycle < CycleCount; cycle++) {
        uint32_t rid = cycle + 1;
        ASSERT_INT_EQ(createGameRoom(db, rid, GameId1, HostUid1), DB_SUCC);
        ASSERT_INT_EQ(gameRoomExists(db, rid), DB_SUCC);
        ASSERT_INT_EQ(deleteGameRoom(db, rid), DB_SUCC);
        ASSERT_INT_EQ(gameRoomExists(db, rid), DB_FAIL);
    }

    uint32_t *ids = NULL;
    size_t count = 0;
    ASSERT_INT_EQ(listGameRooms(db, &ids, &count), DB_SUCC);
    ASSERT_UINT_EQ(count, 0);
    ASSERT_NULL(ids);

    dbClose(db);
}

static void testDeleteZeroId(void) {
    DB *db = openGameRoomDB();
    ASSERT_NOT_NULL(db);

    ASSERT_INT_EQ(deleteGameRoom(db, 0), DB_FAIL);

    dbClose(db);
}

/* ═══════════════════════════════ Main ════════════════════════════════════ */

int main(void) {
    RUN_TEST(testCreateBasic);
    RUN_TEST(testCreateDuplicate);
    RUN_TEST(testCreateZeroId);
    RUN_TEST(testDeleteExisting);
    RUN_TEST(testDeleteNonExisting);
    RUN_TEST(testListEmpty);
    RUN_TEST(testListMultiple);
    RUN_TEST(testExistsNonExisting);
    RUN_TEST(testExistsZeroId);
    RUN_TEST(testNullDatabase);
    RUN_TEST(testMaxId);
    RUN_TEST(testWrongDbType);
    RUN_TEST(testDoubleDelete);
    RUN_TEST(testCreateAfterDelete);
    RUN_TEST(testListNullIds);
    RUN_TEST(testListNullCount);
    RUN_TEST(testListBothNull);
    RUN_TEST(testStressManyRooms);
    RUN_TEST(testRapidCreateDeleteCycles);
    RUN_TEST(testDeleteZeroId);

    return TEST_REPORT();
}
