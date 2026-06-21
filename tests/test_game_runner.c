/**
 * @file test_game_runner.c
 * @brief Adversarial unit tests for the gameRunner module.
 *
 * Covers NULL safety, double-start prevention, stop-without-run safety,
 * and invalid .so path handling for both server-level and per-room game
 * runner APIs.
 *
 * @date 2026-06-21
 * @copyright GPLv3 License
 */

#include "server/gameRunner.h"
#include "server/server.h"
#include "test_utils.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>

enum {
    SpinSleepUs = 10000,
    SpinMaxIter = 200,
};

/* ═══════════════════════ gameRoomStartGame tests ═════════════════════════ */

static void testGameRoomStartNullRoom(void) {
    ASSERT_INT_EQ(gameRoomStartGame(NULL, "/tmp/fake.so"), SERVER_FAIL);
}

static void testGameRoomStartNullPath(void) {
    ActiveGameRoom gr;
    memset(&gr, 0, sizeof(gr));
    ASSERT_INT_EQ(gameRoomStartGame(&gr, NULL), SERVER_FAIL);
}

static void testGameRoomStartBothNull(void) {
    ASSERT_INT_EQ(gameRoomStartGame(NULL, NULL), SERVER_FAIL);
}

static void testGameRoomStartAlreadyRunning(void) {
    ActiveGameRoom gr;
    memset(&gr, 0, sizeof(gr));
    gr.gameRunning = true;
    ASSERT_INT_EQ(gameRoomStartGame(&gr, "/tmp/fake.so"), SERVER_FAIL);
}

static void testGameRoomStartInvalidSo(void) {
    ActiveGameRoom gr;
    memset(&gr, 0, sizeof(gr));
    gr.gameRoomId = 1;

    int rc = gameRoomStartGame(&gr, "/nonexistent/path/invalid.so");
    ASSERT_INT_EQ(rc, SERVER_SUCC);
    ASSERT_TRUE(gr.gameRunning);

    for (int i = 0; i < SpinMaxIter && gr.gameRunning; i++) {
        usleep(SpinSleepUs);
    }

    ASSERT_FALSE(gr.gameRunning);
    ASSERT_NULL(gr.sdk);
    ASSERT_NULL(gr.gameHandle);

    pthread_join(gr.gameThread, NULL);
}

/* ═══════════════════════ gameRoomStopGame tests ══════════════════════════ */

static void testGameRoomStopNull(void) { gameRoomStopGame(NULL); }

static void testGameRoomStopNotRunning(void) {
    ActiveGameRoom gr;
    memset(&gr, 0, sizeof(gr));
    gr.gameRunning = false;
    gameRoomStopGame(&gr);
    ASSERT_FALSE(gr.gameRunning);
}

/* ═══════════════════════ serverStartGame tests ═══════════════════════════ */

static void testServerStartNullServer(void) {
    ASSERT_INT_EQ(serverStartGame(NULL, "/tmp/fake.so"), SERVER_FAIL);
}

static void testServerStartNullPath(void) {
    Server s;
    memset(&s, 0, sizeof(s));
    ASSERT_INT_EQ(serverStartGame(&s, NULL), SERVER_FAIL);
}

static void testServerStartBothNull(void) {
    ASSERT_INT_EQ(serverStartGame(NULL, NULL), SERVER_FAIL);
}

static void testServerStartAlreadyRunning(void) {
    Server s;
    memset(&s, 0, sizeof(s));
    s.gameRunning = true;
    ASSERT_INT_EQ(serverStartGame(&s, "/tmp/fake.so"), SERVER_FAIL);
}

static void testServerStartInvalidSo(void) {
    Server s;
    memset(&s, 0, sizeof(s));

    int rc = serverStartGame(&s, "/nonexistent/path/invalid.so");
    ASSERT_INT_EQ(rc, SERVER_SUCC);
    ASSERT_TRUE(s.gameRunning);

    for (int i = 0; i < SpinMaxIter && s.gameRunning; i++) {
        usleep(SpinSleepUs);
    }

    ASSERT_FALSE(s.gameRunning);
    ASSERT_NULL(s.sdk);
    ASSERT_NULL(s.gameHandle);

    pthread_join(s.gameThread, NULL);
}

/* ═══════════════════════ serverStopGame tests ════════════════════════════ */

static void testServerStopNull(void) { serverStopGame(NULL); }

static void testServerStopNotRunning(void) {
    Server s;
    memset(&s, 0, sizeof(s));
    s.gameRunning = false;
    serverStopGame(&s);
    ASSERT_FALSE(s.gameRunning);
}

/* ═══════════════════════ double-start after failure ══════════════════════ */

static void testGameRoomDoubleStartAfterFailure(void) {
    ActiveGameRoom gr;
    memset(&gr, 0, sizeof(gr));
    gr.gameRoomId = 2;

    int rc = gameRoomStartGame(&gr, "/nonexistent/a.so");
    ASSERT_INT_EQ(rc, SERVER_SUCC);

    for (int i = 0; i < SpinMaxIter && gr.gameRunning; i++) {
        usleep(SpinSleepUs);
    }
    ASSERT_FALSE(gr.gameRunning);
    pthread_join(gr.gameThread, NULL);

    rc = gameRoomStartGame(&gr, "/nonexistent/b.so");
    ASSERT_INT_EQ(rc, SERVER_SUCC);

    for (int i = 0; i < SpinMaxIter && gr.gameRunning; i++) {
        usleep(SpinSleepUs);
    }
    ASSERT_FALSE(gr.gameRunning);
    pthread_join(gr.gameThread, NULL);
}

/* ════════════════════════════════ main ═══════════════════════════════════ */

int main(void) {
    printf("test_game_runner:\n");

    RUN_TEST(testGameRoomStartNullRoom);
    RUN_TEST(testGameRoomStartNullPath);
    RUN_TEST(testGameRoomStartBothNull);
    RUN_TEST(testGameRoomStartAlreadyRunning);
    RUN_TEST(testGameRoomStartInvalidSo);

    RUN_TEST(testGameRoomStopNull);
    RUN_TEST(testGameRoomStopNotRunning);

    RUN_TEST(testServerStartNullServer);
    RUN_TEST(testServerStartNullPath);
    RUN_TEST(testServerStartBothNull);
    RUN_TEST(testServerStartAlreadyRunning);
    RUN_TEST(testServerStartInvalidSo);

    RUN_TEST(testServerStopNull);
    RUN_TEST(testServerStopNotRunning);

    RUN_TEST(testGameRoomDoubleStartAfterFailure);

    return TEST_REPORT();
}
