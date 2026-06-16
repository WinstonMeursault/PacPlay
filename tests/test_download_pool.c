#include "server/downloadPool.h"
#include "test_utils.h"

#include <string.h>
#include <time.h>
#include <unistd.h>

enum {
    TestDataPort = 19800,
    TestWorkerCount = 2,
    ShortSleepUs = 100000,
    TokenFillByte = 0xAA,
    KeyFillByte = 0xBB,
    TestGameId = 42,
    TestResumeChunk = 0,
    TestFileSize = 65536,
    TestTotalChunks = 1,
    ExtraTokenFill = 0xFF,
    FakeTokenFill = 0x99,
    TokenReplayFill = 0xDD,
    PortOffsetCancel = 5,
    PortOffsetShutdown = 6
};

static void fillToken(PendingToken *pt, uint8_t seed) {
    memset(pt, 0, sizeof(*pt));
    memset(pt->token, seed, DATA_AUTH_TOKEN_LEN);
    memset(pt->mainAESKey, KeyFillByte, AES_GCM_KEY_LEN);
    pt->gameId = TestGameId;
    pt->resumeChunkIndex = TestResumeChunk;
    snprintf(pt->filePath, FILE_PATH_MAX_LEN, "/tmp/test_game_%u.bin",
             (unsigned)seed);
    pt->fileSize = TestFileSize;
    pt->totalChunks = TestTotalChunks;
    pt->used = false;
}

static void testPoolInitDestroy(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort, TestWorkerCount);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_FALSE(pool.shutdown);
    ASSERT_UINT_EQ(pool.workerCount, (size_t)TestWorkerCount);
    ASSERT_UINT_EQ(pool.queueCount, (size_t)0);
    downloadPoolDestroy(&pool);
    ASSERT_TRUE(pool.shutdown);
}

static void testPoolInitNullFails(void) {
    int ret = downloadPoolInit(NULL, TestDataPort, TestWorkerCount);
    ASSERT_INT_EQ(ret, -1);
}

static void testPoolInitZeroWorkersFails(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort, 0);
    ASSERT_INT_EQ(ret, -1);
}

static void testPoolInitTooManyWorkersFails(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort, MAX_DOWNLOAD_WORKERS + 1);
    ASSERT_INT_EQ(ret, -1);
}

static void testTokenRegister(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort + 1, TestWorkerCount);
    ASSERT_INT_EQ(ret, 0);

    PendingToken pt;
    fillToken(&pt, TokenFillByte);

    ret = downloadPoolRegisterToken(&pool, &pt);
    ASSERT_INT_EQ(ret, 0);

    pthread_mutex_lock(&pool.tokenMutex);
    bool found = false;
    for (int i = 0; i < MAX_PENDING_TOKENS; i++) {
        if (!pool.tokens[i].used && pool.tokens[i].expiresAt > 0 &&
            memcmp(pool.tokens[i].token, pt.token, DATA_AUTH_TOKEN_LEN) == 0) {
            found = true;
            ASSERT_UINT_EQ(pool.tokens[i].gameId, (uint32_t)TestGameId);
            break;
        }
    }
    pthread_mutex_unlock(&pool.tokenMutex);
    ASSERT_TRUE(found);

    downloadPoolDestroy(&pool);
}

static void testTokenRegisterNullFails(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort + 2, TestWorkerCount);
    ASSERT_INT_EQ(ret, 0);

    ret = downloadPoolRegisterToken(&pool, NULL);
    ASSERT_INT_EQ(ret, -1);

    ret = downloadPoolRegisterToken(NULL, NULL);
    ASSERT_INT_EQ(ret, -1);

    downloadPoolDestroy(&pool);
}

static void testTokenRegisterFull(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort + 3, TestWorkerCount);
    ASSERT_INT_EQ(ret, 0);

    for (int i = 0; i < MAX_PENDING_TOKENS; i++) {
        PendingToken pt;
        fillToken(&pt, (uint8_t)(i + 1));
        ret = downloadPoolRegisterToken(&pool, &pt);
        ASSERT_INT_EQ(ret, 0);
    }

    PendingToken extra;
    fillToken(&extra, ExtraTokenFill);
    ret = downloadPoolRegisterToken(&pool, &extra);
    ASSERT_INT_EQ(ret, -1);

    downloadPoolDestroy(&pool);
}

static void testTokenCancelByToken(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort + 4, TestWorkerCount);
    ASSERT_INT_EQ(ret, 0);

    PendingToken pt;
    fillToken(&pt, TokenFillByte);
    ret = downloadPoolRegisterToken(&pool, &pt);
    ASSERT_INT_EQ(ret, 0);

    ret = downloadPoolCancelByToken(&pool, pt.token);
    ASSERT_INT_EQ(ret, 0);

    pthread_mutex_lock(&pool.tokenMutex);
    bool allUsed = true;
    for (int i = 0; i < MAX_PENDING_TOKENS; i++) {
        if (memcmp(pool.tokens[i].token, pt.token, DATA_AUTH_TOKEN_LEN) == 0) {
            if (!pool.tokens[i].used) {
                allUsed = false;
            }
        }
    }
    pthread_mutex_unlock(&pool.tokenMutex);
    ASSERT_TRUE(allUsed);

    downloadPoolDestroy(&pool);
}

static void testTokenCancelNotFoundFails(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort + PortOffsetCancel,
                               TestWorkerCount);
    ASSERT_INT_EQ(ret, 0);

    uint8_t fakeToken[DATA_AUTH_TOKEN_LEN];
    memset(fakeToken, FakeTokenFill, DATA_AUTH_TOKEN_LEN);
    ret = downloadPoolCancelByToken(&pool, fakeToken);
    ASSERT_INT_EQ(ret, -1);

    downloadPoolDestroy(&pool);
}

static void testPoolShutdownWithPending(void) {
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort + PortOffsetShutdown,
                               TestWorkerCount);
    ASSERT_INT_EQ(ret, 0);

    for (int i = 0; i < MAX_PENDING_TOKENS; i++) {
        PendingToken pt;
        fillToken(&pt, (uint8_t)(i + 1));
        downloadPoolRegisterToken(&pool, &pt);
    }

    downloadPoolDestroy(&pool);
    ASSERT_TRUE(pool.shutdown);
}

static void testDestroyNullSafe(void) { downloadPoolDestroy(NULL); }

static void testTokenReplayPrevention(void) {
    enum { PortOffsetReplay = 7 };
    DownloadPool pool;
    int ret = downloadPoolInit(&pool, TestDataPort + PortOffsetReplay,
                               TestWorkerCount);
    ASSERT_INT_EQ(ret, 0);

    PendingToken pt;
    fillToken(&pt, TokenReplayFill);
    pt.expiresAt = (int64_t)time(NULL) + TOKEN_EXPIRE_SECS;

    ASSERT_INT_EQ(downloadPoolRegisterToken(&pool, &pt), 0);
    ASSERT_INT_EQ(downloadPoolCancelByToken(&pool, pt.token), 0);
    ASSERT_INT_EQ(downloadPoolCancelByToken(&pool, pt.token), -1);

    downloadPoolDestroy(&pool);
}

int main(void) {
    enum { TestTimeoutSecs = 15 };
    alarm(TestTimeoutSecs);
    RUN_TEST(testPoolInitDestroy);
    RUN_TEST(testPoolInitNullFails);
    RUN_TEST(testPoolInitZeroWorkersFails);
    RUN_TEST(testPoolInitTooManyWorkersFails);
    RUN_TEST(testTokenRegister);
    RUN_TEST(testTokenRegisterNullFails);
    RUN_TEST(testTokenRegisterFull);
    RUN_TEST(testTokenCancelByToken);
    RUN_TEST(testTokenCancelNotFoundFails);
    RUN_TEST(testPoolShutdownWithPending);
    RUN_TEST(testDestroyNullSafe);
    RUN_TEST(testTokenReplayPrevention);
    return TEST_REPORT();
}
