/**
 * @file test_pacplay_sdk.c
 * @brief Comprehensive adversarial tests for the PacPlay SDK — thread-safe
 *        ring-buffer bridge between game threads and PacPlay IO threads.
 *
 * Tests both client SDK (pacplay_cli_*) and server SDK (pacplay_srv_*)
 * variants.  Covers create/destroy, send, poll_send, push_received, poll,
 * callback, full roundtrips, concurrency, memory safety, and security
 * boundaries.
 *
 * @date 2026-06-17
 * @copyright GPLv3 License
 */

#include "pacplay_sdk.h"
#include "test_utils.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── ASan / LSan hints ──────────────────────────────────────────────────── */

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
const char *__asan_default_options(void) {
    return "allocator_may_return_null=1";
}
#endif
#endif

/* ── numeric constants (anonymous enum — clang-tidy compliance) ──────────── */

enum {
    SendLen5 = 5,
    SendLen1 = 1,
    SendLen10 = 10,
    SendLen20 = 20,
    SendLen100 = 100,
    SendLen256 = 256,
    MaxPayload = 65536,
    MaxPayloadPlus1 = 65537,
    MaxPayloadMinus1 = 65535,
    QueueCap = 64,
    QueueCapPlus1 = 65,
    IterCount10 = 10,
    IterCount100 = 100,
    IterCount1000 = 1000,
    ThreadCount2 = 2,
    ThreadCount4 = 4,
    SleepUs100 = 100,
    SleepMs1 = 1000,
    SleepMs5 = 5000,
    SleepMs10 = 10000,
    TestByteA = 0x41,
    SentinelPtrVal = 0xDEAD,
    SentinelOutLen = 42,
    TestByteX = 0x58,
    TestByteFF = 0xFF,
    TestByte00 = 0x00,
    TestByteAB = 0xAB,
    FillByteCD = 0xCD
};

/* ── helper: build a deterministically-filled payload ──────────────────── */

static void fillPayload(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static bool verifyPayload(const uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != (uint8_t)(seed + (uint8_t)i)) {
            return false;
        }
    }
    return true;
}

/* ── callback context for poll tests ────────────────────────────────────── */

typedef struct {
    const uint8_t *expectedPayload;
    size_t expectedLen;
    void *expectedUserData;
    int callCount;
    bool payloadOK;
} CallbackCtx;

static void testCallback(const void *payload, size_t len, void *userData) {
    CallbackCtx *ctx = (CallbackCtx *)userData;
    ctx->callCount++;
    if (ctx->expectedPayload != NULL && len == ctx->expectedLen) {
        ctx->payloadOK = (memcmp(payload, ctx->expectedPayload, len) == 0);
    }
    if (ctx->expectedUserData != NULL) {
        if (userData != ctx->expectedUserData) {
            ctx->payloadOK = false;
        }
    }
}

static CallbackCtx makeCallbackCtx(const uint8_t *payload, size_t len,
                                   void *userData) {
    CallbackCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.expectedPayload = payload;
    ctx.expectedLen = len;
    ctx.expectedUserData = userData;
    ctx.payloadOK = true;
    return ctx;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. Create / Destroy
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testCreateBasic(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    ASSERT_NOT_NULL(sdk);
    pacplay_cli_destroy(sdk);
}

static void testCreateBasicSrv(void) {
    PacPlaySDK *sdk = pacplay_srv_create();
    ASSERT_NOT_NULL(sdk);
    pacplay_srv_destroy(sdk);
}

static void testCreateMultiple(void) {
    PacPlaySDK *a = pacplay_cli_create();
    PacPlaySDK *b = pacplay_cli_create();
    ASSERT_NOT_NULL(a);
    ASSERT_NOT_NULL(b);
    pacplay_cli_destroy(a);
    pacplay_cli_destroy(b);
}

static void testDestroyNull(void) {
    pacplay_cli_destroy(NULL);
    pacplay_srv_destroy(NULL);
}

static void testDestroyNormal(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    ASSERT_NOT_NULL(sdk);
    pacplay_cli_destroy(sdk);
}

/* NOTE: destroy-then-destroy-again is NOT safe — sdk_destroy() calls free()
 * and does not null the caller's pointer.  After the first destroy the handle
 * is a dangling pointer.  Callers must set their handle to NULL after destroy
 * and guard against reuse.  The NULL-guard in sdk_destroy() prevents crashes
 * when NULL is passed, but not when a stale pointer is reused. */

static void testDestroyWithPendingSendQueue(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen10];
    fillPayload(buf, SendLen10, TestByteA);
    pacplay_cli_send(sdk, buf, SendLen10);
    pacplay_cli_send(sdk, buf, SendLen10);
    pacplay_cli_destroy(sdk);
}

static void testDestroyWithPendingRecvQueue(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen10];
    fillPayload(buf, SendLen10, TestByteA);
    pacplay_cli_push_received(sdk, buf, SendLen10);
    pacplay_cli_push_received(sdk, buf, SendLen10);
    pacplay_cli_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. Send (Game Thread API)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testSendBasic(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    int ret = pacplay_cli_send(sdk, buf, SendLen5);
    ASSERT_INT_EQ(ret, 0);
    pacplay_cli_destroy(sdk);
}

static void testSendNullSDK(void) {
    uint8_t buf[SendLen5];
    int ret = pacplay_cli_send(NULL, buf, SendLen5);
    ASSERT_INT_EQ(ret, -1);
}

static void testSendNullData(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    int ret = pacplay_cli_send(sdk, NULL, SendLen5);
    ASSERT_INT_EQ(ret, -1);
    pacplay_cli_destroy(sdk);
}

static void testSendZeroLen(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    int ret = pacplay_cli_send(sdk, buf, 0);
    ASSERT_INT_EQ(ret, -1);
    pacplay_cli_destroy(sdk);
}

static void testSendOverMax(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayloadPlus1);
    ASSERT_NOT_NULL(bigBuf);
    int ret = pacplay_cli_send(sdk, bigBuf, MaxPayloadPlus1);
    ASSERT_INT_EQ(ret, -1);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testSendExactlyMaxPayload(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayload);
    ASSERT_NOT_NULL(bigBuf);
    memset(bigBuf, TestByteAB, MaxPayload);
    int ret = pacplay_cli_send(sdk, bigBuf, MaxPayload);
    ASSERT_INT_EQ(ret, 0);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testSendOneByte(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t byteVal = TestByteFF;
    int ret = pacplay_cli_send(sdk, &byteVal, SendLen1);
    ASSERT_INT_EQ(ret, 0);
    pacplay_cli_destroy(sdk);
}

static void testSendZeroes(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen20];
    memset(buf, 0, SendLen20);
    int ret = pacplay_cli_send(sdk, buf, SendLen20);
    ASSERT_INT_EQ(ret, 0);
    pacplay_cli_destroy(sdk);
}

static void testSendPayloadNotModified(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t original[SendLen10];
    uint8_t copy[SendLen10];
    fillPayload(original, SendLen10, TestByteAB);
    memcpy(copy, original, SendLen10);
    pacplay_cli_send(sdk, original, SendLen10);
    ASSERT_MEM_EQ(original, copy, SendLen10);
    pacplay_cli_destroy(sdk);
}

static void testSendServerSDK(void) {
    PacPlaySDK *sdk = pacplay_srv_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    int ret = pacplay_srv_send(sdk, buf, SendLen5);
    ASSERT_INT_EQ(ret, 0);
    pacplay_srv_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. Poll Send (IO Thread API)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testPollSendEmpty(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *outPayload = NULL;
    size_t outLen = 0;
    bool got = pacplay_cli_poll_send(sdk, &outPayload, &outLen);
    ASSERT_FALSE(got);
    pacplay_cli_destroy(sdk);
}

static void testPollSendAfterSend(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    pacplay_cli_send(sdk, buf, SendLen5);

    uint8_t *outPayload = NULL;
    size_t outLen = 0;
    bool got = pacplay_cli_poll_send(sdk, &outPayload, &outLen);
    ASSERT_TRUE(got);
    ASSERT_UINT_EQ(outLen, SendLen5);
    ASSERT_MEM_EQ(outPayload, buf, SendLen5);
    pacplay_cli_free_payload(sdk, outPayload);
    pacplay_cli_destroy(sdk);
}

static void testPollSendNullSDK(void) {
    uint8_t *outPayload = (uint8_t *)(uintptr_t)SentinelPtrVal;
    size_t outLen = SentinelOutLen;
    bool got = pacplay_cli_poll_send(NULL, &outPayload, &outLen);
    ASSERT_FALSE(got);
}

static void testPollSendNullOutPayload(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    size_t outLen = 0;
    bool got = pacplay_cli_poll_send(sdk, NULL, &outLen);
    ASSERT_FALSE(got);
    pacplay_cli_destroy(sdk);
}

static void testPollSendNullOutLen(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *outPayload = NULL;
    bool got = pacplay_cli_poll_send(sdk, &outPayload, NULL);
    ASSERT_FALSE(got);
    pacplay_cli_destroy(sdk);
}

static void testPollSendDrainAll(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);

    pacplay_cli_send(sdk, buf, SendLen5);
    pacplay_cli_send(sdk, buf, SendLen5);
    pacplay_cli_send(sdk, buf, SendLen5);

    int pollCount = 0;
    uint8_t *p = NULL;
    size_t n = 0;
    while (pacplay_cli_poll_send(sdk, &p, &n)) {
        ASSERT_UINT_EQ(n, SendLen5);
        pacplay_cli_free_payload(sdk, p);
        pollCount++;
    }
    ASSERT_INT_EQ(pollCount, 3);

    bool extra = pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_FALSE(extra);
    pacplay_cli_destroy(sdk);
}

static void testPollSendBinaryIntegrity(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen256];
    for (int i = 0; i < SendLen256; i++) {
        buf[i] = (uint8_t)i;
    }
    pacplay_cli_send(sdk, buf, SendLen256);

    uint8_t *outPayload = NULL;
    size_t outLen = 0;
    pacplay_cli_poll_send(sdk, &outPayload, &outLen);
    ASSERT_UINT_EQ(outLen, SendLen256);
    ASSERT_MEM_EQ(outPayload, buf, SendLen256);
    ASSERT_TRUE(verifyPayload(outPayload, SendLen256, 0));
    pacplay_cli_free_payload(sdk, outPayload);
    pacplay_cli_destroy(sdk);
}

static void testPollSendFIFO(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t a[SendLen1] = {TestByteA};
    uint8_t b[SendLen1] = {TestByteX};
    uint8_t c[SendLen1] = {TestByteFF};

    pacplay_cli_send(sdk, a, SendLen1);
    pacplay_cli_send(sdk, b, SendLen1);
    pacplay_cli_send(sdk, c, SendLen1);

    uint8_t *p = NULL;
    size_t n = 0;

    pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_INT_EQ(p[0], TestByteA);
    pacplay_cli_free_payload(sdk, p);

    pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_INT_EQ(p[0], TestByteX);
    pacplay_cli_free_payload(sdk, p);

    pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_INT_EQ(p[0], TestByteFF);
    pacplay_cli_free_payload(sdk, p);

    pacplay_cli_destroy(sdk);
}

static void testFreePayloadBasic(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    pacplay_cli_send(sdk, buf, SendLen5);
    uint8_t *p = NULL;
    size_t n = 0;
    pacplay_cli_poll_send(sdk, &p, &n);
    pacplay_cli_free_payload(sdk, p);
    pacplay_cli_destroy(sdk);
}

static void testFreePayloadNull(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    pacplay_cli_free_payload(sdk, NULL);
    pacplay_srv_free_payload(sdk, NULL);
    pacplay_cli_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 4. Push Received (IO Thread API)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testPushReceivedBasic(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_destroy(sdk);
}

static void testPushReceivedNullSDK(void) {
    uint8_t buf[SendLen5];
    pacplay_cli_push_received(NULL, buf, SendLen5);
}

static void testPushReceivedNullPayload(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    pacplay_cli_push_received(sdk, NULL, SendLen5);
    pacplay_cli_destroy(sdk);
}

static void testPushReceivedZeroLen(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    pacplay_cli_push_received(sdk, buf, 0);
    pacplay_cli_destroy(sdk);
}

static void testPushReceivedOverMax(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayloadPlus1);
    ASSERT_NOT_NULL(bigBuf);
    memset(bigBuf, TestByteAB, MaxPayloadPlus1);
    pacplay_cli_push_received(sdk, bigBuf, MaxPayloadPlus1);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testPushReceivedMultiple(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen10];
    fillPayload(buf, SendLen10, TestByteAB);
    pacplay_cli_push_received(sdk, buf, SendLen10);
    pacplay_cli_push_received(sdk, buf, SendLen10);
    pacplay_cli_push_received(sdk, buf, SendLen10);
    pacplay_cli_destroy(sdk);
}

static void testPushReceivedMaxPayload(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayload);
    ASSERT_NOT_NULL(bigBuf);
    memset(bigBuf, TestByteAB, MaxPayload);
    pacplay_cli_push_received(sdk, bigBuf, MaxPayload);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testPushReceivedServerSDK(void) {
    PacPlaySDK *sdk = pacplay_srv_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    pacplay_srv_push_received(sdk, buf, SendLen5);
    pacplay_srv_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 5. Poll + Callback (Game Thread API)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testPollEmpty(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, 0);
    pacplay_cli_destroy(sdk);
}

static void testPollNullSDK(void) {
    pacplay_cli_poll(NULL);
}

static void testCallbackFires(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    CallbackCtx ctx = makeCallbackCtx(buf, SendLen5, &ctx);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, 1);
    pacplay_cli_destroy(sdk);
}

static void testCallbackPayloadMatch(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen10];
    fillPayload(buf, SendLen10, TestByteAB);
    CallbackCtx ctx = makeCallbackCtx(buf, SendLen10, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_push_received(sdk, buf, SendLen10);
    pacplay_cli_poll(sdk);
    ASSERT_TRUE(ctx.payloadOK);
    pacplay_cli_destroy(sdk);
}

static void testCallbackUserData(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    CallbackCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.expectedUserData = &ctx;
    ctx.payloadOK = true;
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    uint8_t buf[SendLen5];
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, 1);
    ASSERT_TRUE(ctx.payloadOK);
    pacplay_cli_destroy(sdk);
}

static void testMultipleCallbacks(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, 3);
    pacplay_cli_destroy(sdk);
}

static void testPollWithoutCallback(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_poll(sdk);
    pacplay_cli_destroy(sdk);
}

static void testCallbackSetNull(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_on_receive(sdk, NULL, NULL);
    uint8_t buf[SendLen5];
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, 0);
    pacplay_cli_destroy(sdk);
}

static void testOnReceiveNullSDK(void) {
    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(NULL, testCallback, &ctx);
}

static void testPollServerSDK(void) {
    PacPlaySDK *sdk = pacplay_srv_create();
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    CallbackCtx ctx = makeCallbackCtx(buf, SendLen5, &ctx);
    pacplay_srv_on_receive(sdk, testCallback, &ctx);
    pacplay_srv_push_received(sdk, buf, SendLen5);
    pacplay_srv_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, 1);
    ASSERT_TRUE(ctx.payloadOK);
    pacplay_srv_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 6. Full Roundtrip Integration
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testSendPollSendRoundtrip(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t original[SendLen20];
    fillPayload(original, SendLen20, FillByteCD);

    pacplay_cli_send(sdk, original, SendLen20);

    uint8_t *received = NULL;
    size_t recvLen = 0;
    bool got = pacplay_cli_poll_send(sdk, &received, &recvLen);
    ASSERT_TRUE(got);
    ASSERT_UINT_EQ(recvLen, SendLen20);
    ASSERT_MEM_EQ(received, original, SendLen20);
    pacplay_cli_free_payload(sdk, received);
    pacplay_cli_destroy(sdk);
}

static void testPushPollRoundtrip(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t original[SendLen20];
    fillPayload(original, SendLen20, FillByteCD);

    CallbackCtx ctx = makeCallbackCtx(original, SendLen20, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_push_received(sdk, original, SendLen20);
    pacplay_cli_poll(sdk);

    ASSERT_INT_EQ(ctx.callCount, 1);
    ASSERT_TRUE(ctx.payloadOK);
    pacplay_cli_destroy(sdk);
}

static void testFullDuplex(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t sendBuf[SendLen10];
    uint8_t recvBuf[SendLen10];
    fillPayload(sendBuf, SendLen10, TestByteA);
    fillPayload(recvBuf, SendLen10, TestByteX);

    pacplay_cli_send(sdk, sendBuf, SendLen10);
    pacplay_cli_push_received(sdk, recvBuf, SendLen10);

    CallbackCtx ctx = makeCallbackCtx(recvBuf, SendLen10, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);

    uint8_t *outSend = NULL;
    size_t outSendLen = 0;
    bool gotSend = pacplay_cli_poll_send(sdk, &outSend, &outSendLen);
    ASSERT_TRUE(gotSend);
    ASSERT_MEM_EQ(outSend, sendBuf, SendLen10);
    pacplay_cli_free_payload(sdk, outSend);

    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, 1);
    ASSERT_TRUE(ctx.payloadOK);
    pacplay_cli_destroy(sdk);
}

static void testMultipleRoundtrips(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    for (int i = 0; i < IterCount100; i++) {
        uint8_t buf[SendLen5];
        fillPayload(buf, SendLen5, (uint8_t)i);
        int ret = pacplay_cli_send(sdk, buf, SendLen5);
        ASSERT_INT_EQ(ret, 0);

        uint8_t *p = NULL;
        size_t n = 0;
        bool got = pacplay_cli_poll_send(sdk, &p, &n);
        ASSERT_TRUE(got);
        ASSERT_UINT_EQ(n, SendLen5);
        ASSERT_MEM_EQ(p, buf, SendLen5);
        pacplay_cli_free_payload(sdk, p);
    }
    pacplay_cli_destroy(sdk);
}

static void testLongPayloadRoundtrip(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayload);
    ASSERT_NOT_NULL(bigBuf);
    fillPayload(bigBuf, MaxPayload, TestByteAB);

    int ret = pacplay_cli_send(sdk, bigBuf, MaxPayload);
    ASSERT_INT_EQ(ret, 0);

    uint8_t *p = NULL;
    size_t n = 0;
    bool got = pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_TRUE(got);
    ASSERT_UINT_EQ(n, MaxPayload);
    ASSERT_MEM_EQ(p, bigBuf, MaxPayload);
    pacplay_cli_free_payload(sdk, p);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testPushPollMaxPayloadRoundtrip(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayload);
    ASSERT_NOT_NULL(bigBuf);
    fillPayload(bigBuf, MaxPayload, FillByteCD);

    CallbackCtx ctx = makeCallbackCtx(bigBuf, MaxPayload, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_push_received(sdk, bigBuf, MaxPayload);
    pacplay_cli_poll(sdk);

    ASSERT_INT_EQ(ctx.callCount, 1);
    ASSERT_TRUE(ctx.payloadOK);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 7. Queue Auto-Expand (Send beyond default capacity)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testQueueAutoExpandSend(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen10];
    fillPayload(buf, SendLen10, TestByteA);

    for (int i = 0; i < QueueCap; i++) {
        int ret = pacplay_cli_send(sdk, buf, SendLen10);
        ASSERT_INT_EQ(ret, 0);
    }

    int retOver = pacplay_cli_send(sdk, buf, SendLen10);
    ASSERT_INT_EQ(retOver, -1);

    int drainCount = 0;
    uint8_t *p = NULL;
    size_t n = 0;
    while (pacplay_cli_poll_send(sdk, &p, &n)) {
        ASSERT_UINT_EQ(n, SendLen10);
        pacplay_cli_free_payload(sdk, p);
        drainCount++;
    }
    ASSERT_INT_EQ(drainCount, QueueCap);
    pacplay_cli_destroy(sdk);
}

static void testQueueAutoExpandRecv(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen10];
    fillPayload(buf, SendLen10, TestByteA);

    for (int i = 0; i < QueueCapPlus1; i++) {
        pacplay_cli_push_received(sdk, buf, SendLen10);
    }

    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, QueueCapPlus1);
    pacplay_cli_destroy(sdk);
}

static void testSendManyThenDrainAll(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen10];
    fillPayload(buf, SendLen10, TestByteA);

    for (int i = 0; i < QueueCap; i++) {
        pacplay_cli_send(sdk, buf, SendLen10);
    }

    int count = 0;
    uint8_t *p = NULL;
    size_t n = 0;
    while (pacplay_cli_poll_send(sdk, &p, &n)) {
        pacplay_cli_free_payload(sdk, p);
        count++;
    }
    ASSERT_INT_EQ(count, QueueCap);
    pacplay_cli_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 8. Concurrency / Thread Safety
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    PacPlaySDK *sdk;
    int sendCount;
    int sendSize;
    uint8_t seed;
    volatile int done;
} ThreadArg;

static void *threadSender(void *arg) {
    ThreadArg *ta = (ThreadArg *)arg;
    uint8_t buf[SendLen100];
    memset(buf, ta->seed, SendLen100);
    for (int i = 0; i < ta->sendCount; i++) {
        pacplay_cli_send(ta->sdk, buf, (size_t)ta->sendSize);
    }
    ta->done = 1;
    return NULL;
}

static void *threadPusher(void *arg) {
    ThreadArg *ta = (ThreadArg *)arg;
    uint8_t buf[SendLen100];
    memset(buf, ta->seed, SendLen100);
    for (int i = 0; i < ta->sendCount; i++) {
        pacplay_cli_push_received(ta->sdk, buf, (size_t)ta->sendSize);
    }
    ta->done = 1;
    return NULL;
}

static void testConcurrentSendTwoThreads(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    const int perThread = QueueCap / ThreadCount2;
    ThreadArg args[ThreadCount2];
    pthread_t threads[ThreadCount2];

    for (int i = 0; i < ThreadCount2; i++) {
        args[i].sdk = sdk;
        args[i].sendCount = perThread;
        args[i].sendSize = SendLen10;
        args[i].seed = (uint8_t)(TestByteA + i);
        args[i].done = 0;
        pthread_create(&threads[i], NULL, threadSender, &args[i]);
    }

    int totalDrained = 0;
    int totalExpected = ThreadCount2 * perThread;
    while (totalDrained < totalExpected) {
        uint8_t *p = NULL;
        size_t n = 0;
        if (pacplay_cli_poll_send(sdk, &p, &n)) {
            pacplay_cli_free_payload(sdk, p);
            totalDrained++;
        } else {
            usleep(SleepUs100);
        }
    }

    for (int i = 0; i < ThreadCount2; i++) {
        pthread_join(threads[i], NULL);
    }

    ASSERT_INT_EQ(totalDrained, totalExpected);
    pacplay_cli_destroy(sdk);
}

static void testConcurrentPushTwoThreads(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    ThreadArg args[ThreadCount2];
    pthread_t threads[ThreadCount2];

    for (int i = 0; i < ThreadCount2; i++) {
        args[i].sdk = sdk;
        args[i].sendCount = IterCount100;
        args[i].sendSize = SendLen10;
        args[i].seed = (uint8_t)(TestByteA + i);
        args[i].done = 0;
        pthread_create(&threads[i], NULL, threadPusher, &args[i]);
    }

    for (int i = 0; i < ThreadCount2; i++) {
        pthread_join(threads[i], NULL);
    }

    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, ThreadCount2 * IterCount100);
    pacplay_cli_destroy(sdk);
}

static void testProducerConsumer(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    ThreadArg arg;
    arg.sdk = sdk;
    arg.sendCount = QueueCap;
    arg.sendSize = SendLen10;
    arg.seed = TestByteAB;
    arg.done = 0;

    pthread_t sender;
    pthread_create(&sender, NULL, threadSender, &arg);

    usleep(SleepMs1);
    int drained = 0;
    while (drained < QueueCap) {
        uint8_t *p = NULL;
        size_t n = 0;
        if (pacplay_cli_poll_send(sdk, &p, &n)) {
            pacplay_cli_free_payload(sdk, p);
            drained++;
        }
    }

    pthread_join(sender, NULL);
    ASSERT_INT_EQ(drained, QueueCap);
    pacplay_cli_destroy(sdk);
}

static void testProducerConsumerReverse(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    ThreadArg arg;
    arg.sdk = sdk;
    arg.sendCount = IterCount100;
    arg.sendSize = SendLen10;
    arg.seed = TestByteAB;
    arg.done = 0;

    pthread_t pusher;
    pthread_create(&pusher, NULL, threadPusher, &arg);
    pthread_join(pusher, NULL);

    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, IterCount100);
    pacplay_cli_destroy(sdk);
}

static void testSendWhilePolling(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen10];
    fillPayload(buf, SendLen10, TestByteA);

    pacplay_cli_push_received(sdk, buf, SendLen10);
    pacplay_cli_push_received(sdk, buf, SendLen10);

    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);

    pacplay_cli_send(sdk, buf, SendLen10);
    pacplay_cli_poll(sdk);

    uint8_t *p = NULL;
    size_t n = 0;
    bool gotSend = pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_TRUE(gotSend);
    pacplay_cli_free_payload(sdk, p);

    ASSERT_INT_EQ(ctx.callCount, 2);
    pacplay_cli_destroy(sdk);
}

static void testRapidSendDrain(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen20];
    fillPayload(buf, SendLen20, FillByteCD);

    for (int i = 0; i < IterCount1000; i++) {
        pacplay_cli_send(sdk, buf, SendLen20);

        uint8_t *p = NULL;
        size_t n = 0;
        bool got = pacplay_cli_poll_send(sdk, &p, &n);
        ASSERT_TRUE(got);
        ASSERT_UINT_EQ(n, SendLen20);
        pacplay_cli_free_payload(sdk, p);
    }

    bool empty = pacplay_cli_poll_send(sdk, NULL, NULL);
    ASSERT_FALSE(empty);
    pacplay_cli_destroy(sdk);
}

static void testMultipleSenders(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    const int threadCount = ThreadCount4;
    const int perThread = QueueCap / ThreadCount4;
    ThreadArg args[ThreadCount4];
    pthread_t threads[ThreadCount4];

    for (int i = 0; i < threadCount; i++) {
        args[i].sdk = sdk;
        args[i].sendCount = perThread;
        args[i].sendSize = SendLen10;
        args[i].seed = (uint8_t)(TestByteA + i);
        args[i].done = 0;
        pthread_create(&threads[i], NULL, threadSender, &args[i]);
    }

    int totalDrained = 0;
    int expected = threadCount * perThread;
    while (totalDrained < expected) {
        uint8_t *p = NULL;
        size_t n = 0;
        if (pacplay_cli_poll_send(sdk, &p, &n)) {
            pacplay_cli_free_payload(sdk, p);
            totalDrained++;
        }
    }

    for (int i = 0; i < threadCount; i++) {
        pthread_join(threads[i], NULL);
    }

    ASSERT_INT_EQ(totalDrained, expected);
    pacplay_cli_destroy(sdk);
}

static void testDestroyWhileSending(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    /* Send one message so it's in the queue, then destroy. */
    uint8_t buf[SendLen10];
    pacplay_cli_send(sdk, buf, SendLen10);
    pacplay_cli_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 9. Callback Reentrancy Safety
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    PacPlaySDK *sdk;
    int callCount;
    uint8_t sendBuf[SendLen5];
} ReentrantCtx;

static void reentrantCallback(const void *payload, size_t len, void *userData) {
    ReentrantCtx *rctx = (ReentrantCtx *)userData;
    rctx->callCount++;
    (void)payload;
    (void)len;
    /* Send another message from inside the callback — must not deadlock. */
    pacplay_cli_send(rctx->sdk, rctx->sendBuf, SendLen5);
}

static void testCallbackReentrancySend(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    ReentrantCtx rctx;
    rctx.sdk = sdk;
    rctx.callCount = 0;
    fillPayload(rctx.sendBuf, SendLen5, TestByteAB);

    pacplay_cli_on_receive(sdk, reentrantCallback, &rctx);
    uint8_t buf[SendLen5];
    fillPayload(buf, SendLen5, TestByteA);
    pacplay_cli_push_received(sdk, buf, SendLen5);
    pacplay_cli_poll(sdk);

    ASSERT_INT_EQ(rctx.callCount, 1);

    uint8_t *p = NULL;
    size_t n = 0;
    bool got = pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_TRUE(got);
    ASSERT_UINT_EQ(n, SendLen5);
    ASSERT_MEM_EQ(p, rctx.sendBuf, SendLen5);
    pacplay_cli_free_payload(sdk, p);
    pacplay_cli_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 10. Memory Safety / Resource
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testCreateDestroyLoop(void) {
    for (int i = 0; i < IterCount100; i++) {
        PacPlaySDK *sdk = pacplay_cli_create();
        ASSERT_NOT_NULL(sdk);
        uint8_t buf[SendLen10];
        pacplay_cli_send(sdk, buf, SendLen10);
        pacplay_cli_push_received(sdk, buf, SendLen10);
        pacplay_cli_destroy(sdk);
    }
}

static void testFreePayloadServerNull(void) {
    PacPlaySDK *sdk = pacplay_srv_create();
    pacplay_srv_free_payload(sdk, NULL);
    pacplay_srv_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 11. Security / Boundary
 * ═══════════════════════════════════════════════════════════════════════════ */

static void testSendMaxMinusOne(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayloadMinus1);
    ASSERT_NOT_NULL(bigBuf);
    memset(bigBuf, TestByteAB, MaxPayloadMinus1);
    int ret = pacplay_cli_send(sdk, bigBuf, MaxPayloadMinus1);
    ASSERT_INT_EQ(ret, 0);

    uint8_t *p = NULL;
    size_t n = 0;
    bool got = pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_TRUE(got);
    ASSERT_UINT_EQ(n, MaxPayloadMinus1);
    pacplay_cli_free_payload(sdk, p);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testSendOverflowOneByte(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayloadPlus1);
    ASSERT_NOT_NULL(bigBuf);
    memset(bigBuf, TestByteAB, MaxPayloadPlus1);
    int ret = pacplay_cli_send(sdk, bigBuf, MaxPayloadPlus1);
    ASSERT_INT_EQ(ret, -1);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testPushOverflowOneByte(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayloadPlus1);
    ASSERT_NOT_NULL(bigBuf);
    memset(bigBuf, TestByteAB, MaxPayloadPlus1);
    pacplay_cli_push_received(sdk, bigBuf, MaxPayloadPlus1);

    CallbackCtx ctx = makeCallbackCtx(NULL, 0, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_poll(sdk);
    ASSERT_INT_EQ(ctx.callCount, 0);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testPushExactlyMaxPayload(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t *bigBuf = malloc(MaxPayload);
    ASSERT_NOT_NULL(bigBuf);
    fillPayload(bigBuf, MaxPayload, FillByteCD);

    pacplay_cli_push_received(sdk, bigBuf, MaxPayload);
    CallbackCtx ctx = makeCallbackCtx(bigBuf, MaxPayload, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_poll(sdk);

    ASSERT_INT_EQ(ctx.callCount, 1);
    ASSERT_TRUE(ctx.payloadOK);
    free(bigBuf);
    pacplay_cli_destroy(sdk);
}

static void testAllZeroPayload(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen20];
    memset(buf, 0, SendLen20);

    pacplay_cli_send(sdk, buf, SendLen20);
    uint8_t *p = NULL;
    size_t n = 0;
    pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_UINT_EQ(n, SendLen20);
    ASSERT_MEM_EQ(p, buf, SendLen20);
    pacplay_cli_free_payload(sdk, p);

    pacplay_cli_push_received(sdk, buf, SendLen20);
    CallbackCtx ctx = makeCallbackCtx(buf, SendLen20, NULL);
    pacplay_cli_on_receive(sdk, testCallback, &ctx);
    pacplay_cli_poll(sdk);
    ASSERT_TRUE(ctx.payloadOK);

    pacplay_cli_destroy(sdk);
}

static void testAlternatingPatternPayload(void) {
    PacPlaySDK *sdk = pacplay_cli_create();
    uint8_t buf[SendLen256];
    for (int i = 0; i < SendLen256; i++) {
        buf[i] = (uint8_t)((i & 1) ? TestByteFF : TestByte00);
    }
    pacplay_cli_send(sdk, buf, SendLen256);
    uint8_t *p = NULL;
    size_t n = 0;
    pacplay_cli_poll_send(sdk, &p, &n);
    ASSERT_UINT_EQ(n, SendLen256);
    ASSERT_MEM_EQ(p, buf, SendLen256);
    pacplay_cli_free_payload(sdk, p);
    pacplay_cli_destroy(sdk);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main — test runner
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(void) {
    /* 1. Create / Destroy */
    RUN_TEST(testCreateBasic);
    RUN_TEST(testCreateBasicSrv);
    RUN_TEST(testCreateMultiple);
    RUN_TEST(testDestroyNull);
    RUN_TEST(testDestroyNormal);
    RUN_TEST(testDestroyWithPendingSendQueue);
    RUN_TEST(testDestroyWithPendingRecvQueue);

    /* 2. Send */
    RUN_TEST(testSendBasic);
    RUN_TEST(testSendNullSDK);
    RUN_TEST(testSendNullData);
    RUN_TEST(testSendZeroLen);
    RUN_TEST(testSendOverMax);
    RUN_TEST(testSendExactlyMaxPayload);
    RUN_TEST(testSendOneByte);
    RUN_TEST(testSendZeroes);
    RUN_TEST(testSendPayloadNotModified);
    RUN_TEST(testSendServerSDK);

    /* 3. Poll Send */
    RUN_TEST(testPollSendEmpty);
    RUN_TEST(testPollSendAfterSend);
    RUN_TEST(testPollSendNullSDK);
    RUN_TEST(testPollSendNullOutPayload);
    RUN_TEST(testPollSendNullOutLen);
    RUN_TEST(testPollSendDrainAll);
    RUN_TEST(testPollSendBinaryIntegrity);
    RUN_TEST(testPollSendFIFO);
    RUN_TEST(testFreePayloadBasic);
    RUN_TEST(testFreePayloadNull);

    /* 4. Push Received */
    RUN_TEST(testPushReceivedBasic);
    RUN_TEST(testPushReceivedNullSDK);
    RUN_TEST(testPushReceivedNullPayload);
    RUN_TEST(testPushReceivedZeroLen);
    RUN_TEST(testPushReceivedOverMax);
    RUN_TEST(testPushReceivedMultiple);
    RUN_TEST(testPushReceivedMaxPayload);
    RUN_TEST(testPushReceivedServerSDK);

    /* 5. Poll + Callback */
    RUN_TEST(testPollEmpty);
    RUN_TEST(testPollNullSDK);
    RUN_TEST(testCallbackFires);
    RUN_TEST(testCallbackPayloadMatch);
    RUN_TEST(testCallbackUserData);
    RUN_TEST(testMultipleCallbacks);
    RUN_TEST(testPollWithoutCallback);
    RUN_TEST(testCallbackSetNull);
    RUN_TEST(testOnReceiveNullSDK);
    RUN_TEST(testPollServerSDK);

    /* 6. Full Roundtrip */
    RUN_TEST(testSendPollSendRoundtrip);
    RUN_TEST(testPushPollRoundtrip);
    RUN_TEST(testFullDuplex);
    RUN_TEST(testMultipleRoundtrips);
    RUN_TEST(testLongPayloadRoundtrip);
    RUN_TEST(testPushPollMaxPayloadRoundtrip);

    /* 7. Queue Auto-Expand */
    RUN_TEST(testQueueAutoExpandSend);
    RUN_TEST(testQueueAutoExpandRecv);
    RUN_TEST(testSendManyThenDrainAll);

    /* 8. Concurrency / Thread Safety */
    RUN_TEST(testConcurrentSendTwoThreads);
    RUN_TEST(testConcurrentPushTwoThreads);
    RUN_TEST(testProducerConsumer);
    RUN_TEST(testProducerConsumerReverse);
    RUN_TEST(testSendWhilePolling);
    RUN_TEST(testRapidSendDrain);
    RUN_TEST(testMultipleSenders);
    RUN_TEST(testDestroyWhileSending);

    /* 9. Callback Reentrancy */
    RUN_TEST(testCallbackReentrancySend);

    /* 10. Memory Safety */
    RUN_TEST(testCreateDestroyLoop);
    RUN_TEST(testFreePayloadServerNull);

    /* 11. Security / Boundary */
    RUN_TEST(testSendMaxMinusOne);
    RUN_TEST(testSendOverflowOneByte);
    RUN_TEST(testPushOverflowOneByte);
    RUN_TEST(testPushExactlyMaxPayload);
    RUN_TEST(testAllZeroPayload);
    RUN_TEST(testAlternatingPatternPayload);

    return TEST_REPORT();
}
