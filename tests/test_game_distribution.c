#include "archive.h"
#include "client/gameDownload.h"
#include "protocol.h"
#include "server/downloadPool.h"
#include "test_utils.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    HkdfKeyLen = 32,
    HkdfSaltLen = 32,
    HkdfOutLen = 32,
    HkdfDeriveFail = -1,
    HkdfDeriveSucc = 0
};

enum {
    ExpectedResumeInfoSize = 87,
    ResumeInfoGameIdOffset = 0,
    ResumeInfoHashOffset = 4,
    ResumeInfoTotalChunksOffset = 69,
    ResumeInfoReceivedChunksOffset = 73,
    ResumeInfoFileSizeOffset = 77,
    ResumeInfoDataPortOffset = 85
};

enum {
    TestGameId = 42,
    TestFileSize = 131072,
    TestTotalChunks = 2,
    TestReceivedChunks = 1,
    TestDataPort = 19801,
    FillByte = 0xAB
};

enum {
    ExpectedMaxChunkRetries = 3,
    MaxReasonableRetries = 10,
    ExpectedTokenExpireSecs = 30
};

enum { GameInfoEntryCount = 3, ChunkCountHundred = 100 };

enum { RespStatusSuccess = 0, RespStatusFailure = 1 };

enum { TestCreatedAt = 1718600000, TestUpdatedAt = 1718700000 };

enum { TypicalPort = 8080, MaxSafePort = 65534, OverflowPort = 65535 };

static int testDeriveDataChannelKey(const uint8_t *mainKey, const uint8_t *salt,
                                    uint8_t *outKey) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return HkdfDeriveFail;
    }

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) {
        return HkdfDeriveFail;
    }

    const char *info = HKDF_INFO_DATA_CHANNEL;
    const char *digest = "SHA256";

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0),
        OSSL_PARAM_construct_octet_string("key", (void *)mainKey,
                                          AES_GCM_KEY_LEN),
        OSSL_PARAM_construct_octet_string("salt", (void *)salt,
                                          DATA_AUTH_TOKEN_LEN),
        OSSL_PARAM_construct_octet_string("info", (void *)info, strlen(info)),
        OSSL_PARAM_construct_end()};

    int result = HkdfDeriveSucc;
    if (EVP_KDF_derive(ctx, outKey, AES_GCM_KEY_LEN, params) <= 0) {
        result = HkdfDeriveFail;
    }

    EVP_KDF_CTX_free(ctx);
    return result;
}

static void testHkdfDeterministic(void) {
    static const uint8_t testKey[HkdfKeyLen] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    static const uint8_t testSalt[HkdfSaltLen] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6,
        0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90};

    uint8_t derivedA[HkdfOutLen];
    uint8_t derivedB[HkdfOutLen];

    int retA = testDeriveDataChannelKey(testKey, testSalt, derivedA);
    int retB = testDeriveDataChannelKey(testKey, testSalt, derivedB);

    ASSERT_INT_EQ(retA, HkdfDeriveSucc);
    ASSERT_INT_EQ(retB, HkdfDeriveSucc);
    ASSERT_MEM_EQ(derivedA, derivedB, HkdfOutLen);
}

static void testHkdfDifferentInputsDifferentOutput(void) {
    static const uint8_t keyA[HkdfKeyLen] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    static const uint8_t keyB[HkdfKeyLen] = {
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5,
        0xF4, 0xF3, 0xF2, 0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA,
        0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0};

    static const uint8_t salt[HkdfSaltLen] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6,
        0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90};

    uint8_t derivedA[HkdfOutLen];
    uint8_t derivedB[HkdfOutLen];

    ASSERT_INT_EQ(testDeriveDataChannelKey(keyA, salt, derivedA),
                  HkdfDeriveSucc);
    ASSERT_INT_EQ(testDeriveDataChannelKey(keyB, salt, derivedB),
                  HkdfDeriveSucc);
    ASSERT_TRUE(memcmp(derivedA, derivedB, HkdfOutLen) != 0);
}

static void testDownloadResumeInfoLayout(void) {
    ASSERT_UINT_EQ(sizeof(DownloadResumeInfo), (size_t)ExpectedResumeInfoSize);
    ASSERT_UINT_EQ(offsetof(DownloadResumeInfo, gameId),
                   (size_t)ResumeInfoGameIdOffset);
    ASSERT_UINT_EQ(offsetof(DownloadResumeInfo, hash),
                   (size_t)ResumeInfoHashOffset);
    ASSERT_UINT_EQ(offsetof(DownloadResumeInfo, totalChunks),
                   (size_t)ResumeInfoTotalChunksOffset);
    ASSERT_UINT_EQ(offsetof(DownloadResumeInfo, receivedChunks),
                   (size_t)ResumeInfoReceivedChunksOffset);
    ASSERT_UINT_EQ(offsetof(DownloadResumeInfo, fileSize),
                   (size_t)ResumeInfoFileSizeOffset);
    ASSERT_UINT_EQ(offsetof(DownloadResumeInfo, dataPort),
                   (size_t)ResumeInfoDataPortOffset);
}

static void testGameInfoEntryPopulationRoundtrip(void) {
    GameInfoEntry src;
    memset(&src, 0, sizeof(src));
    src.gameId = TestGameId;
    strncpy(src.name, "TestGame", GAME_NAME_LEN - 1);
    strncpy(src.version, "2.0.1", GAME_VERSION_LEN - 1);
    strncpy(src.description, "An adversarial test game", GAME_DESC_LEN - 1);
    src.createdAt = TestCreatedAt;
    src.updatedAt = TestUpdatedAt;

    uint8_t buf[sizeof(GameInfoEntry)];
    memcpy(buf, &src, sizeof(GameInfoEntry));

    GameInfoEntry dst;
    memcpy(&dst, buf, sizeof(GameInfoEntry));

    ASSERT_UINT_EQ(dst.gameId, (uint32_t)TestGameId);
    ASSERT_STR_EQ(dst.name, "TestGame");
    ASSERT_STR_EQ(dst.version, "2.0.1");
    ASSERT_STR_EQ(dst.description, "An adversarial test game");
    ASSERT_INT_EQ(dst.createdAt, src.createdAt);
    ASSERT_INT_EQ(dst.updatedAt, src.updatedAt);
    ASSERT_MEM_EQ(&src, &dst, sizeof(GameInfoEntry));
}

static void testGameListReqRangeAllGames(void) {
    GameListReqPayload req;
    memset(&req, 0, sizeof(req));
    req.rangeStart = 0;
    req.rangeEnd = 0;
    ASSERT_UINT_EQ(req.rangeStart, 0u);
    ASSERT_UINT_EQ(req.rangeEnd, 0u);
}

static void testGameListReqRangeNormal(void) {
    enum { RangeStart = 5, RangeEnd = 10 };
    GameListReqPayload req;
    memset(&req, 0, sizeof(req));
    req.rangeStart = RangeStart;
    req.rangeEnd = RangeEnd;
    ASSERT_UINT_EQ(req.rangeStart, (uint32_t)RangeStart);
    ASSERT_UINT_EQ(req.rangeEnd, (uint32_t)RangeEnd);
    ASSERT_TRUE(req.rangeStart <= req.rangeEnd);
}

static void testGameListReqRangeInverted(void) {
    enum { RangeStart = 10, RangeEnd = 5 };
    GameListReqPayload req;
    memset(&req, 0, sizeof(req));
    req.rangeStart = RangeStart;
    req.rangeEnd = RangeEnd;
    ASSERT_TRUE(req.rangeStart > req.rangeEnd);
}

static void testGameListReqRangeBoundary(void) {
    GameListReqPayload req;
    memset(&req, 0, sizeof(req));
    req.rangeStart = UINT32_MAX;
    req.rangeEnd = UINT32_MAX;
    ASSERT_UINT_EQ(req.rangeStart, UINT32_MAX);
    ASSERT_UINT_EQ(req.rangeEnd, UINT32_MAX);
}

static void testGameListReqPlatformFilter(void) {
    GameListReqPayload req;
    memset(&req, 0, sizeof(req));
    const char *plat = "linux-x86_64";
    strncpy(req.platform, plat, PLATFORM_NAME_LEN - 1);
    ASSERT_STR_EQ(req.platform, plat);
    ASSERT_UINT_EQ(req.platform[PLATFORM_NAME_LEN - 1], 0u);
    ASSERT_UINT_EQ(req.rangeStart, 0u);
    ASSERT_UINT_EQ(req.rangeEnd, 0u);
}

static void testGameListReqEmptyPlatform(void) {
    GameListReqPayload req;
    memset(&req, 0, sizeof(req));
    ASSERT_UINT_EQ(req.platform[0], 0u);
}

static void testGameListReqPlatformMaxLen(void) {
    GameListReqPayload req;
    memset(&req, 0, sizeof(req));
    const char *longPlat = "0123456789ABCDEF"; /* 16 chars = PLATFORM_NAME_LEN */
    strncpy(req.platform, longPlat, PLATFORM_NAME_LEN - 1);
    req.platform[PLATFORM_NAME_LEN - 1] = '\0';
    ASSERT_UINT_EQ(strlen(req.platform), (size_t)(PLATFORM_NAME_LEN - 1));
    ASSERT_STR_EQ(req.platform, "0123456789ABCDE");
}

static void testDataPortOffset(void) {
    ASSERT_UINT_EQ(DATA_PORT_OFFSET, 1u);
    uint32_t computed = (uint32_t)TypicalPort + DATA_PORT_OFFSET;
    ASSERT_UINT_EQ(computed, (uint32_t)(TypicalPort + 1));
}

static void testDataPortOverflowBoundary(void) {
    uint32_t safeResult = (uint32_t)MaxSafePort + DATA_PORT_OFFSET;
    ASSERT_TRUE(safeResult <= UINT16_MAX);

    uint32_t overflowResult = (uint32_t)OverflowPort + DATA_PORT_OFFSET;
    ASSERT_TRUE(overflowResult > UINT16_MAX);
}

static void testMaxChunkRetriesExpected(void) {
    ASSERT_TRUE(ExpectedMaxChunkRetries > 0);
    ASSERT_TRUE(ExpectedMaxChunkRetries <= MaxReasonableRetries);
    ASSERT_INT_EQ(ExpectedMaxChunkRetries, 3);
}

static void testTokenExpireSecs(void) {
    ASSERT_UINT_EQ(TOKEN_EXPIRE_SECS, (uint32_t)ExpectedTokenExpireSecs);
    ASSERT_TRUE(TOKEN_EXPIRE_SECS > 0);
}

static void testGameDownloadRespConstruction(void) {
    GameDownloadRespPayload resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = RespStatusSuccess;
    resp.gameId = TestGameId;
    resp.fileSize = TestFileSize;
    resp.totalChunks = TestTotalChunks;
    resp.dataPort = TestDataPort;
    memset(resp.token, FillByte, DATA_AUTH_TOKEN_LEN);
    strncpy(resp.hash, "abcdef1234567890", GAME_HASH_LEN - 1);

    ASSERT_UINT_EQ(resp.status, (uint8_t)RespStatusSuccess);
    ASSERT_UINT_EQ(resp.gameId, (uint32_t)TestGameId);
    ASSERT_UINT_EQ(resp.fileSize, (uint64_t)TestFileSize);
    ASSERT_UINT_EQ(resp.totalChunks, (uint32_t)TestTotalChunks);
    ASSERT_UINT_EQ(resp.dataPort, (uint16_t)TestDataPort);
    ASSERT_STR_EQ(resp.hash, "abcdef1234567890");
}

static void testGameDownloadRespStatusValues(void) {
    GameDownloadRespPayload succResp;
    memset(&succResp, 0, sizeof(succResp));
    succResp.status = RespStatusSuccess;
    ASSERT_UINT_EQ(succResp.status, 0u);

    GameDownloadRespPayload failResp;
    memset(&failResp, 0, sizeof(failResp));
    failResp.status = RespStatusFailure;
    ASSERT_UINT_EQ(failResp.status, 1u);
}

static void testGameInfoEntryArraySerialization(void) {
    GameInfoEntry entries[GameInfoEntryCount];
    memset(entries, 0, sizeof(entries));

    entries[0].gameId = 1;
    strncpy(entries[0].name, "GameA", GAME_NAME_LEN - 1);
    entries[1].gameId = 2;
    strncpy(entries[1].name, "GameB", GAME_NAME_LEN - 1);
    entries[2].gameId = 3;
    strncpy(entries[2].name, "GameC", GAME_NAME_LEN - 1);

    size_t totalSize = sizeof(entries);
    ASSERT_UINT_EQ(totalSize,
                   (size_t)(GameInfoEntryCount * sizeof(GameInfoEntry)));

    ASSERT_UINT_EQ(entries[0].gameId, 1u);
    ASSERT_STR_EQ(entries[0].name, "GameA");
    ASSERT_UINT_EQ(entries[1].gameId, 2u);
    ASSERT_STR_EQ(entries[1].name, "GameB");
    ASSERT_UINT_EQ(entries[2].gameId, 3u);
    ASSERT_STR_EQ(entries[2].name, "GameC");

    uint8_t *raw = (uint8_t *)entries;
    GameInfoEntry *recovered = (GameInfoEntry *)(raw + sizeof(GameInfoEntry));
    ASSERT_UINT_EQ(recovered->gameId, 2u);
    ASSERT_STR_EQ(recovered->name, "GameB");
}

static void testChunkCountZeroFile(void) {
    uint64_t fileSize = 0;
    uint64_t totalChunks =
        (fileSize == 0) ? 0
                        : (fileSize + GAME_CHUNK_SIZE - 1) / GAME_CHUNK_SIZE;
    ASSERT_UINT_EQ(totalChunks, 0u);
}

static void testChunkCountOneByteFile(void) {
    uint64_t fileSize = 1;
    uint64_t totalChunks = (fileSize + GAME_CHUNK_SIZE - 1) / GAME_CHUNK_SIZE;
    ASSERT_UINT_EQ(totalChunks, 1u);
}

static void testChunkCountExactChunk(void) {
    uint64_t fileSize = GAME_CHUNK_SIZE;
    uint64_t totalChunks = (fileSize + GAME_CHUNK_SIZE - 1) / GAME_CHUNK_SIZE;
    ASSERT_UINT_EQ(totalChunks, 1u);
}

static void testChunkCountExactChunkPlusOne(void) {
    uint64_t fileSize = (uint64_t)GAME_CHUNK_SIZE + 1;
    uint64_t totalChunks = (fileSize + GAME_CHUNK_SIZE - 1) / GAME_CHUNK_SIZE;
    ASSERT_UINT_EQ(totalChunks, 2u);
}

static void testChunkCountMultipleExact(void) {
    uint64_t fileSize = (uint64_t)GAME_CHUNK_SIZE * ChunkCountHundred;
    uint64_t totalChunks = (fileSize + GAME_CHUNK_SIZE - 1) / GAME_CHUNK_SIZE;
    ASSERT_UINT_EQ(totalChunks, (uint64_t)ChunkCountHundred);
}

static void testDownloadProgressZeroInit(void) {
    DownloadProgress prog;
    memset(&prog, 0, sizeof(prog));

    ASSERT_UINT_EQ(prog.gameId, 0u);
    ASSERT_UINT_EQ(prog.fileSize, 0u);
    ASSERT_UINT_EQ(prog.totalChunks, 0u);
    ASSERT_UINT_EQ(prog.receivedChunks, 0u);
    ASSERT_INT_EQ((int)prog.status, (int)DlPending);
    ASSERT_STR_EQ(prog.gameName, "");
    ASSERT_STR_EQ(prog.gameVersion, "");
    ASSERT_STR_EQ(prog.platform, "");
}

static void testArchiveConstants(void) {
    ASSERT_INT_EQ(ARCHIVE_SUCC, 0);
    ASSERT_INT_EQ(ARCHIVE_FAIL, -1);
}

int main(void) {
    printf("test_game_distribution:\n");

    RUN_TEST(testHkdfDeterministic);
    RUN_TEST(testHkdfDifferentInputsDifferentOutput);
    RUN_TEST(testDownloadResumeInfoLayout);
    RUN_TEST(testGameInfoEntryPopulationRoundtrip);
    RUN_TEST(testGameListReqRangeAllGames);
    RUN_TEST(testGameListReqRangeNormal);
    RUN_TEST(testGameListReqRangeInverted);
    RUN_TEST(testGameListReqRangeBoundary);
    RUN_TEST(testGameListReqPlatformFilter);
    RUN_TEST(testGameListReqEmptyPlatform);
    RUN_TEST(testGameListReqPlatformMaxLen);
    RUN_TEST(testDataPortOffset);
    RUN_TEST(testDataPortOverflowBoundary);
    RUN_TEST(testMaxChunkRetriesExpected);
    RUN_TEST(testTokenExpireSecs);
    RUN_TEST(testGameDownloadRespConstruction);
    RUN_TEST(testGameDownloadRespStatusValues);
    RUN_TEST(testGameInfoEntryArraySerialization);
    RUN_TEST(testChunkCountZeroFile);
    RUN_TEST(testChunkCountOneByteFile);
    RUN_TEST(testChunkCountExactChunk);
    RUN_TEST(testChunkCountExactChunkPlusOne);
    RUN_TEST(testChunkCountMultipleExact);
    RUN_TEST(testDownloadProgressZeroInit);
    RUN_TEST(testArchiveConstants);

    return TEST_REPORT();
}
