#include "protocol.h"
#include "test_utils.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

enum {
    ExpectedGameListEntrySize = 173,
    GameListEntryGameIdOffset = 0,
    GameListEntryFileSizeOffset = 4,
    GameListEntryNameOffset = 12,
    GameListEntryVersionOffset = 76,
    GameListEntryHashOffset = 108
};

enum {
    ExpectedGameDownloadReqSize = 24,
    GameDownloadReqGameIdOffset = 0,
    GameDownloadReqResumeOffset = 4,
    GameDownloadReqPlatformOffset = 8
};

enum {
    ExpectedGameDownloadRespSize = 116,
    GameDownloadRespStatusOffset = 0,
    GameDownloadRespGameIdOffset = 1,
    GameDownloadRespFileSizeOffset = 5,
    GameDownloadRespTotalChunksOffset = 13,
    GameDownloadRespDataPortOffset = 17,
    GameDownloadRespTokenOffset = 19,
    GameDownloadRespHashOffset = 51
};

enum {
    ExpectedGameChunkBaseSize = 8,
    ExpectedDataAuthPayloadSize = 32
};

enum {
    ExpectedGameMetadataSize = 189,
    GameMetadataGameIdOffset = 0,
    GameMetadataFileSizeOffset = 4,
    GameMetadataNameOffset = 12,
    GameMetadataVersionOffset = 76,
    GameMetadataHashOffset = 108,
    GameMetadataPlatformOffset = 173
};

enum {
    TestSeqID = 42,
    FillByte = 0xAB,
    RoundtripDataLen = 512
};

static void testGameListEntryLayout(void) {
    ASSERT_UINT_EQ(sizeof(GameListEntry), (size_t)ExpectedGameListEntrySize);
    ASSERT_UINT_EQ(offsetof(GameListEntry, gameId),
                   (size_t)GameListEntryGameIdOffset);
    ASSERT_UINT_EQ(offsetof(GameListEntry, fileSize),
                   (size_t)GameListEntryFileSizeOffset);
    ASSERT_UINT_EQ(offsetof(GameListEntry, name),
                   (size_t)GameListEntryNameOffset);
    ASSERT_UINT_EQ(offsetof(GameListEntry, version),
                   (size_t)GameListEntryVersionOffset);
    ASSERT_UINT_EQ(offsetof(GameListEntry, hash),
                   (size_t)GameListEntryHashOffset);
}

static void testGameDownloadReqLayout(void) {
    ASSERT_UINT_EQ(sizeof(GameDownloadReqPayload),
                   (size_t)ExpectedGameDownloadReqSize);
    ASSERT_UINT_EQ(offsetof(GameDownloadReqPayload, gameId),
                   (size_t)GameDownloadReqGameIdOffset);
    ASSERT_UINT_EQ(offsetof(GameDownloadReqPayload, resumeChunkIndex),
                   (size_t)GameDownloadReqResumeOffset);
    ASSERT_UINT_EQ(offsetof(GameDownloadReqPayload, platform),
                   (size_t)GameDownloadReqPlatformOffset);
}

static void testGameDownloadRespLayout(void) {
    ASSERT_UINT_EQ(sizeof(GameDownloadRespPayload),
                   (size_t)ExpectedGameDownloadRespSize);
    ASSERT_UINT_EQ(offsetof(GameDownloadRespPayload, status),
                   (size_t)GameDownloadRespStatusOffset);
    ASSERT_UINT_EQ(offsetof(GameDownloadRespPayload, gameId),
                   (size_t)GameDownloadRespGameIdOffset);
    ASSERT_UINT_EQ(offsetof(GameDownloadRespPayload, fileSize),
                   (size_t)GameDownloadRespFileSizeOffset);
    ASSERT_UINT_EQ(offsetof(GameDownloadRespPayload, totalChunks),
                   (size_t)GameDownloadRespTotalChunksOffset);
    ASSERT_UINT_EQ(offsetof(GameDownloadRespPayload, dataPort),
                   (size_t)GameDownloadRespDataPortOffset);
    ASSERT_UINT_EQ(offsetof(GameDownloadRespPayload, token),
                   (size_t)GameDownloadRespTokenOffset);
    ASSERT_UINT_EQ(offsetof(GameDownloadRespPayload, hash),
                   (size_t)GameDownloadRespHashOffset);
}

static void testGameChunkPayloadBaseSize(void) {
    ASSERT_UINT_EQ(offsetof(GameChunkPayload, data),
                   (size_t)ExpectedGameChunkBaseSize);
}

static void testDataAuthPayloadSize(void) {
    ASSERT_UINT_EQ(sizeof(DataAuthPayload),
                   (size_t)ExpectedDataAuthPayloadSize);
}

static void testGameMetadataPayloadLayout(void) {
    ASSERT_UINT_EQ(sizeof(GameMetadataPayload),
                   (size_t)ExpectedGameMetadataSize);
    ASSERT_UINT_EQ(offsetof(GameMetadataPayload, gameId),
                   (size_t)GameMetadataGameIdOffset);
    ASSERT_UINT_EQ(offsetof(GameMetadataPayload, fileSize),
                   (size_t)GameMetadataFileSizeOffset);
    ASSERT_UINT_EQ(offsetof(GameMetadataPayload, name),
                   (size_t)GameMetadataNameOffset);
    ASSERT_UINT_EQ(offsetof(GameMetadataPayload, version),
                   (size_t)GameMetadataVersionOffset);
    ASSERT_UINT_EQ(offsetof(GameMetadataPayload, hash),
                   (size_t)GameMetadataHashOffset);
    ASSERT_UINT_EQ(offsetof(GameMetadataPayload, platform),
                   (size_t)GameMetadataPlatformOffset);
}

static void testPacketInitDataNormal(void) {
    uint8_t *data = malloc(DATA_MAX_PAYLOAD_LEN);
    ASSERT_TRUE(data != NULL);
    memset(data, FillByte, DATA_MAX_PAYLOAD_LEN);

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;

    int ret = packetInitData(&pkt, MsgGameChunk, TestSeqID, PlaintextPacket,
                             data, DATA_MAX_PAYLOAD_LEN);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_UINT_EQ(pkt.header.magic, PACKET_MAGIC);
    ASSERT_INT_EQ((int)pkt.header.messageType, MsgGameChunk);
    ASSERT_UINT_EQ(pkt.header.payloadLength, DATA_MAX_PAYLOAD_LEN);
    ASSERT_UINT_EQ(pkt.header.sequenceID, TestSeqID);
    ASSERT_TRUE(pkt.payload != NULL);
    ASSERT_MEM_EQ(pkt.payload, data, DATA_MAX_PAYLOAD_LEN);

    packetClear(&pkt);
    free(data);
}

static void testPacketInitDataTooLarge(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;

    int ret = packetInitData(&pkt, MsgGameChunk, 0, PlaintextPacket, NULL,
                             (size_t)DATA_MAX_PAYLOAD_LEN + 1);
    ASSERT_INT_EQ(ret, PROTOCOL_FAIL);
}

static void testPacketInitDataNullPayload(void) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;

    enum { NonZeroLen = 100 };
    int ret = packetInitData(&pkt, MsgGameChunk, 0, PlaintextPacket, NULL,
                             NonZeroLen);
    ASSERT_INT_EQ(ret, PROTOCOL_FAIL);
}

static void testPacketSendEncryptedDataRoundtrip(void) {
    static const uint8_t testKey[AES_GCM_KEY_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    uint8_t data[RoundtripDataLen];
    memset(data, FillByte, sizeof(data));

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.payload = NULL;

    int ret = packetInitData(&pkt, MsgGameMetadata, TestSeqID, PlaintextPacket,
                             data, sizeof(data));
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESEncrypt(&pkt, (uint8_t *)testKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ((int)pkt.header.packetType, AES256GCMPacket);

    enum { SerBufSize = 2048 };
    uint8_t buf[SerBufSize];
    size_t serializedSize = 0;
    ret = packetSerialize(&pkt, buf, sizeof(buf), &serializedSize);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    packetClear(&pkt);

    Packet restored;
    memset(&restored, 0, sizeof(restored));
    restored.payload = NULL;
    ret = packetDeserialize(buf, serializedSize, &restored);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);

    ret = packetAESDecrypt(&restored, (uint8_t *)testKey);
    ASSERT_INT_EQ(ret, PROTOCOL_SUCC);
    ASSERT_INT_EQ((int)restored.header.packetType, PlaintextPacket);
    ASSERT_INT_EQ((int)restored.header.messageType, MsgGameMetadata);
    ASSERT_UINT_EQ(restored.header.sequenceID, TestSeqID);
    ASSERT_UINT_EQ(restored.header.payloadLength, sizeof(data));
    ASSERT_MEM_EQ(restored.payload, data, sizeof(data));

    packetClear(&restored);
}

static void testGameDownloadRespZeroFileSize(void) {
    GameDownloadRespPayload resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = 0;
    resp.totalChunks = 0;
    ASSERT_UINT_EQ(resp.totalChunks, 0u);
}

static void testGameChunkPayloadMaxChunkSize(void) {
    ASSERT_UINT_EQ(GAME_CHUNK_SIZE, 65536u);
    ASSERT_UINT_EQ(DATA_MAX_PAYLOAD_LEN, 65536u);
}

int main(void) {
    printf("test_game_protocol:\n");

    RUN_TEST(testGameListEntryLayout);
    RUN_TEST(testGameDownloadReqLayout);
    RUN_TEST(testGameDownloadRespLayout);
    RUN_TEST(testGameChunkPayloadBaseSize);
    RUN_TEST(testDataAuthPayloadSize);
    RUN_TEST(testGameMetadataPayloadLayout);
    RUN_TEST(testPacketInitDataNormal);
    RUN_TEST(testPacketInitDataTooLarge);
    RUN_TEST(testPacketInitDataNullPayload);
    RUN_TEST(testPacketSendEncryptedDataRoundtrip);
    RUN_TEST(testGameDownloadRespZeroFileSize);
    RUN_TEST(testGameChunkPayloadMaxChunkSize);

    return TEST_REPORT();
}
