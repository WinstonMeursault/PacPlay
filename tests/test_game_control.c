#include "test_utils.h"

#include "cJSON.h"
#include "crypto.h"
#include "platform.h"
#include "server/gameControl.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum {
    Sha256DigestLen = 32,
    Sha256HexLen = 64,
    HexCharCount = 2,
    NibbleShift = 4,
    NibbleMask = 0x0F,
    NonceLen = 12,
    TagLen = 16,
    KeyLen = 32,
    DekEnvelopeSize = 60,
    PathBufSize = 512,
    HashBufSize = 65,
    TestContentLen = 5,
    EncryptTestDataLen = 128,
    OversizedNameLen = 5000,
    TraversalFileNameMaxLen = 64
};

static const char *hexDigitsTable = "0123456789abcdef";

static int testComputeFileSHA256(const char *filePath,
                                 char outHex[HashBufSize]) {
    FILE *fp = fopen(filePath, "rb");
    if (fp == NULL) {
        return GAME_CONTROL_FAIL;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }

    enum { ReadBufSize = 4096 };
    uint8_t buf[ReadBufSize];
    size_t bytesRead;
    while ((bytesRead = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, bytesRead) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            return GAME_CONTROL_FAIL;
        }
    }
    fclose(fp);

    uint8_t digest[Sha256DigestLen];
    unsigned int digestLen = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1) {
        EVP_MD_CTX_free(ctx);
        return GAME_CONTROL_FAIL;
    }
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < digestLen; i++) {
        outHex[i * HexCharCount] =
            hexDigitsTable[(digest[i] >> NibbleShift) & NibbleMask];
        outHex[i * HexCharCount + 1] = hexDigitsTable[digest[i] & NibbleMask];
    }
    outHex[Sha256HexLen] = '\0';

    return GAME_CONTROL_SUCC;
}

static int testParseMetadata(const char *jsonPath, char **outName,
                             char **outVersion, cJSON **outPlatforms) {
    if (jsonPath == NULL || outName == NULL || outVersion == NULL ||
        outPlatforms == NULL) {
        return GAME_CONTROL_FAIL;
    }

    FILE *fp = fopen(jsonPath, "rb");
    if (fp == NULL) {
        return GAME_CONTROL_FAIL;
    }

    fseek(fp, 0, SEEK_END);
    long fileLen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileLen <= 0) {
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }

    char *content = (char *)malloc((size_t)fileLen + 1);
    if (content == NULL) {
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }

    if (fread(content, 1, (size_t)fileLen, fp) != (size_t)fileLen) {
        free(content);
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }
    content[fileLen] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(content);
    free(content);
    if (root == NULL) {
        return GAME_CONTROL_FAIL;
    }

    cJSON *nameItem = cJSON_GetObjectItem(root, "name");
    cJSON *versionItem = cJSON_GetObjectItem(root, "version");
    cJSON *platformsItem = cJSON_GetObjectItem(root, "platforms");

    char *nameStr = cJSON_GetStringValue(nameItem);
    char *versionStr = cJSON_GetStringValue(versionItem);

    if (nameStr == NULL || versionStr == NULL || platformsItem == NULL ||
        !cJSON_IsArray(platformsItem)) {
        cJSON_Delete(root);
        return GAME_CONTROL_FAIL;
    }

    *outName = strdup(nameStr);
    *outVersion = strdup(versionStr);
    if (*outName == NULL || *outVersion == NULL) {
        free(*outName);
        free(*outVersion);
        cJSON_Delete(root);
        return GAME_CONTROL_FAIL;
    }

    *outPlatforms = cJSON_DetachItemFromObject(root, "platforms");
    cJSON_Delete(root);
    return GAME_CONTROL_SUCC;
}

static void testComputeSha256KnownVector(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_sha256_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char filePath[PathBufSize];
    (void)snprintf(filePath, sizeof(filePath), "%s/hello.txt", tmpDir);

    FILE *fp = fopen(filePath, "wb");
    ASSERT_TRUE(fp != NULL);
    size_t written = fwrite("hello", 1, TestContentLen, fp);
    ASSERT_UINT_EQ(written, (size_t)TestContentLen);
    fclose(fp);

    char hashHex[HashBufSize];
    int ret = testComputeFileSHA256(filePath, hashHex);
    ASSERT_INT_EQ(ret, GAME_CONTROL_SUCC);

    ASSERT_STR_EQ(
        hashHex,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

    platformRmrf(tmpDir);
}

static void testEncryptDecryptRoundtrip(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_enc_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char srcPath[PathBufSize];
    (void)snprintf(srcPath, sizeof(srcPath), "%s/plain.bin", tmpDir);

    uint8_t originalData[EncryptTestDataLen];
    ASSERT_INT_EQ(cryptoRandomBytes(originalData, EncryptTestDataLen),
                  CRYPTO_SUCC);

    FILE *fp = fopen(srcPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(originalData, 1, sizeof(originalData), fp);
    fclose(fp);

    uint8_t key[KeyLen];
    ASSERT_INT_EQ(cryptoRandomBytes(key, KeyLen), CRYPTO_SUCC);

    AESGCMKey aesKey;
    memcpy(aesKey.key, key, AES_GCM_KEY_LEN);
    ASSERT_INT_EQ(cryptoRandomBytes(aesKey.nonce, AES_GCM_NONCE_LEN),
                  CRYPTO_SUCC);

    AESGCMBuffer plainBuf = {.data = originalData,
                             .capacity = sizeof(originalData),
                             .len = sizeof(originalData)};

    AESGCMCipher cipher;
    ASSERT_INT_EQ(aesGCMBufferInit(&cipher.buffer, sizeof(originalData)),
                  CRYPTO_SUCC);
    ASSERT_INT_EQ(encryptAESGCM(&plainBuf, NULL, &aesKey, &cipher),
                  CRYPTO_SUCC);

    char encPath[PathBufSize];
    (void)snprintf(encPath, sizeof(encPath), "%s/encrypted.bin", tmpDir);

    fp = fopen(encPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(aesKey.nonce, 1, AES_GCM_NONCE_LEN, fp);
    fwrite(cipher.buffer.data, 1, cipher.buffer.len, fp);
    fwrite(cipher.tag, 1, AES_GCM_TAG_LEN, fp);
    fclose(fp);

    ASSERT_TRUE(cipher.buffer.len > 0);
    ASSERT_TRUE(
        memcmp(cipher.buffer.data, originalData, sizeof(originalData)) != 0);

    fp = fopen(encPath, "rb");
    ASSERT_TRUE(fp != NULL);

    uint8_t readNonce[NonceLen];
    size_t nr = fread(readNonce, 1, NonceLen, fp);
    ASSERT_UINT_EQ(nr, (size_t)NonceLen);

    uint8_t readCiphertext[EncryptTestDataLen];
    nr = fread(readCiphertext, 1, sizeof(readCiphertext), fp);
    ASSERT_UINT_EQ(nr, (size_t)EncryptTestDataLen);

    uint8_t readTag[TagLen];
    nr = fread(readTag, 1, TagLen, fp);
    ASSERT_UINT_EQ(nr, (size_t)TagLen);
    fclose(fp);

    AESGCMKey decKey;
    memcpy(decKey.key, key, AES_GCM_KEY_LEN);
    memcpy(decKey.nonce, readNonce, AES_GCM_NONCE_LEN);

    AESGCMCipher decCipher;
    ASSERT_INT_EQ(aesGCMBufferInit(&decCipher.buffer, EncryptTestDataLen),
                  CRYPTO_SUCC);
    memcpy(decCipher.buffer.data, readCiphertext, EncryptTestDataLen);
    decCipher.buffer.len = EncryptTestDataLen;
    memcpy(decCipher.tag, readTag, TagLen);

    AESGCMBuffer decPlain;
    ASSERT_INT_EQ(aesGCMBufferInit(&decPlain, EncryptTestDataLen), CRYPTO_SUCC);

    int ret = decryptAESGCM(&decCipher, NULL, &decKey, &decPlain);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    ASSERT_UINT_EQ(decPlain.len, sizeof(originalData));
    ASSERT_MEM_EQ(decPlain.data, originalData, sizeof(originalData));

    aesGCMBufferDeinit(&cipher.buffer);
    aesGCMBufferDeinit(&decCipher.buffer);
    aesGCMBufferDeinit(&decPlain);
    platformRmrf(tmpDir);
}

static void testMetadataParseValid(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_meta_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    const char *validJson =
        "{\"name\":\"TestGame\",\"version\":\"1.0.0\","
        "\"platforms\":[{\"platform\":\"linux\",\"file\":\"game.tar.gz\","
        "\"hash\":\"abc123\"}]}";

    FILE *fp = fopen(metaPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(validJson, 1, strlen(validJson), fp);
    fclose(fp);

    char *name = NULL;
    char *version = NULL;
    cJSON *platforms = NULL;
    int ret = testParseMetadata(metaPath, &name, &version, &platforms);
    ASSERT_INT_EQ(ret, GAME_CONTROL_SUCC);
    ASSERT_NOT_NULL(name);
    ASSERT_NOT_NULL(version);
    ASSERT_NOT_NULL(platforms);

    ASSERT_STR_EQ(name, "TestGame");
    ASSERT_STR_EQ(version, "1.0.0");
    ASSERT_TRUE(cJSON_IsArray(platforms));
    ASSERT_INT_EQ(cJSON_GetArraySize(platforms), 1);

    cJSON *entry = cJSON_GetArrayItem(platforms, 0);
    ASSERT_NOT_NULL(entry);
    ASSERT_STR_EQ(cJSON_GetStringValue(cJSON_GetObjectItem(entry, "platform")),
                  "linux");
    ASSERT_STR_EQ(cJSON_GetStringValue(cJSON_GetObjectItem(entry, "file")),
                  "game.tar.gz");
    ASSERT_STR_EQ(cJSON_GetStringValue(cJSON_GetObjectItem(entry, "hash")),
                  "abc123");

    free(name);
    free(version);
    cJSON_Delete(platforms);
    platformRmrf(tmpDir);
}

static void testMetadataParseMissingName(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_meta_nn_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    const char *json =
        "{\"version\":\"1.0.0\","
        "\"platforms\":[{\"platform\":\"linux\",\"file\":\"g.tar.gz\","
        "\"hash\":\"abc\"}]}";

    FILE *fp = fopen(metaPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(json, 1, strlen(json), fp);
    fclose(fp);

    char *name = NULL;
    char *version = NULL;
    cJSON *platforms = NULL;
    int ret = testParseMetadata(metaPath, &name, &version, &platforms);
    ASSERT_INT_EQ(ret, GAME_CONTROL_FAIL);

    platformRmrf(tmpDir);
}

static void testMetadataParseMissingPlatforms(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_meta_np_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    const char *json = "{\"name\":\"TestGame\",\"version\":\"1.0.0\"}";

    FILE *fp = fopen(metaPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(json, 1, strlen(json), fp);
    fclose(fp);

    char *name = NULL;
    char *version = NULL;
    cJSON *platforms = NULL;
    int ret = testParseMetadata(metaPath, &name, &version, &platforms);
    ASSERT_INT_EQ(ret, GAME_CONTROL_FAIL);

    platformRmrf(tmpDir);
}

static void testDekEnvelopeEncryptDecrypt(void) {
    uint8_t dekKey[KeyLen];
    uint8_t plainKey[KeyLen];
    ASSERT_INT_EQ(cryptoRandomBytes(dekKey, KeyLen), CRYPTO_SUCC);
    ASSERT_INT_EQ(cryptoRandomBytes(plainKey, KeyLen), CRYPTO_SUCC);

    AESGCMKey encKey;
    memcpy(encKey.key, dekKey, AES_GCM_KEY_LEN);
    ASSERT_INT_EQ(cryptoRandomBytes(encKey.nonce, AES_GCM_NONCE_LEN),
                  CRYPTO_SUCC);

    AESGCMBuffer plainBuf = {
        .data = plainKey, .capacity = KeyLen, .len = KeyLen};

    AESGCMCipher cipher;
    ASSERT_INT_EQ(aesGCMBufferInit(&cipher.buffer, KeyLen), CRYPTO_SUCC);
    ASSERT_INT_EQ(encryptAESGCM(&plainBuf, NULL, &encKey, &cipher),
                  CRYPTO_SUCC);

    uint8_t envelope[DekEnvelopeSize];
    memcpy(envelope, encKey.nonce, NonceLen);
    memcpy(envelope + NonceLen, cipher.buffer.data, KeyLen);
    memcpy(envelope + NonceLen + KeyLen, cipher.tag, TagLen);
    aesGCMBufferDeinit(&cipher.buffer);

    AESGCMKey decKey;
    memcpy(decKey.key, dekKey, AES_GCM_KEY_LEN);
    memcpy(decKey.nonce, envelope, NonceLen);

    AESGCMCipher decCipher;
    ASSERT_INT_EQ(aesGCMBufferInit(&decCipher.buffer, KeyLen), CRYPTO_SUCC);
    memcpy(decCipher.buffer.data, envelope + NonceLen, KeyLen);
    decCipher.buffer.len = KeyLen;
    memcpy(decCipher.tag, envelope + NonceLen + KeyLen, TagLen);

    AESGCMBuffer decPlain;
    ASSERT_INT_EQ(aesGCMBufferInit(&decPlain, KeyLen), CRYPTO_SUCC);

    int ret = decryptAESGCM(&decCipher, NULL, &decKey, &decPlain);
    ASSERT_INT_EQ(ret, CRYPTO_SUCC);
    ASSERT_UINT_EQ(decPlain.len, (size_t)KeyLen);
    ASSERT_MEM_EQ(decPlain.data, plainKey, KeyLen);

    aesGCMBufferDeinit(&decCipher.buffer);
    aesGCMBufferDeinit(&decPlain);
}

static void testGamectlListNullArgs(void) {
    ASSERT_INT_EQ(gameCtlList(NULL, NULL), GAME_CONTROL_FAIL);

    Server fakeServer;
    memset(&fakeServer, 0, sizeof(fakeServer));
    ASSERT_INT_EQ(gameCtlList(&fakeServer, NULL), GAME_CONTROL_FAIL);
    ASSERT_INT_EQ(gameCtlList(NULL, (ControlScrollTextBox *)1),
                  GAME_CONTROL_FAIL);
}

static void testPathTraversalInMetadata(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_meta_pt_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    const char *json =
        "{\"name\":\"EvilGame\",\"version\":\"1.0.0\","
        "\"platforms\":[{\"platform\":\"linux\","
        "\"file\":\"../../../etc/passwd\",\"hash\":\"deadbeef\"}]}";

    FILE *fp = fopen(metaPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(json, 1, strlen(json), fp);
    fclose(fp);

    char *name = NULL;
    char *version = NULL;
    cJSON *platforms = NULL;
    int ret = testParseMetadata(metaPath, &name, &version, &platforms);
    ASSERT_INT_EQ(ret, GAME_CONTROL_SUCC);

    cJSON *entry = cJSON_GetArrayItem(platforms, 0);
    ASSERT_NOT_NULL(entry);
    char *fileStr = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "file"));
    ASSERT_NOT_NULL(fileStr);
    ASSERT_TRUE(strstr(fileStr, "..") != NULL);

    free(name);
    free(version);
    cJSON_Delete(platforms);
    platformRmrf(tmpDir);
}

static void testOversizedMetadata(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_meta_os_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    char *longName = (char *)malloc(OversizedNameLen + 1);
    ASSERT_NOT_NULL(longName);
    memset(longName, 'A', OversizedNameLen);
    longName[OversizedNameLen] = '\0';

    enum { JsonBufSize = 6000 };
    char *jsonBuf = (char *)malloc(JsonBufSize);
    ASSERT_NOT_NULL(jsonBuf);
    (void)snprintf(jsonBuf, JsonBufSize,
                   "{\"name\":\"%s\",\"version\":\"1.0.0\","
                   "\"platforms\":[{\"platform\":\"linux\","
                   "\"file\":\"game.bin\",\"hash\":\"abc\"}]}",
                   longName);

    FILE *fp = fopen(metaPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(jsonBuf, 1, strlen(jsonBuf), fp);
    fclose(fp);

    char *name = NULL;
    char *version = NULL;
    cJSON *platforms = NULL;
    int ret = testParseMetadata(metaPath, &name, &version, &platforms);
    ASSERT_INT_EQ(ret, GAME_CONTROL_SUCC);
    ASSERT_NOT_NULL(name);
    ASSERT_UINT_EQ(strlen(name), (size_t)OversizedNameLen);

    free(name);
    free(version);
    cJSON_Delete(platforms);
    free(longName);
    free(jsonBuf);
    platformRmrf(tmpDir);
}

static void testNullByteInName(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_meta_nb_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    const char *json =
        "{\"name\":\"test\\u0000evil\",\"version\":\"1.0.0\","
        "\"platforms\":[{\"platform\":\"linux\",\"file\":\"g.bin\","
        "\"hash\":\"abc\"}]}";

    FILE *fp = fopen(metaPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(json, 1, strlen(json), fp);
    fclose(fp);

    char *name = NULL;
    char *version = NULL;
    cJSON *platforms = NULL;
    int ret = testParseMetadata(metaPath, &name, &version, &platforms);

    if (ret == GAME_CONTROL_SUCC) {
        ASSERT_NOT_NULL(name);
        ASSERT_TRUE(strlen(name) <= strlen("test\\u0000evil"));
        free(name);
        free(version);
        cJSON_Delete(platforms);
    }

    platformRmrf(tmpDir);
}

static int testParseMetadataFull(const char *jsonPath, char **outName,
                                 char **outVersion, char **outDescription,
                                 cJSON **outPlatforms) {
    if (jsonPath == NULL || outName == NULL || outVersion == NULL ||
        outDescription == NULL || outPlatforms == NULL) {
        return GAME_CONTROL_FAIL;
    }

    FILE *fp = fopen(jsonPath, "rb");
    if (fp == NULL) {
        return GAME_CONTROL_FAIL;
    }

    fseek(fp, 0, SEEK_END);
    long fileLen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileLen <= 0) {
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }

    char *content = (char *)malloc((size_t)fileLen + 1);
    if (content == NULL) {
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }

    if (fread(content, 1, (size_t)fileLen, fp) != (size_t)fileLen) {
        free(content);
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }
    content[fileLen] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(content);
    free(content);
    if (root == NULL) {
        return GAME_CONTROL_FAIL;
    }

    cJSON *nameItem = cJSON_GetObjectItem(root, "name");
    cJSON *versionItem = cJSON_GetObjectItem(root, "version");
    cJSON *descItem = cJSON_GetObjectItem(root, "description");
    cJSON *platformsItem = cJSON_GetObjectItem(root, "platforms");

    char *nameStr = cJSON_GetStringValue(nameItem);
    char *versionStr = cJSON_GetStringValue(versionItem);

    if (nameStr == NULL || versionStr == NULL || platformsItem == NULL ||
        !cJSON_IsArray(platformsItem)) {
        cJSON_Delete(root);
        return GAME_CONTROL_FAIL;
    }

    *outName = strdup(nameStr);
    *outVersion = strdup(versionStr);
    char *descStr = cJSON_GetStringValue(descItem);
    *outDescription = strdup(descStr != NULL ? descStr : "");
    if (*outName == NULL || *outVersion == NULL || *outDescription == NULL) {
        free(*outName);
        free(*outVersion);
        free(*outDescription);
        cJSON_Delete(root);
        return GAME_CONTROL_FAIL;
    }

    *outPlatforms = cJSON_DetachItemFromObject(root, "platforms");
    cJSON_Delete(root);
    return GAME_CONTROL_SUCC;
}

static void testMetadataParseDescription(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_meta_desc_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    const char *json =
        "{\"name\":\"DescGame\",\"version\":\"2.0.0\","
        "\"description\":\"A very cool game\","
        "\"platforms\":[{\"platform\":\"linux\",\"file\":\"game.tar.gz\","
        "\"hash\":\"abc123\"}]}";

    FILE *fp = fopen(metaPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(json, 1, strlen(json), fp);
    fclose(fp);

    char *name = NULL;
    char *version = NULL;
    char *description = NULL;
    cJSON *platforms = NULL;
    int ret = testParseMetadataFull(metaPath, &name, &version, &description,
                                    &platforms);
    ASSERT_INT_EQ(ret, GAME_CONTROL_SUCC);
    ASSERT_NOT_NULL(description);
    ASSERT_STR_EQ(description, "A very cool game");
    ASSERT_STR_EQ(name, "DescGame");

    free(name);
    free(version);
    free(description);
    cJSON_Delete(platforms);
    platformRmrf(tmpDir);
}

static void testMetadataParseNoDescription(void) {
    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/test_meta_nd_XXXXXX");
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    const char *json =
        "{\"name\":\"NoDescGame\",\"version\":\"1.0.0\","
        "\"platforms\":[{\"platform\":\"linux\",\"file\":\"game.tar.gz\","
        "\"hash\":\"abc123\"}]}";

    FILE *fp = fopen(metaPath, "wb");
    ASSERT_TRUE(fp != NULL);
    fwrite(json, 1, strlen(json), fp);
    fclose(fp);

    char *name = NULL;
    char *version = NULL;
    char *description = NULL;
    cJSON *platforms = NULL;
    int ret = testParseMetadataFull(metaPath, &name, &version, &description,
                                    &platforms);
    ASSERT_INT_EQ(ret, GAME_CONTROL_SUCC);
    ASSERT_NOT_NULL(description);
    ASSERT_STR_EQ(description, "");

    free(name);
    free(version);
    free(description);
    cJSON_Delete(platforms);
    platformRmrf(tmpDir);
}

int main(void) {
    printf("test_game_control:\n");

    RUN_TEST(testComputeSha256KnownVector);
    RUN_TEST(testEncryptDecryptRoundtrip);
    RUN_TEST(testMetadataParseValid);
    RUN_TEST(testMetadataParseMissingName);
    RUN_TEST(testMetadataParseMissingPlatforms);
    RUN_TEST(testDekEnvelopeEncryptDecrypt);
    RUN_TEST(testGamectlListNullArgs);
    RUN_TEST(testPathTraversalInMetadata);
    RUN_TEST(testOversizedMetadata);
    RUN_TEST(testNullByteInName);
    RUN_TEST(testMetadataParseDescription);
    RUN_TEST(testMetadataParseNoDescription);

    return TEST_REPORT();
}
