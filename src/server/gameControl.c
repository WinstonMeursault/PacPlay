#include "gameControl.h"
#include "archive.h"
#include "cJSON.h"
#include "crypto.h"
#include "database.h"
#include "log.h"
#include "platform.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#if defined(__linux__)
#define SERVER_DEFAULT_PLATFORM "linux"
#elif defined(_WIN32) || defined(_WIN64)
#define SERVER_DEFAULT_PLATFORM "windows"
#else
#define SERVER_DEFAULT_PLATFORM "unknown"
#endif

enum {
    GzBufSize = 65536,
    Sha256HexLen = 64,
    Sha256DigestLen = 32,
    DekEnvelopeSize = 60,
    NonceLen = 12,
    TagLen = 16,
    KeyLen = 32,
    PathBufSize = 512,
    LineBufSize = 256,
    NibbleShift = 4,
    NibbleMask = 0x0F,
    HexCharCount = 2
};

static const char *hexDigits = "0123456789abcdef";

static int parseMetadata(const char *jsonPath, char **outName,
                         char **outVersion, char **outDescription,
                         char **outServerArchive, cJSON **outServerPlatforms,
                         char **outClientArchive, cJSON **outClientPlatforms) {
    if (jsonPath == NULL || outName == NULL || outVersion == NULL ||
        outDescription == NULL || outServerArchive == NULL ||
        outServerPlatforms == NULL || outClientArchive == NULL ||
        outClientPlatforms == NULL) {
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

    cJSON *nameItem = cJSON_GetObjectItem(root, "gameName");
    cJSON *versionItem = cJSON_GetObjectItem(root, "version");
    cJSON *serverItem = cJSON_GetObjectItem(root, "server");
    cJSON *clientItem = cJSON_GetObjectItem(root, "client");

    char *nameStr = cJSON_GetStringValue(nameItem);
    char *versionStr = cJSON_GetStringValue(versionItem);

    if (nameStr == NULL || versionStr == NULL || serverItem == NULL ||
        !cJSON_IsObject(serverItem) || clientItem == NULL ||
        !cJSON_IsObject(clientItem)) {
        cJSON_Delete(root);
        return GAME_CONTROL_FAIL;
    }

    cJSON *descItem = cJSON_GetObjectItem(root, "description");
    char *descStr = cJSON_GetStringValue(descItem);

    cJSON *servArchiveItem = cJSON_GetObjectItem(serverItem, "archive");
    cJSON *cliArchiveItem = cJSON_GetObjectItem(clientItem, "archive");
    char *servArchiveStr = cJSON_GetStringValue(servArchiveItem);
    char *cliArchiveStr = cJSON_GetStringValue(cliArchiveItem);

    if (servArchiveStr == NULL || cliArchiveStr == NULL) {
        cJSON_Delete(root);
        return GAME_CONTROL_FAIL;
    }

    *outName = strdup(nameStr);
    *outVersion = strdup(versionStr);
    *outDescription = strdup(descStr != NULL ? descStr : "");
    *outServerArchive = strdup(servArchiveStr);
    *outClientArchive = strdup(cliArchiveStr);

    if (*outName == NULL || *outVersion == NULL || *outDescription == NULL ||
        *outServerArchive == NULL || *outClientArchive == NULL) {
        free(*outName);
        free(*outVersion);
        free(*outDescription);
        free(*outServerArchive);
        free(*outClientArchive);
        cJSON_Delete(root);
        return GAME_CONTROL_FAIL;
    }

    *outServerPlatforms = cJSON_DetachItemFromObject(serverItem, "server");
    if (*outServerPlatforms == NULL) {
        *outServerPlatforms = cJSON_CreateObject();
    } else {
        cJSON_Delete(*outServerPlatforms);
        *outServerPlatforms = cJSON_Duplicate(serverItem, 1);
    }
    // Re-read: we want the server object minus "archive"
    cJSON_Delete(*outServerPlatforms);
    *outServerPlatforms = cJSON_Duplicate(serverItem, 1);
    cJSON_DeleteItemFromObject(*outServerPlatforms, "archive");

    *outClientPlatforms = cJSON_Duplicate(clientItem, 1);
    cJSON_DeleteItemFromObject(*outClientPlatforms, "archive");

    cJSON_Delete(root);
    return GAME_CONTROL_SUCC;
}

static int computeFileSHA256(const char *filePath, char outHex[GAME_HASH_LEN]) {
    if (filePath == NULL || outHex == NULL) {
        return GAME_CONTROL_FAIL;
    }

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

    uint8_t buf[GzBufSize];
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
            hexDigits[(digest[i] >> NibbleShift) & NibbleMask];
        outHex[i * HexCharCount + 1] = hexDigits[digest[i] & NibbleMask];
    }
    outHex[Sha256HexLen] = '\0';

    return GAME_CONTROL_SUCC;
}

static int dekEnvelopeEncrypt(const uint8_t *dekKey, const uint8_t *plainKey,
                              uint8_t *outEnvelope, size_t *outLen) {
    if (dekKey == NULL || plainKey == NULL || outEnvelope == NULL ||
        outLen == NULL) {
        return GAME_CONTROL_FAIL;
    }

    AESGCMKey encKey;
    memcpy(encKey.key, dekKey, AES_GCM_KEY_LEN);
    if (cryptoRandomBytes(encKey.nonce, AES_GCM_NONCE_LEN) != CRYPTO_SUCC) {
        return GAME_CONTROL_FAIL;
    }

    AESGCMBuffer plainBuf = {.data = (uint8_t *)(uintptr_t)plainKey,
                             .capacity = KeyLen,
                             .len = KeyLen};

    AESGCMCipher cipher;
    if (aesGCMBufferInit(&cipher.buffer, KeyLen) != CRYPTO_SUCC) {
        return GAME_CONTROL_FAIL;
    }

    if (encryptAESGCM(&plainBuf, NULL, &encKey, &cipher) != CRYPTO_SUCC) {
        aesGCMBufferDeinit(&cipher.buffer);
        return GAME_CONTROL_FAIL;
    }

    memcpy(outEnvelope, encKey.nonce, NonceLen);
    memcpy(outEnvelope + NonceLen, cipher.buffer.data, KeyLen);
    memcpy(outEnvelope + NonceLen + KeyLen, cipher.tag, TagLen);
    *outLen = DekEnvelopeSize;

    aesGCMBufferDeinit(&cipher.buffer);
    return GAME_CONTROL_SUCC;
}

static void freeAll(char *name, char *version, char *description,
                    char *serverArchive, char *clientArchive,
                    cJSON *serverPlatforms, cJSON *clientPlatforms) {
    free(name);
    free(version);
    free(description);
    free(serverArchive);
    free(clientArchive);
    cJSON_Delete(serverPlatforms);
    cJSON_Delete(clientPlatforms);
}

static int storePlatformFiles(Server *s, uint32_t gameId, const char *version,
                               const char *tmpDir, cJSON *section,
                               const char *role,
                               const char *filterPlatform,
                               ControlScrollTextBox *outBox) {
    for (cJSON *platform = section->child; platform != NULL;
         platform = platform->next) {
        const char *platName = platform->string;
        cJSON *libItem = cJSON_GetObjectItem(platform, "libraryPath");
        char *libPath = cJSON_GetStringValue(libItem);

        if (platName == NULL || libPath == NULL) {
            continue;
        }

        if (filterPlatform != NULL && filterPlatform[0] != '\0' &&
            strcmp(platName, filterPlatform) != 0) {
            continue;
        }

        const char *fileName = strrchr(libPath, '/');
        if (fileName == NULL) {
            fileName = libPath;
        } else {
            fileName++;
        }

        char srcFilePath[PathBufSize];
        (void)snprintf(srcFilePath, sizeof(srcFilePath), "%s/%s", tmpDir,
                       libPath + 2);

        if (access(srcFilePath, R_OK) != 0) {
            char errLine[LineBufSize];
            (void)snprintf(errLine, sizeof(errLine),
                           "Error: file '%s' not found in archive\n", libPath);
            controlScrollTextBoxAppend(outBox, errLine);
            return GAME_CONTROL_FAIL;
        }

        char computedHash[Sha256HexLen + 1];
        if (computeFileSHA256(srcFilePath, computedHash) != GAME_CONTROL_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: hash computation failed\n");
            return GAME_CONTROL_FAIL;
        }

        char destDir[PathBufSize];
        (void)snprintf(destDir, sizeof(destDir), "%s/%u/%s/%s/%s",
                       GAME_LIB_DIR, gameId, version, role, platName);
        platformMkdirp(destDir);

        char dstFilePath[PathBufSize];
        (void)snprintf(dstFilePath, sizeof(dstFilePath), "%s/%s", destDir,
                       fileName);

        FILE *src = fopen(srcFilePath, "rb");
        if (src == NULL) {
            return GAME_CONTROL_FAIL;
        }
        FILE *dst = fopen(dstFilePath, "wb");
        if (dst == NULL) {
            fclose(src);
            return GAME_CONTROL_FAIL;
        }
        char buf[GzBufSize];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
            fwrite(buf, 1, n, dst);
        }
        fclose(src);
        fclose(dst);

        uint64_t fileSz = 0;
        platformFileSize(dstFilePath, &fileSz);

        GamePlatformInfo platInfo;
        memset(&platInfo, 0, sizeof(platInfo));
        (void)snprintf(platInfo.platform, sizeof(platInfo.platform), "%s",
                       platName);
        platInfo.fileName = strdup(fileName);
        platInfo.hash = strdup(computedHash);
        strncpy(platInfo.role, role, sizeof(platInfo.role) - 1);
        platInfo.fileSize = fileSz;

        if (platInfo.fileName == NULL || platInfo.hash == NULL) {
            gamePlatformInfoFree(&platInfo);
            return GAME_CONTROL_FAIL;
        }

        if (registerGamePlatform(s->gameDB, gameId, &platInfo) != DB_SUCC) {
            char errLine[LineBufSize];
            (void)snprintf(errLine, sizeof(errLine),
                           "Warning: platform '%s' registration failed\n",
                           platName);
            controlScrollTextBoxAppend(outBox, errLine);
        }
        gamePlatformInfoFree(&platInfo);
    }
    return GAME_CONTROL_SUCC;
}

static int storeClientDownloadArchive(Server *s, uint32_t gameId,
                                       const char *version,
                                       const char *tmpDir,
                                       cJSON *clientPlatforms,
                                       ControlScrollTextBox *outBox) {
    char dlTmpDir[PathBufSize];
    snprintf(dlTmpDir, sizeof(dlTmpDir), "/tmp/pacplay_dl_XXXXXX");
    if (platformMkdtemp(dlTmpDir, sizeof(dlTmpDir)) != PLATFORM_SUCC) {
        controlScrollTextBoxAppend(outBox,
                                    "Error: failed to create temp dir\n");
        return GAME_CONTROL_FAIL;
    }

    char metaSrc[PathBufSize];
    snprintf(metaSrc, sizeof(metaSrc), "%s/metadata.json", tmpDir);
    char metaDst[PathBufSize];
    snprintf(metaDst, sizeof(metaDst), "%s/metadata.json", dlTmpDir);

    FILE *metaIn = fopen(metaSrc, "rb");
    if (metaIn == NULL) {
        platformRmrf(dlTmpDir);
        controlScrollTextBoxAppend(outBox,
                                    "Error: metadata.json not found\n");
        return GAME_CONTROL_FAIL;
    }
    FILE *metaOut = fopen(metaDst, "wb");
    if (metaOut == NULL) {
        fclose(metaIn);
        platformRmrf(dlTmpDir);
        return GAME_CONTROL_FAIL;
    }
    char metaBuf[GzBufSize];
    size_t n;
    while ((n = fread(metaBuf, 1, sizeof(metaBuf), metaIn)) > 0) {
        fwrite(metaBuf, 1, n, metaOut);
    }
    fclose(metaIn);
    fclose(metaOut);

    for (cJSON *platform = clientPlatforms->child; platform != NULL;
         platform = platform->next) {
        const char *platName = platform->string;
        cJSON *libItem = cJSON_GetObjectItem(platform, "libraryPath");
        char *libPath = cJSON_GetStringValue(libItem);

        if (platName == NULL || libPath == NULL) {
            continue;
        }

        char srcFilePath[PathBufSize];
        snprintf(srcFilePath, sizeof(srcFilePath), "%s/%s", tmpDir,
                 libPath + 2);

        if (access(srcFilePath, R_OK) != 0) {
            char errLine[LineBufSize];
            snprintf(errLine, sizeof(errLine),
                     "Error: client file '%s' not found in archive\n", libPath);
            controlScrollTextBoxAppend(outBox, errLine);
            platformRmrf(dlTmpDir);
            return GAME_CONTROL_FAIL;
        }

        char platDir[PathBufSize];
        snprintf(platDir, sizeof(platDir), "%s/%s", dlTmpDir, platName);
        platformMkdirp(platDir);

        const char *fileName = strrchr(libPath, '/');
        if (fileName == NULL) {
            fileName = libPath;
        } else {
            fileName++;
        }

        char dstFilePath[PathBufSize];
        snprintf(dstFilePath, sizeof(dstFilePath), "%s/%s/%s", dlTmpDir,
                 platName, fileName);

        FILE *src = fopen(srcFilePath, "rb");
        if (src == NULL) {
            platformRmrf(dlTmpDir);
            return GAME_CONTROL_FAIL;
        }
        FILE *dst = fopen(dstFilePath, "wb");
        if (dst == NULL) {
            fclose(src);
            platformRmrf(dlTmpDir);
            return GAME_CONTROL_FAIL;
        }
        char cpyBuf[GzBufSize];
        size_t cpyN;
        while ((cpyN = fread(cpyBuf, 1, sizeof(cpyBuf), src)) > 0) {
            fwrite(cpyBuf, 1, cpyN, dst);
        }
        fclose(src);
        fclose(dst);
    }

    char destDir[PathBufSize];
    snprintf(destDir, sizeof(destDir), "%s/%u/%s", GAME_LIB_DIR, gameId,
             version);
    platformMkdirp(destDir);

    char destPath[PathBufSize];
    snprintf(destPath, sizeof(destPath), "%s/download.tar.gz", destDir);

    if (createTarGz(dlTmpDir, destPath) != ARCHIVE_SUCC) {
        platformRmrf(dlTmpDir);
        controlScrollTextBoxAppend(outBox,
                                    "Error: failed to create download archive\n");
        return GAME_CONTROL_FAIL;
    }
    platformRmrf(dlTmpDir);

    char computedHash[Sha256HexLen + 1];
    if (computeFileSHA256(destPath, computedHash) != GAME_CONTROL_SUCC) {
        controlScrollTextBoxAppend(outBox,
                                    "Error: hash computation failed\n");
        return GAME_CONTROL_FAIL;
    }

    uint64_t fileSz = 0;
    platformFileSize(destPath, &fileSz);

    for (cJSON *platform = clientPlatforms->child; platform != NULL;
         platform = platform->next) {
        const char *platName = platform->string;
        cJSON *libItem = cJSON_GetObjectItem(platform, "libraryPath");
        char *libPath = cJSON_GetStringValue(libItem);

        if (platName == NULL || libPath == NULL) {
            continue;
        }

        GamePlatformInfo platInfo;
        memset(&platInfo, 0, sizeof(platInfo));
        snprintf(platInfo.platform, sizeof(platInfo.platform), "%s", platName);
        platInfo.fileName = strdup("download.tar.gz");
        platInfo.hash = strdup(computedHash);
        strncpy(platInfo.role, "client", sizeof(platInfo.role) - 1);
        platInfo.fileSize = fileSz;

        if (platInfo.fileName == NULL || platInfo.hash == NULL) {
            gamePlatformInfoFree(&platInfo);
            return GAME_CONTROL_FAIL;
        }

        if (registerGamePlatform(s->gameDB, gameId, &platInfo) != DB_SUCC) {
            char errLine[LineBufSize];
            snprintf(errLine, sizeof(errLine),
                     "Warning: platform '%s' registration failed\n", platName);
            controlScrollTextBoxAppend(outBox, errLine);
        }
        gamePlatformInfoFree(&platInfo);
    }

    return GAME_CONTROL_SUCC;
}

int gameCtlList(Server *s, ControlScrollTextBox *outBox) {
    if (s == NULL || outBox == NULL) {
        return GAME_CONTROL_FAIL;
    }

    GameInfo *games = NULL;
    size_t count = 0;
    if (listRegisteredGames(s->gameDB, &games, &count) != DB_SUCC) {
        controlScrollTextBoxAppend(outBox, "Error: failed to query games\n");
        return GAME_CONTROL_FAIL;
    }

    if (count == 0) {
        controlScrollTextBoxAppend(outBox, "No games registered.\n");
        return GAME_CONTROL_SUCC;
    }

    controlScrollTextBoxAppend(outBox, "ID    Name                 Version\n");
    controlScrollTextBoxAppend(outBox, "----  -------------------  --------\n");

    char line[LineBufSize];
    for (size_t i = 0; i < count; i++) {
        (void)snprintf(line, sizeof(line), "%-4u  %-19s  %s\n", games[i].gameId,
                       games[i].name != NULL ? games[i].name : "(null)",
                       games[i].version != NULL ? games[i].version : "(null)");
        controlScrollTextBoxAppend(outBox, line);
    }

    gameInfoArrayFree(games, count);
    return GAME_CONTROL_SUCC;
}

int gameCtlUpdate(Server *s, const char *tarGzPath,
                  ControlScrollTextBox *outBox) {
    if (s == NULL || tarGzPath == NULL || outBox == NULL) {
        return GAME_CONTROL_FAIL;
    }

    if (access(tarGzPath, R_OK) != 0) {
        controlScrollTextBoxAppend(outBox, "Error: cannot read file\n");
        return GAME_CONTROL_FAIL;
    }

    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/pacplay_game_XXXXXX");
    if (platformMkdtemp(tmpDir, sizeof(tmpDir)) != PLATFORM_SUCC) {
        controlScrollTextBoxAppend(outBox,
                                   "Error: failed to create temp dir\n");
        return GAME_CONTROL_FAIL;
    }

    if (extractTarGz(tarGzPath, tmpDir) != ARCHIVE_SUCC) {
        controlScrollTextBoxAppend(outBox, "Error: extraction failed\n");
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    char *name = NULL;
    char *version = NULL;
    char *description = NULL;
    char *serverArchive = NULL;
    char *clientArchive = NULL;
    cJSON *serverPlatforms = NULL;
    cJSON *clientPlatforms = NULL;
    if (parseMetadata(metaPath, &name, &version, &description, &serverArchive,
                      &serverPlatforms, &clientArchive, &clientPlatforms) !=
        GAME_CONTROL_SUCC) {
        controlScrollTextBoxAppend(outBox, "Error: invalid metadata.json\n");
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }

    char serverArchivePath[PathBufSize];
    (void)snprintf(serverArchivePath, sizeof(serverArchivePath), "%s/%s",
                   tmpDir, serverArchive);
    if (access(serverArchivePath, R_OK) != 0) {
        controlScrollTextBoxAppend(outBox, "Error: server archive not found\n");
        free(name);
        free(version);
        free(description);
        free(serverArchive);
        free(clientArchive);
        cJSON_Delete(serverPlatforms);
        cJSON_Delete(clientPlatforms);
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }
    if (extractTarGz(serverArchivePath, tmpDir) != ARCHIVE_SUCC) {
        controlScrollTextBoxAppend(outBox,
                                    "Error: server archive extraction failed\n");
        free(name);
        free(version);
        free(description);
        free(serverArchive);
        free(clientArchive);
        cJSON_Delete(serverPlatforms);
        cJSON_Delete(clientPlatforms);
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }

    char clientArchivePath[PathBufSize];
    (void)snprintf(clientArchivePath, sizeof(clientArchivePath), "%s/%s",
                   tmpDir, clientArchive);
    if (access(clientArchivePath, R_OK) != 0) {
        controlScrollTextBoxAppend(outBox, "Error: client archive not found\n");
        free(name);
        free(version);
        free(description);
        free(serverArchive);
        free(clientArchive);
        cJSON_Delete(serverPlatforms);
        cJSON_Delete(clientPlatforms);
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }
    if (extractTarGz(clientArchivePath, tmpDir) != ARCHIVE_SUCC) {
        controlScrollTextBoxAppend(outBox,
                                    "Error: client archive extraction failed\n");
        free(name);
        free(version);
        free(description);
        free(serverArchive);
        free(clientArchive);
        cJSON_Delete(serverPlatforms);
        cJSON_Delete(clientPlatforms);
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }

    GameInfo existing;
    memset(&existing, 0, sizeof(existing));
    uint32_t gameId = 0;
    bool isNewGame = (getGameByName(s->gameDB, name, &existing) != DB_SUCC);

    if (isNewGame) {
        uint8_t envelope[DekEnvelopeSize];
        size_t envLen = 0;
        uint8_t gameKey[KeyLen];
        if (cryptoRandomBytes(gameKey, KeyLen) != CRYPTO_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: key generation failed\n");
            freeAll(name, version, description, serverArchive, clientArchive,
                    serverPlatforms, clientPlatforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }
        if (dekEnvelopeEncrypt(s->dekKey, gameKey, envelope, &envLen) !=
            GAME_CONTROL_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: envelope encryption failed\n");
            freeAll(name, version, description, serverArchive, clientArchive,
                    serverPlatforms, clientPlatforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }

        GameInfo newGame;
        memset(&newGame, 0, sizeof(newGame));
        newGame.name = name;
        newGame.version = version;
        newGame.description = description;

        if (registerGame(s->gameDB, &newGame, envelope, envLen) != DB_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: game registration failed\n");
            freeAll(name, version, description, serverArchive, clientArchive,
                    serverPlatforms, clientPlatforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }
        gameId = newGame.gameId;
    } else {
        gameId = existing.gameId;
        if (updateGameVersion(s->gameDB, gameId, version) != DB_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: version update failed\n");
            gameInfoFree(&existing);
            freeAll(name, version, description, serverArchive, clientArchive,
                    serverPlatforms, clientPlatforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }
        gameInfoFree(&existing);
    }

    if (storePlatformFiles(s, gameId, version, tmpDir, serverPlatforms, "server",
                           SERVER_DEFAULT_PLATFORM, outBox) != GAME_CONTROL_SUCC) {
        freeAll(name, version, description, serverArchive, clientArchive,
                serverPlatforms, clientPlatforms);
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }

    if (storeClientDownloadArchive(s, gameId, version, tmpDir,
                                    clientPlatforms,
                                    outBox) != GAME_CONTROL_SUCC) {
        freeAll(name, version, description, serverArchive, clientArchive,
                serverPlatforms, clientPlatforms);
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }

    platformRmrf(tmpDir);

    char successLine[LineBufSize];
    (void)snprintf(successLine, sizeof(successLine),
                   "Game '%s' v%s (id=%u) %s successfully.\n", name, version,
                   gameId, isNewGame ? "registered" : "updated");
    controlScrollTextBoxAppend(outBox, successLine);

    freeAll(name, version, description, serverArchive, clientArchive,
            serverPlatforms, clientPlatforms);
    return GAME_CONTROL_SUCC;
}

int gameCtlDelete(Server *s, uint32_t gameId, ControlScrollTextBox *outBox) {
    if (s == NULL || outBox == NULL) {
        return GAME_CONTROL_FAIL;
    }

    GameInfo info;
    memset(&info, 0, sizeof(info));
    if (getGameById(s->gameDB, gameId, &info) != DB_SUCC) {
        controlScrollTextBoxAppend(outBox, "Error: game not found\n");
        return GAME_CONTROL_FAIL;
    }

    char gameName[LineBufSize];
    (void)snprintf(gameName, sizeof(gameName), "%s",
                   info.name != NULL ? info.name : "(unknown)");
    gameInfoFree(&info);

    if (unregisterGame(s->gameDB, gameId) != DB_SUCC) {
        controlScrollTextBoxAppend(outBox,
                                   "Error: failed to unregister game\n");
        return GAME_CONTROL_FAIL;
    }

    char libDir[PathBufSize];
    (void)snprintf(libDir, sizeof(libDir), "%s/%u", GAME_LIB_DIR, gameId);
    platformRmrf(libDir);

    char line[LineBufSize];
    (void)snprintf(line, sizeof(line), "Game '%s' (id=%u) deleted.\n", gameName,
                   gameId);
    controlScrollTextBoxAppend(outBox, line);
    return GAME_CONTROL_SUCC;
}

int gameCtlScan(Server *s, ControlScrollTextBox *outBox) {
    if (s == NULL || outBox == NULL) {
        return GAME_CONTROL_FAIL;
    }

    DIR *libDir = opendir(GAME_LIB_DIR);
    if (libDir == NULL) {
        controlScrollTextBoxAppend(outBox, "No gameLib directory found.\n");
        return GAME_CONTROL_SUCC;
    }

    int totalFiles = 0;
    int orphanFiles = 0;
    struct dirent *gameEntry;

    while ((gameEntry = readdir(libDir)) != NULL) {
        if (gameEntry->d_name[0] == '.') {
            continue;
        }

        char *endPtr = NULL;
        unsigned long gid = strtoul(gameEntry->d_name, &endPtr, 10); // NOLINT
        if (endPtr == gameEntry->d_name || *endPtr != '\0') {
            continue;
        }

        GameInfo info;
        memset(&info, 0, sizeof(info));
        if (getGameById(s->gameDB, (uint32_t)gid, &info) != DB_SUCC) {
            char line[LineBufSize];
            (void)snprintf(line, sizeof(line),
                           "Orphan directory: %s/%s (no DB record)\n",
                           GAME_LIB_DIR, gameEntry->d_name);
            controlScrollTextBoxAppend(outBox, line);
            orphanFiles++;
        } else {
            gameInfoFree(&info);
            totalFiles++;
        }
    }
    closedir(libDir);

    char summary[LineBufSize];
    (void)snprintf(summary, sizeof(summary),
                   "Scan complete: %d valid, %d orphan entries.\n", totalFiles,
                   orphanFiles);
    controlScrollTextBoxAppend(outBox, summary);
    return GAME_CONTROL_SUCC;
}

int gameCtlInfo(Server *s, uint32_t gameId, ControlScrollTextBox *outBox) {
    if (s == NULL || outBox == NULL) {
        return GAME_CONTROL_FAIL;
    }

    GameInfo info;
    memset(&info, 0, sizeof(info));
    if (getGameById(s->gameDB, gameId, &info) != DB_SUCC) {
        controlScrollTextBoxAppend(outBox, "Error: game not found\n");
        return GAME_CONTROL_FAIL;
    }

    char line[LineBufSize];
    (void)snprintf(line, sizeof(line), "Game ID:  %u\n", info.gameId);
    controlScrollTextBoxAppend(outBox, line);
    (void)snprintf(line, sizeof(line), "Name:     %s\n",
                   info.name != NULL ? info.name : "(null)");
    controlScrollTextBoxAppend(outBox, line);
    (void)snprintf(line, sizeof(line), "Version:  %s\n",
                   info.version != NULL ? info.version : "(null)");
    controlScrollTextBoxAppend(outBox, line);

    GamePlatformInfo *plats = NULL;
    size_t platCount = 0;
    if (listGamePlatforms(s->gameDB, gameId, &plats, &platCount) == DB_SUCC &&
        platCount > 0) {
        controlScrollTextBoxAppend(outBox, "Platforms:\n");
        for (size_t i = 0; i < platCount; i++) {
            (void)snprintf(line, sizeof(line), "  [%s] %-10s  %s  (%lu bytes)\n",
                           plats[i].role[0] != '\0' ? plats[i].role : "?",
                           plats[i].platform,
                           plats[i].fileName != NULL ? plats[i].fileName
                                                     : "(null)",
                           (unsigned long)plats[i].fileSize);
            controlScrollTextBoxAppend(outBox, line);
        }
        gamePlatformInfoArrayFree(plats, platCount);
    } else {
        controlScrollTextBoxAppend(outBox, "No platform binaries.\n");
    }

    gameInfoFree(&info);
    return GAME_CONTROL_SUCC;
}
