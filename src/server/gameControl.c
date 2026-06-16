#include "gameControl.h"
#include "cJSON.h"
#include "crypto.h"
#include "database.h"
#include "log.h"
#include "microtar.h"
#include "platform.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#ifndef WITH_GZFILEOP
#define WITH_GZFILEOP
#endif
#include <zlib-ng.h>

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

static int extractTarGz(const char *tarGzPath, const char *destDir) {
    if (tarGzPath == NULL || destDir == NULL) {
        return GAME_CONTROL_FAIL;
    }

    gzFile gz = zng_gzopen(tarGzPath, "rb");
    if (gz == NULL) {
        return GAME_CONTROL_FAIL;
    }

    char tarPath[PathBufSize];
    (void)snprintf(tarPath, sizeof(tarPath), "%s/temp.tar", destDir);

    FILE *tarFile = fopen(tarPath, "wb");
    if (tarFile == NULL) {
        zng_gzclose(gz);
        return GAME_CONTROL_FAIL;
    }

    uint8_t buf[GzBufSize];
    int32_t bytesRead;
    while ((bytesRead = zng_gzread(gz, buf, sizeof(buf))) > 0) {
        if (fwrite(buf, 1, (size_t)bytesRead, tarFile) != (size_t)bytesRead) {
            fclose(tarFile);
            zng_gzclose(gz);
            remove(tarPath);
            return GAME_CONTROL_FAIL;
        }
    }
    fclose(tarFile);
    zng_gzclose(gz);

    mtar_t tar;
    if (mtar_open(&tar, tarPath, "r") != MTAR_ESUCCESS) {
        remove(tarPath);
        return GAME_CONTROL_FAIL;
    }

    mtar_header_t header;
    while (mtar_read_header(&tar, &header) == MTAR_ESUCCESS) {
        if (header.type == MTAR_TDIR) {
            char dirPath[PathBufSize];
            (void)snprintf(dirPath, sizeof(dirPath), "%s/%s", destDir,
                           header.name);
            platformMkdirp(dirPath);
        } else if (header.type == MTAR_TREG) {
            char filePath[PathBufSize];
            (void)snprintf(filePath, sizeof(filePath), "%s/%s", destDir,
                           header.name);

            void *data = malloc(header.size);
            if (data == NULL) {
                mtar_close(&tar);
                remove(tarPath);
                return GAME_CONTROL_FAIL;
            }

            if (mtar_read_data(&tar, data, header.size) != MTAR_ESUCCESS) {
                free(data);
                mtar_close(&tar);
                remove(tarPath);
                return GAME_CONTROL_FAIL;
            }

            FILE *outFile = fopen(filePath, "wb");
            if (outFile == NULL) {
                free(data);
                mtar_close(&tar);
                remove(tarPath);
                return GAME_CONTROL_FAIL;
            }
            fwrite(data, 1, header.size, outFile);
            fclose(outFile);
            free(data);
        }
        mtar_next(&tar);
    }

    mtar_close(&tar);
    remove(tarPath);
    return GAME_CONTROL_SUCC;
}

static int parseMetadata(const char *jsonPath, char **outName,
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
        outHex[i * HexCharCount] = hexDigits[(digest[i] >> NibbleShift) & NibbleMask];
        outHex[i * HexCharCount + 1] = hexDigits[digest[i] & NibbleMask];
    }
    outHex[Sha256HexLen] = '\0';

    return GAME_CONTROL_SUCC;
}

static int encryptFileWithKey(const char *srcPath, const char *dstPath,
                              const uint8_t key[AES_GCM_KEY_LEN]) {
    if (srcPath == NULL || dstPath == NULL || key == NULL) {
        return GAME_CONTROL_FAIL;
    }

    FILE *fp = fopen(srcPath, "rb");
    if (fp == NULL) {
        return GAME_CONTROL_FAIL;
    }

    fseek(fp, 0, SEEK_END);
    long fileLen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileLen < 0) {
        fclose(fp);
        return GAME_CONTROL_FAIL;
    }

    uint8_t *plainData = NULL;
    size_t dataLen = (size_t)fileLen;
    if (dataLen > 0) {
        plainData = (uint8_t *)malloc(dataLen);
        if (plainData == NULL) {
            fclose(fp);
            return GAME_CONTROL_FAIL;
        }
        if (fread(plainData, 1, dataLen, fp) != dataLen) {
            free(plainData);
            fclose(fp);
            return GAME_CONTROL_FAIL;
        }
    }
    fclose(fp);

    AESGCMKey aesKey;
    memcpy(aesKey.key, key, AES_GCM_KEY_LEN);
    if (cryptoRandomBytes(aesKey.nonce, AES_GCM_NONCE_LEN) != CRYPTO_SUCC) {
        free(plainData);
        return GAME_CONTROL_FAIL;
    }

    AESGCMBuffer plainBuf = {.data = plainData, .capacity = dataLen, .len = dataLen};

    AESGCMCipher cipher;
    if (aesGCMBufferInit(&cipher.buffer, dataLen) != CRYPTO_SUCC) {
        free(plainData);
        return GAME_CONTROL_FAIL;
    }

    if (encryptAESGCM(&plainBuf, NULL, &aesKey, &cipher) != CRYPTO_SUCC) {
        aesGCMBufferDeinit(&cipher.buffer);
        free(plainData);
        return GAME_CONTROL_FAIL;
    }
    free(plainData);

    FILE *out = fopen(dstPath, "wb");
    if (out == NULL) {
        aesGCMBufferDeinit(&cipher.buffer);
        return GAME_CONTROL_FAIL;
    }

    fwrite(aesKey.nonce, 1, AES_GCM_NONCE_LEN, out);
    fwrite(cipher.buffer.data, 1, cipher.buffer.len, out);
    fwrite(cipher.tag, 1, AES_GCM_TAG_LEN, out);
    fclose(out);

    aesGCMBufferDeinit(&cipher.buffer);
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

    AESGCMBuffer plainBuf = {
        .data = (uint8_t *)(uintptr_t)plainKey, .capacity = KeyLen, .len = KeyLen};

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

static int dekEnvelopeDecrypt(const uint8_t *dekKey, const uint8_t *envelope,
                              size_t envLen, uint8_t *outKey) {
    if (dekKey == NULL || envelope == NULL || outKey == NULL) {
        return GAME_CONTROL_FAIL;
    }
    if (envLen != DekEnvelopeSize) {
        return GAME_CONTROL_FAIL;
    }

    AESGCMKey decKey;
    memcpy(decKey.key, dekKey, AES_GCM_KEY_LEN);
    memcpy(decKey.nonce, envelope, NonceLen);

    AESGCMCipher cipher;
    if (aesGCMBufferInit(&cipher.buffer, KeyLen) != CRYPTO_SUCC) {
        return GAME_CONTROL_FAIL;
    }
    memcpy(cipher.buffer.data, envelope + NonceLen, KeyLen);
    cipher.buffer.len = KeyLen;
    memcpy(cipher.tag, envelope + NonceLen + KeyLen, TagLen);

    AESGCMBuffer plainBuf;
    if (aesGCMBufferInit(&plainBuf, KeyLen) != CRYPTO_SUCC) {
        aesGCMBufferDeinit(&cipher.buffer);
        return GAME_CONTROL_FAIL;
    }

    int rc = decryptAESGCM(&cipher, NULL, &decKey, &plainBuf);
    aesGCMBufferDeinit(&cipher.buffer);

    if (rc != CRYPTO_SUCC) {
        aesGCMBufferDeinit(&plainBuf);
        return GAME_CONTROL_FAIL;
    }

    memcpy(outKey, plainBuf.data, KeyLen);
    aesGCMBufferDeinit(&plainBuf);
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
        (void)snprintf(line, sizeof(line), "%-4u  %-19s  %s\n",
                       games[i].gameId,
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
        controlScrollTextBoxAppend(outBox,
                                   "Error: cannot read file\n");
        return GAME_CONTROL_FAIL;
    }

    char tmpDir[PathBufSize];
    (void)snprintf(tmpDir, sizeof(tmpDir), "/tmp/pacplay_game_XXXXXX");
    if (platformMkdtemp(tmpDir, sizeof(tmpDir)) != PLATFORM_SUCC) {
        controlScrollTextBoxAppend(outBox, "Error: failed to create temp dir\n");
        return GAME_CONTROL_FAIL;
    }

    if (extractTarGz(tarGzPath, tmpDir) != GAME_CONTROL_SUCC) {
        controlScrollTextBoxAppend(outBox, "Error: extraction failed\n");
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }

    char metaPath[PathBufSize];
    (void)snprintf(metaPath, sizeof(metaPath), "%s/metadata.json", tmpDir);

    char *name = NULL;
    char *version = NULL;
    cJSON *platforms = NULL;
    if (parseMetadata(metaPath, &name, &version, &platforms) !=
        GAME_CONTROL_SUCC) {
        controlScrollTextBoxAppend(outBox, "Error: invalid metadata.json\n");
        platformRmrf(tmpDir);
        return GAME_CONTROL_FAIL;
    }

    int platCount = cJSON_GetArraySize(platforms);
    for (int i = 0; i < platCount; i++) {
        cJSON *entry = cJSON_GetArrayItem(platforms, i);
        cJSON *fileItem = cJSON_GetObjectItem(entry, "file");
        cJSON *hashItem = cJSON_GetObjectItem(entry, "hash");

        char *fileStr = cJSON_GetStringValue(fileItem);
        char *hashStr = cJSON_GetStringValue(hashItem);
        if (fileStr == NULL || hashStr == NULL) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: platform entry missing fields\n");
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }

        char srcFilePath[PathBufSize];
        (void)snprintf(srcFilePath, sizeof(srcFilePath), "%s/%s", tmpDir,
                       fileStr);

        if (access(srcFilePath, R_OK) != 0) {
            char errLine[LineBufSize];
            (void)snprintf(errLine, sizeof(errLine),
                           "Error: file '%s' not found in archive\n", fileStr);
            controlScrollTextBoxAppend(outBox, errLine);
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }

        char computedHash[Sha256HexLen + 1];
        if (computeFileSHA256(srcFilePath, computedHash) != GAME_CONTROL_SUCC) {
            controlScrollTextBoxAppend(outBox, "Error: hash computation failed\n");
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }

        if (strcmp(computedHash, hashStr) != 0) {
            char errLine[LineBufSize];
            (void)snprintf(errLine, sizeof(errLine),
                           "Error: hash mismatch for '%s'\n", fileStr);
            controlScrollTextBoxAppend(outBox, errLine);
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }
    }

    GameInfo existing;
    memset(&existing, 0, sizeof(existing));
    uint8_t gameKey[KeyLen];
    uint32_t gameId = 0;
    bool isNewGame = (getGameByName(s->gameDB, name, &existing) != DB_SUCC);

    if (isNewGame) {
        if (cryptoRandomBytes(gameKey, KeyLen) != CRYPTO_SUCC) {
            controlScrollTextBoxAppend(outBox, "Error: key generation failed\n");
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }

        uint8_t envelope[DekEnvelopeSize];
        size_t envLen = 0;
        if (dekEnvelopeEncrypt(s->dekKey, gameKey, envelope, &envLen) !=
            GAME_CONTROL_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: envelope encryption failed\n");
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }

        GameInfo newGame;
        memset(&newGame, 0, sizeof(newGame));
        newGame.name = name;
        newGame.version = version;

        if (registerGame(s->gameDB, &newGame, envelope, envLen) != DB_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: game registration failed\n");
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }
        gameId = newGame.gameId;
    } else {
        gameId = existing.gameId;

        uint8_t *envData = NULL;
        size_t envDataLen = 0;
        if (getGameEncKey(s->gameDB, gameId, &envData, &envDataLen) !=
            DB_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: failed to retrieve game key\n");
            gameInfoFree(&existing);
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }

        if (dekEnvelopeDecrypt(s->dekKey, envData, envDataLen, gameKey) !=
            GAME_CONTROL_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: key decryption failed\n");
            free(envData);
            gameInfoFree(&existing);
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }
        free(envData);

        if (updateGameVersion(s->gameDB, gameId, version) != DB_SUCC) {
            controlScrollTextBoxAppend(outBox,
                                       "Error: version update failed\n");
            gameInfoFree(&existing);
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }
        gameInfoFree(&existing);
    }

    for (int i = 0; i < platCount; i++) {
        cJSON *entry = cJSON_GetArrayItem(platforms, i);
        cJSON *platItem = cJSON_GetObjectItem(entry, "platform");
        cJSON *fileItem = cJSON_GetObjectItem(entry, "file");
        cJSON *hashItem = cJSON_GetObjectItem(entry, "hash");

        char *platStr = cJSON_GetStringValue(platItem);
        char *fileStr = cJSON_GetStringValue(fileItem);
        char *hashStr = cJSON_GetStringValue(hashItem);

        if (platStr == NULL || fileStr == NULL || hashStr == NULL) {
            continue;
        }

        char destDir[PathBufSize];
        (void)snprintf(destDir, sizeof(destDir), "%s/%u/%s", GAME_LIB_DIR,
                       gameId, version);
        platformMkdirp(destDir);

        char srcFilePath[PathBufSize];
        (void)snprintf(srcFilePath, sizeof(srcFilePath), "%s/%s", tmpDir,
                       fileStr);

        char dstFilePath[PathBufSize];
        (void)snprintf(dstFilePath, sizeof(dstFilePath), "%s/%s", destDir,
                       fileStr);

        if (encryptFileWithKey(srcFilePath, dstFilePath, gameKey) !=
            GAME_CONTROL_SUCC) {
            char errLine[LineBufSize];
            (void)snprintf(errLine, sizeof(errLine),
                           "Error: encryption failed for '%s'\n", fileStr);
            controlScrollTextBoxAppend(outBox, errLine);
            free(name);
            free(version);
            cJSON_Delete(platforms);
            platformRmrf(tmpDir);
            return GAME_CONTROL_FAIL;
        }

        uint64_t encFileSize = 0;
        platformFileSize(dstFilePath, &encFileSize);

        GamePlatformInfo platInfo;
        memset(&platInfo, 0, sizeof(platInfo));
        (void)snprintf(platInfo.platform, sizeof(platInfo.platform), "%s",
                       platStr);
        platInfo.fileName = fileStr;
        platInfo.hash = hashStr;
        platInfo.fileSize = encFileSize;

        if (registerGamePlatform(s->gameDB, gameId, &platInfo) != DB_SUCC) {
            char errLine[LineBufSize];
            (void)snprintf(errLine, sizeof(errLine),
                           "Warning: platform '%s' registration failed\n",
                           platStr);
            controlScrollTextBoxAppend(outBox, errLine);
        }
    }

    platformRmrf(tmpDir);

    char successLine[LineBufSize];
    (void)snprintf(successLine, sizeof(successLine),
                   "Game '%s' v%s (id=%u) %s successfully.\n", name, version,
                   gameId, isNewGame ? "registered" : "updated");
    controlScrollTextBoxAppend(outBox, successLine);

    free(name);
    free(version);
    cJSON_Delete(platforms);
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
        unsigned long gid =
            strtoul(gameEntry->d_name, &endPtr, 10); // NOLINT
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
            (void)snprintf(
                line, sizeof(line), "  %-10s  %s  (%lu bytes)\n",
                plats[i].platform,
                plats[i].fileName != NULL ? plats[i].fileName : "(null)",
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
