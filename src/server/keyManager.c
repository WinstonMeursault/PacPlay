/**
 * @file keyManager.c
 * @brief Server cryptographic key generation and envelope management —
 * implementation.
 *
 * @date 2026-06-07
 * @copyright GPLv3 License
 * @section LICENSE
 * PacPlay
 * Copyright (C) 2026 Winston Meursault & Kiraterin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */
#include "keyManager.h"
#include "log.h"
#include "server/database.h"
#include "utils.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    AES256KeyLen = 32,
    MkHexLen = AES256KeyLen * 2,
    EncEnvelopeLen = AES_GCM_NONCE_LEN + AES_GCM_KEY_LEN + AES_GCM_TAG_LEN
};

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int encryptAndStoreKey(const uint8_t *mkKey, const uint8_t *keyData,
                              const char *keyName, DB *serverDB) {
    AESGCMKey encKey;
    memcpy(encKey.key, mkKey, AES_GCM_KEY_LEN);
    if (cryptoRandomBytes(encKey.nonce, AES_GCM_NONCE_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("encryptAndStoreKey: nonce generation failed for %s",
                  keyName);
        OPENSSL_cleanse(&encKey, sizeof(encKey));
        return SERVER_FAIL;
    }
    AESGCMBuffer pt = {(uint8_t *)keyData, AES_GCM_KEY_LEN, AES_GCM_KEY_LEN};
    AESGCMCipher ct;
    if (aesGCMBufferInit(&ct.buffer, AES_GCM_KEY_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("encryptAndStoreKey: buffer init failed for %s", keyName);
        OPENSSL_cleanse(&encKey, sizeof(encKey));
        return SERVER_FAIL;
    }
    if (encryptAESGCM(&pt, NULL, &encKey, &ct) != CRYPTO_SUCC) {
        LOG_ERROR("encryptAndStoreKey: encryption failed for %s", keyName);
        aesGCMBufferDeinit(&ct.buffer);
        OPENSSL_cleanse(&encKey, sizeof(encKey));
        return SERVER_FAIL;
    }
    uint8_t envelope[EncEnvelopeLen];
    memcpy(envelope, encKey.nonce, AES_GCM_NONCE_LEN);
    memcpy(envelope + AES_GCM_NONCE_LEN, ct.buffer.data, AES_GCM_KEY_LEN);
    memcpy(envelope + AES_GCM_NONCE_LEN + AES_GCM_KEY_LEN, ct.tag,
           AES_GCM_TAG_LEN);
    aesGCMBufferDeinit(&ct.buffer);
    OPENSSL_cleanse(&encKey, sizeof(encKey));
    if (setServerKey(serverDB, keyName, envelope, sizeof(envelope)) !=
        DB_SUCC) {
        LOG_ERROR("encryptAndStoreKey: setServerKey failed for %s", keyName);
        return SERVER_FAIL;
    }
    return SERVER_SUCC;
}

static int decryptAndLoadKey(const uint8_t *mkKey, const uint8_t *blob,
                             size_t blobLen, const char *keyName,
                             uint8_t *outKey) {
    if (blobLen != EncEnvelopeLen) {
        LOG_ERROR("decryptAndLoadKey: corrupted %s blob (len=%zu, expected=%d)",
                  keyName, blobLen, EncEnvelopeLen);
        return SERVER_FAIL;
    }
    AESGCMKey decKey;
    memcpy(decKey.key, mkKey, AES_GCM_KEY_LEN);
    memcpy(decKey.nonce, blob, AES_GCM_NONCE_LEN);
    AESGCMCipher ct;
    ct.buffer.data = (uint8_t *)blob + AES_GCM_NONCE_LEN;
    ct.buffer.len = AES_GCM_KEY_LEN;
    ct.buffer.capacity = AES_GCM_KEY_LEN;
    memcpy(ct.tag, blob + AES_GCM_NONCE_LEN + AES_GCM_KEY_LEN, AES_GCM_TAG_LEN);
    AESGCMBuffer pt;
    if (aesGCMBufferInit(&pt, AES_GCM_KEY_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("decryptAndLoadKey: buffer init failed for %s", keyName);
        OPENSSL_cleanse(&decKey, sizeof(decKey));
        return SERVER_FAIL;
    }
    int dr = decryptAESGCM(&ct, NULL, &decKey, &pt);
    if (dr == CRYPTO_AUTH_FAIL) {
        LOG_ERROR("decryptAndLoadKey: Master Key is incorrect (%s)", keyName);
        aesGCMBufferDeinit(&pt);
        OPENSSL_cleanse(&decKey, sizeof(decKey));
        return SERVER_FAIL;
    }
    if (dr != CRYPTO_SUCC) {
        LOG_ERROR("decryptAndLoadKey: decryption failed for %s", keyName);
        aesGCMBufferDeinit(&pt);
        OPENSSL_cleanse(&decKey, sizeof(decKey));
        return SERVER_FAIL;
    }
    memcpy(outKey, pt.data, AES_GCM_KEY_LEN);
    aesGCMBufferDeinit(&pt);
    OPENSSL_cleanse(&decKey, sizeof(decKey));
    return SERVER_SUCC;
}

static int hexToBytes(const char *hex, uint8_t *out, size_t outLen) {
    size_t hexLen = strlen(hex);
    if (hexLen != outLen * 2) {
        return SERVER_FAIL;
    }
    for (size_t i = 0; i < outLen; i++) {
        int hv = hexCharToNibble(hex[i * 2]);
        int lv = hexCharToNibble(hex[i * 2 + 1]);
        if (hv < 0 || lv < 0) {
            return SERVER_FAIL;
        }
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    return SERVER_SUCC;
}

bool serverIsFirstRun(Server *s) {
    uint8_t *val = NULL;
    size_t valLen = 0;
    if (getServerKey(s->serverDB, "DEK", &val, &valLen) != DB_SUCC) {
        LOG_ERROR("serverIsFirstRun: getServerKey failed");
        return false;
    }
    bool isFirst = (val == NULL);
    free(val);
    return isFirst;
}

bool serverKeysAreComplete(Server *s) {
    const char *keyNames[] = {"DEK",    "UserDBKey",   "GameDBKey",
                               "GameRoomDBKey", "FriendDBKey",
                               "PrivateChatDBKey", "GroupDBKey"};
    enum { KeyCount = 7 };
    for (int i = 0; i < KeyCount; i++) {
        uint8_t *val = NULL;
        size_t valLen = 0;
        if (getServerKey(s->serverDB, keyNames[i], &val, &valLen) != DB_SUCC) {
            LOG_ERROR("serverKeysAreComplete: getServerKey failed for %s",
                      keyNames[i]);
            return false;
        }
        if (val == NULL) {
            LOG_ERROR("serverKeysAreComplete: missing key %s", keyNames[i]);
            return false;
        }
        free(val);
    }
    return true;
}

char *serverGenerateFreshKeys(Server *s) {
    LOG_INFO("serverGenerateFreshKeys: generating fresh server keys");
    uint8_t mkKey[AES256KeyLen], dekKey[AES256KeyLen],
        userDbKey[DB_ENC_KEY_LEN], gameDbKey[DB_ENC_KEY_LEN],
        gameRoomDbKey[DB_ENC_KEY_LEN],
        friendDbKey[DB_ENC_KEY_LEN], privateChatDbKey[DB_ENC_KEY_LEN],
        groupDbKey[DB_ENC_KEY_LEN];
    if (cryptoRandomBytes(mkKey, AES256KeyLen) != CRYPTO_SUCC ||
        cryptoRandomBytes(dekKey, AES256KeyLen) != CRYPTO_SUCC ||
        cryptoRandomBytes(userDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC ||
        cryptoRandomBytes(gameDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC ||
        cryptoRandomBytes(gameRoomDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC ||
        cryptoRandomBytes(friendDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC ||
        cryptoRandomBytes(privateChatDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC ||
        cryptoRandomBytes(groupDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("serverGenerateFreshKeys: cryptoRandomBytes failed");
        return NULL;
    }
    if (encryptAndStoreKey(mkKey, dekKey, "DEK", s->serverDB) != SERVER_SUCC ||
        encryptAndStoreKey(mkKey, userDbKey, "UserDBKey", s->serverDB) !=
            SERVER_SUCC ||
        encryptAndStoreKey(mkKey, gameDbKey, "GameDBKey", s->serverDB) !=
            SERVER_SUCC ||
        encryptAndStoreKey(mkKey, gameRoomDbKey, "GameRoomDBKey",
                           s->serverDB) != SERVER_SUCC ||
        encryptAndStoreKey(mkKey, friendDbKey, "FriendDBKey",
                           s->serverDB) != SERVER_SUCC ||
        encryptAndStoreKey(mkKey, privateChatDbKey, "PrivateChatDBKey",
                           s->serverDB) != SERVER_SUCC ||
        encryptAndStoreKey(mkKey, groupDbKey, "GroupDBKey",
                           s->serverDB) != SERVER_SUCC) {
        OPENSSL_cleanse(mkKey, sizeof(mkKey));
        OPENSSL_cleanse(dekKey, sizeof(dekKey));
        OPENSSL_cleanse(userDbKey, sizeof(userDbKey));
        OPENSSL_cleanse(gameDbKey, sizeof(gameDbKey));
        OPENSSL_cleanse(gameRoomDbKey, sizeof(gameRoomDbKey));
        OPENSSL_cleanse(friendDbKey, sizeof(friendDbKey));
        OPENSSL_cleanse(privateChatDbKey, sizeof(privateChatDbKey));
        OPENSSL_cleanse(groupDbKey, sizeof(groupDbKey));
        return NULL;
    }
    OPENSSL_cleanse(dekKey, sizeof(dekKey));
    OPENSSL_cleanse(userDbKey, sizeof(userDbKey));
    OPENSSL_cleanse(gameDbKey, sizeof(gameDbKey));
    OPENSSL_cleanse(gameRoomDbKey, sizeof(gameRoomDbKey));
    OPENSSL_cleanse(friendDbKey, sizeof(friendDbKey));
    OPENSSL_cleanse(privateChatDbKey, sizeof(privateChatDbKey));
    OPENSSL_cleanse(groupDbKey, sizeof(groupDbKey));

    char *hex = malloc((size_t)MkHexLen + 1);
    if (hex == NULL) {
        LOG_ERROR("serverGenerateFreshKeys: malloc failed for hex buffer");
        OPENSSL_cleanse(mkKey, sizeof(mkKey));
        return NULL;
    }
    for (int i = 0; i < AES256KeyLen; i++) {
        snprintf(hex + (size_t)i * 2, 3, "%02x", mkKey[i]);
    }
    hex[MkHexLen] = '\0';
    OPENSSL_cleanse(mkKey, sizeof(mkKey));
    s->freshKeysGenerated = true;
    LOG_INFO("serverGenerateFreshKeys: key initialization complete");
    return hex;
}

int serverUnlockWithMK(Server *s, const char *masterKeyHex) {
    uint8_t mkKey[AES256KeyLen];
    if (hexToBytes(masterKeyHex, mkKey, sizeof(mkKey)) != SERVER_SUCC) {
        LOG_ERROR("serverUnlockWithMK: invalid hex Master Key");
        return SERVER_FAIL;
    }

    uint8_t *dekEnc = NULL, *userDbEnc = NULL,
            *gameDbEnc = NULL, *gameRoomDbEnc = NULL,
            *friendDbEnc = NULL, *privateChatDbEnc = NULL, *groupDbEnc = NULL;
    size_t dekLen = 0, uLen = 0, gLen = 0, grLen = 0,
           frLen = 0, pcLen = 0, gpLen = 0;
    if (getServerKey(s->serverDB, "DEK", &dekEnc, &dekLen) != DB_SUCC ||
        getServerKey(s->serverDB, "UserDBKey", &userDbEnc, &uLen) != DB_SUCC ||
        getServerKey(s->serverDB, "GameDBKey", &gameDbEnc, &gLen) !=
            DB_SUCC ||
        getServerKey(s->serverDB, "GameRoomDBKey", &gameRoomDbEnc, &grLen) !=
            DB_SUCC ||
        getServerKey(s->serverDB, "FriendDBKey", &friendDbEnc, &frLen) !=
            DB_SUCC ||
        getServerKey(s->serverDB, "PrivateChatDBKey", &privateChatDbEnc,
                     &pcLen) != DB_SUCC ||
        getServerKey(s->serverDB, "GroupDBKey", &groupDbEnc, &gpLen) !=
            DB_SUCC) {
        OPENSSL_cleanse(mkKey, sizeof(mkKey));
        free(dekEnc);
        free(userDbEnc);
        free(gameDbEnc);
        free(gameRoomDbEnc);
        free(friendDbEnc);
        free(privateChatDbEnc);
        free(groupDbEnc);
        return SERVER_FAIL;
    }
    if (!dekEnc || !userDbEnc || !gameDbEnc ||
        !gameRoomDbEnc || !friendDbEnc || !privateChatDbEnc || !groupDbEnc) {
        LOG_ERROR("serverUnlockWithMK: missing one or more key envelopes");
        OPENSSL_cleanse(mkKey, sizeof(mkKey));
        free(dekEnc);
        free(userDbEnc);
        free(gameDbEnc);
        free(gameRoomDbEnc);
        free(friendDbEnc);
        free(privateChatDbEnc);
        free(groupDbEnc);
        return SERVER_FAIL;
    }

    int ret = SERVER_SUCC;
    if (decryptAndLoadKey(mkKey, dekEnc, dekLen, "DEK", s->dekKey) !=
            SERVER_SUCC ||
        decryptAndLoadKey(mkKey, userDbEnc, uLen, "UserDBKey",
                          s->userDbEncKey) != SERVER_SUCC ||
        decryptAndLoadKey(mkKey, gameDbEnc, gLen, "GameDBKey",
                          s->gameDbEncKey) != SERVER_SUCC ||
        decryptAndLoadKey(mkKey, gameRoomDbEnc, grLen, "GameRoomDBKey",
                           s->gameRoomDbEncKey) != SERVER_SUCC ||
        decryptAndLoadKey(mkKey, friendDbEnc, frLen, "FriendDBKey",
                           s->friendDbEncKey) != SERVER_SUCC ||
        decryptAndLoadKey(mkKey, privateChatDbEnc, pcLen, "PrivateChatDBKey",
                           s->privateChatDbEncKey) != SERVER_SUCC ||
        decryptAndLoadKey(mkKey, groupDbEnc, gpLen, "GroupDBKey",
                           s->groupDbEncKey) != SERVER_SUCC) {
        ret = SERVER_FAIL;
    }

    OPENSSL_cleanse(mkKey, sizeof(mkKey));
    free(dekEnc);
    free(userDbEnc);
    free(gameDbEnc);
    free(gameRoomDbEnc);
    free(friendDbEnc);
    free(privateChatDbEnc);
    free(groupDbEnc);

    if (ret == SERVER_SUCC) {
        LOG_INFO("serverUnlockWithMK: server unlocked successfully");
    }
    return ret;
}
