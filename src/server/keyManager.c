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
        return SERVER_FAIL;
    }
    AESGCMBuffer pt = {(uint8_t *)keyData, AES_GCM_KEY_LEN, AES_GCM_KEY_LEN};
    AESGCMCipher ct;
    if (aesGCMBufferInit(&ct.buffer, AES_GCM_KEY_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("encryptAndStoreKey: buffer init failed for %s", keyName);
        return SERVER_FAIL;
    }
    if (encryptAESGCM(&pt, NULL, &encKey, &ct) != CRYPTO_SUCC) {
        LOG_ERROR("encryptAndStoreKey: encryption failed for %s", keyName);
        aesGCMBufferDeinit(&ct.buffer);
        return SERVER_FAIL;
    }
    uint8_t envelope[EncEnvelopeLen];
    memcpy(envelope, encKey.nonce, AES_GCM_NONCE_LEN);
    memcpy(envelope + AES_GCM_NONCE_LEN, ct.buffer.data, AES_GCM_KEY_LEN);
    memcpy(envelope + AES_GCM_NONCE_LEN + AES_GCM_KEY_LEN, ct.tag,
           AES_GCM_TAG_LEN);
    aesGCMBufferDeinit(&ct.buffer);
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
        return SERVER_FAIL;
    }
    int dr = decryptAESGCM(&ct, NULL, &decKey, &pt);
    if (dr == CRYPTO_AUTH_FAIL) {
        LOG_ERROR("decryptAndLoadKey: Master Key is incorrect (%s)", keyName);
        aesGCMBufferDeinit(&pt);
        return SERVER_FAIL;
    }
    if (dr != CRYPTO_SUCC) {
        LOG_ERROR("decryptAndLoadKey: decryption failed for %s", keyName);
        aesGCMBufferDeinit(&pt);
        return SERVER_FAIL;
    }
    memcpy(outKey, pt.data, AES_GCM_KEY_LEN);
    aesGCMBufferDeinit(&pt);
    return SERVER_SUCC;
}

int serverInitKeys(Server *s) {
    uint8_t *dekEnc = NULL;
    size_t dekLen = 0;
    if (getServerKey(s->serverDB, "DEK", &dekEnc, &dekLen) != DB_SUCC)
        return SERVER_FAIL;
    if (dekEnc != NULL) {
        uint8_t *userDbEnc = NULL, *chatDbEnc = NULL, *gameDbEnc = NULL;
        size_t uLen = 0, cLen = 0, gLen = 0;
        if (getServerKey(s->serverDB, "UserDBKey", &userDbEnc, &uLen) !=
                DB_SUCC ||
            getServerKey(s->serverDB, "ChatHistoryDBKey", &chatDbEnc, &cLen) !=
                DB_SUCC ||
            getServerKey(s->serverDB, "GameDBKey", &gameDbEnc, &gLen) !=
                DB_SUCC) {
            free(dekEnc);
            free(userDbEnc);
            free(chatDbEnc);
            free(gameDbEnc);
            return SERVER_FAIL;
        }
        if (!userDbEnc) {
            LOG_ERROR("Missing key: UserDBKey");
            free(dekEnc);
            return SERVER_FAIL;
        }
        if (!chatDbEnc) {
            LOG_ERROR("Missing key: ChatHistoryDBKey");
            free(dekEnc);
            free(userDbEnc);
            return SERVER_FAIL;
        }
        if (!gameDbEnc) {
            LOG_ERROR("Missing key: GameDBKey");
            free(dekEnc);
            free(userDbEnc);
            free(chatDbEnc);
            return SERVER_FAIL;
        }
        char hexBuf[MkHexLen + 1];
        printf("Enter Master Key: ");
        fflush(stdout);
        if (readPasswordMasked(hexBuf, sizeof(hexBuf)) == 0) {
            LOG_ERROR("serverInitKeys: failed to read Master Key");
            free(dekEnc);
            free(userDbEnc);
            free(chatDbEnc);
            free(gameDbEnc);
            return SERVER_FAIL;
        }
        printf("\n");
        uint8_t mkKey[AES256KeyLen];
        for (size_t i = 0; i < AES256KeyLen; i++) {
            int hv = hexCharToNibble(hexBuf[i * 2]),
                lv = hexCharToNibble(hexBuf[i * 2 + 1]);
            if (hv < 0 || lv < 0) {
                LOG_ERROR("serverInitKeys: invalid hex char in Master Key");
                OPENSSL_cleanse(hexBuf, sizeof(hexBuf));
                free(dekEnc);
                free(userDbEnc);
                free(chatDbEnc);
                free(gameDbEnc);
                return SERVER_FAIL;
            }
            mkKey[i] = (uint8_t)((hv << 4) | lv);
        }
        OPENSSL_cleanse(hexBuf, sizeof(hexBuf));
        if (decryptAndLoadKey(mkKey, dekEnc, dekLen, "DEK", s->dekKey) !=
                SERVER_SUCC ||
            decryptAndLoadKey(mkKey, userDbEnc, uLen, "UserDBKey",
                              s->userDbEncKey) != SERVER_SUCC ||
            decryptAndLoadKey(mkKey, chatDbEnc, cLen, "ChatHistoryDBKey",
                              s->chatDbEncKey) != SERVER_SUCC ||
            decryptAndLoadKey(mkKey, gameDbEnc, gLen, "GameDBKey",
                              s->gameDbEncKey) != SERVER_SUCC) {
            OPENSSL_cleanse(mkKey, sizeof(mkKey));
            free(dekEnc);
            free(userDbEnc);
            free(chatDbEnc);
            free(gameDbEnc);
            return SERVER_FAIL;
        }
        OPENSSL_cleanse(mkKey, sizeof(mkKey));
        free(dekEnc);
        free(userDbEnc);
        free(chatDbEnc);
        free(gameDbEnc);
        s->freshKeysGenerated = false;
        return SERVER_SUCC;
    }
    free(dekEnc);
    LOG_INFO("serverInitKeys: generating fresh server keys");
    uint8_t mkKey[AES256KeyLen], dekKey[AES256KeyLen],
        userDbKey[DB_ENC_KEY_LEN], chatDbKey[DB_ENC_KEY_LEN],
        gameDbKey[DB_ENC_KEY_LEN];
    if (cryptoRandomBytes(mkKey, AES256KeyLen) != CRYPTO_SUCC ||
        cryptoRandomBytes(dekKey, AES256KeyLen) != CRYPTO_SUCC ||
        cryptoRandomBytes(userDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC ||
        cryptoRandomBytes(chatDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC ||
        cryptoRandomBytes(gameDbKey, DB_ENC_KEY_LEN) != CRYPTO_SUCC) {
        LOG_ERROR("serverInitKeys: cryptoRandomBytes failed");
        return SERVER_FAIL;
    }
    if (encryptAndStoreKey(mkKey, dekKey, "DEK", s->serverDB) != SERVER_SUCC ||
        encryptAndStoreKey(mkKey, userDbKey, "UserDBKey", s->serverDB) !=
            SERVER_SUCC ||
        encryptAndStoreKey(mkKey, chatDbKey, "ChatHistoryDBKey", s->serverDB) !=
            SERVER_SUCC ||
        encryptAndStoreKey(mkKey, gameDbKey, "GameDBKey", s->serverDB) !=
            SERVER_SUCC) {
        OPENSSL_cleanse(mkKey, sizeof(mkKey));
        OPENSSL_cleanse(dekKey, sizeof(dekKey));
        OPENSSL_cleanse(userDbKey, sizeof(userDbKey));
        OPENSSL_cleanse(chatDbKey, sizeof(chatDbKey));
        OPENSSL_cleanse(gameDbKey, sizeof(gameDbKey));
        return SERVER_FAIL;
    }
    memcpy(s->dekKey, dekKey, AES256KeyLen);
    memcpy(s->userDbEncKey, userDbKey, DB_ENC_KEY_LEN);
    memcpy(s->chatDbEncKey, chatDbKey, DB_ENC_KEY_LEN);
    memcpy(s->gameDbEncKey, gameDbKey, DB_ENC_KEY_LEN);
    OPENSSL_cleanse(dekKey, sizeof(dekKey));
    OPENSSL_cleanse(userDbKey, sizeof(userDbKey));
    OPENSSL_cleanse(chatDbKey, sizeof(chatDbKey));
    OPENSSL_cleanse(gameDbKey, sizeof(gameDbKey));
    printf("\n========================================\n");
    printf("  Master Key (SAVE THIS — shown only once):\n  ");
    for (int i = 0; i < AES256KeyLen; i++)
        printf("%02x", mkKey[i]);
    printf("\n========================================\n");
    printf("Press Enter after you have saved the key...");
    (void)getchar();
    printf("\033[2J\033[H");
    fflush(stdout);
    OPENSSL_cleanse(mkKey, sizeof(mkKey));
    LOG_INFO("serverInitKeys: key initialization complete");
    s->freshKeysGenerated = true;
    return SERVER_SUCC;
}
