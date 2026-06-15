/**
 * @file auth.c
 * @brief Server-side authentication handlers — implementation.
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
#include "auth.h"
#include "log.h"
#include "server/communication.h"
#include "server/database.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

enum {
    StatusSuccess = 0,
    StatusFailure = 1,
    LoginHeaderSize = offsetof(LoginRequestPayload, password),
    RegisterHeaderSize = offsetof(RegisterRequestPayload, password),
    MinLoginPayload = LoginHeaderSize + 1
};

int serverHandleLogin(Server *s, ClientSession *cs, const Packet *pkt) {
    if (pkt->header.payloadLength < MinLoginPayload) {
        LoginResponsePayload fr;
        memset(&fr, 0, sizeof(fr));
        serverSendEncryptedPacket(cs, MsgLoginResp, &fr, sizeof(fr));
        return SERVER_SUCC;
    }
    LoginRequestPayload *login = (LoginRequestPayload *)pkt->payload;
    if (login->username[LOGIN_USERNAME_LEN - 1] != '\0') {
        LoginResponsePayload fr;
        memset(&fr, 0, sizeof(fr));
        serverSendEncryptedPacket(cs, MsgLoginResp, &fr, sizeof(fr));
        return SERVER_SUCC;
    }
    size_t pwLen = pkt->header.payloadLength - LoginHeaderSize;
    if (memchr(login->password, '\0', pwLen) == NULL) {
        LoginResponsePayload fr;
        memset(&fr, 0, sizeof(fr));
        serverSendEncryptedPacket(cs, MsgLoginResp, &fr, sizeof(fr));
        return SERVER_SUCC;
    }
    User user;
    memset(&user, 0, sizeof(user));
    memcpy(user.username, login->username, USERNAME_MAX_LEN);
    user.password = strdup(login->password);
    if (!user.password) {
        LoginResponsePayload fr;
        memset(&fr, 0, sizeof(fr));
        serverSendEncryptedPacket(cs, MsgLoginResp, &fr, sizeof(fr));
        return SERVER_SUCC;
    }
    int dbRet = verifyUser(s->userDB, &user);
    OPENSSL_cleanse(user.password, strlen(user.password));
    free(user.password);
    if (dbRet != DB_SUCC) {
        LoginResponsePayload fr;
        memset(&fr, 0, sizeof(fr));
        serverSendEncryptedPacket(cs, MsgLoginResp, &fr, sizeof(fr));
        return SERVER_SUCC;
    }
    memcpy(cs->currentUser.username, user.username, USERNAME_MAX_LEN);
    memcpy(cs->currentUser.nickname, user.nickname, NICKNAME_MAX_LEN);
    cs->currentUser.uid = user.uid;
    cs->currentUser.password = NULL;
    if (user.totpSecret != NULL) {
        cs->currentUser.totpSecret = user.totpSecret;
        user.totpSecret = NULL;
        cs->state = SessionTOTPVerify;
        serverSendEncryptedPacket(cs, MsgTOTPVerifyReq, NULL, 0);
        return SERVER_SUCC;
    }
    cs->state = SessionRoom;
    LoginResponsePayload sr;
    memset(&sr, 0, sizeof(sr));
    sr.uid = user.uid;
    sr.totpEnabled = 0;
    memcpy(sr.username, user.username, LOGIN_USERNAME_LEN);
    memcpy(sr.nickname, user.nickname, LOGIN_NICKNAME_LEN);
    serverSendEncryptedPacket(cs, MsgLoginResp, &sr, sizeof(sr));
    return SERVER_SUCC;
}

int serverHandleRegister(Server *s, ClientSession *cs, const Packet *pkt) {
    enum { MinReg = RegisterHeaderSize + 1 };
    if (pkt->header.payloadLength < MinReg) {
        serverSendStatusResponse(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }
    RegisterRequestPayload *reg = (RegisterRequestPayload *)pkt->payload;
    if (reg->username[LOGIN_USERNAME_LEN - 1] != '\0' ||
        reg->nickname[LOGIN_NICKNAME_LEN - 1] != '\0') {
        serverSendStatusResponse(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }
    size_t pwLen = pkt->header.payloadLength - RegisterHeaderSize;
    if (memchr(reg->password, '\0', pwLen) == NULL) {
        serverSendStatusResponse(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }
    User user;
    memset(&user, 0, sizeof(user));
    memcpy(user.username, reg->username, USERNAME_MAX_LEN);
    memcpy(user.nickname, reg->nickname, NICKNAME_MAX_LEN);
    user.password = strdup(reg->password);
    if (!user.password) {
        serverSendStatusResponse(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }
    int dbRet = createUser(s->userDB, &user);
    OPENSSL_cleanse(user.password, strlen(user.password));
    free(user.password);
    if (dbRet != DB_SUCC) {
        serverSendStatusResponse(cs, MsgRegisterResp, StatusFailure);
        return SERVER_SUCC;
    }
    serverSendStatusResponse(cs, MsgRegisterResp, StatusSuccess);
    return SERVER_SUCC;
}

int serverHandleTOTPSetup(Server *s, ClientSession *cs) {
    enum { RawSecretLen = 20, Base32EncodedLen = 32 };
    (void)s;
    char *existing = getTOTPSecret(s->userDB, &cs->currentUser);
    if (existing) {
        free(existing);
        serverSendStatusResponse(cs, MsgTOTPSetupResp, StatusFailure);
        return SERVER_SUCC;
    }
    uint8_t raw[RawSecretLen];
    if (cryptoRandomBytes(raw, RawSecretLen) != CRYPTO_SUCC)
        return SERVER_FAIL;
    char *b32 = NULL;
    if (base32Encode(raw, RawSecretLen, &b32) != CRYPTO_SUCC) {
        OPENSSL_cleanse(raw, sizeof(raw));
        return SERVER_FAIL;
    }
    OPENSSL_cleanse(raw, sizeof(raw));
    if (setTOTPSecret(s->userDB, &cs->currentUser, b32) != DB_SUCC) {
        OPENSSL_cleanse(b32, Base32EncodedLen);
        free(b32);
        return SERVER_FAIL;
    }
    TOTPSetupRespPayload resp;
    memset(&resp, 0, sizeof(resp));
    memcpy(resp.secret, b32, Base32EncodedLen);
    int ret =
        serverSendEncryptedPacket(cs, MsgTOTPSetupResp, &resp, sizeof(resp));
    OPENSSL_cleanse(b32, Base32EncodedLen);
    free(b32);
    return ret;
}

int serverHandleTOTPVerify(Server *s, ClientSession *cs, const Packet *pkt) {
    enum { MinCode = 0, MaxCode = 999999 };
    (void)s;
    if (pkt->header.payloadLength < sizeof(TOTPVerifyPayload))
        return SERVER_FAIL;
    TOTPVerifyPayload *vp = (TOTPVerifyPayload *)pkt->payload;
    int code = (int)vp->code;
    if (vp->code < MinCode || vp->code > MaxCode)
        return SERVER_FAIL;
    int vr = verifyTOTPCode(cs->currentUser.totpSecret, &code);
    OPENSSL_cleanse(cs->currentUser.totpSecret,
                    strlen(cs->currentUser.totpSecret));
    free(cs->currentUser.totpSecret);
    cs->currentUser.totpSecret = NULL;
    if (vr != CRYPTO_SUCC) {
        LoginResponsePayload fr;
        memset(&fr, 0, sizeof(fr));
        serverSendEncryptedPacket(cs, MsgLoginResp, &fr, sizeof(fr));
        cs->state = SessionLogin;
        return SERVER_SUCC;
    }
    cs->state = SessionRoom;
    LoginResponsePayload sr;
    memset(&sr, 0, sizeof(sr));
    sr.uid = cs->currentUser.uid;
    sr.totpEnabled = 1;
    memcpy(sr.username, cs->currentUser.username, LOGIN_USERNAME_LEN);
    memcpy(sr.nickname, cs->currentUser.nickname, LOGIN_NICKNAME_LEN);
    serverSendEncryptedPacket(cs, MsgLoginResp, &sr, sizeof(sr));
    return SERVER_SUCC;
}

int serverHandleDBKeyReq(Server *s, ClientSession *cs) {
    (void)s;
    uint8_t outKey[DB_ENC_KEY_LEN];
    if (getCDBKey(s->userDB, cs->currentUser.uid, outKey) != DB_SUCC)
        return SERVER_FAIL;
    serverSendEncryptedPacket(cs, MsgDBKeyResp, outKey, DB_ENC_KEY_LEN);
    OPENSSL_cleanse(outKey, sizeof(outKey));
    return SERVER_SUCC;
}
