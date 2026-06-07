/**
 * @file auth.c
 * @brief Client-side authentication module — login, registration, and TOTP
 *        setup implementation.
 *
 * Implements three user-facing flows:
 *  - clientLogin():     username/password → optional TOTP challenge →
 *                       CDBKey retrieval → encrypted local database init
 *  - clientRegister():  collect username/nickname/password → send to server
 *  - clientTOTPSetup(): request TOTP secret from server → display QR URI
 *
 * All functions return @c CLIENT_SUCC on success or @c CLIENT_FAIL on error
 * and are responsible for zeroing any sensitive material before returning.
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
#include "client/auth.h"
#include "client/communication.h"
#include "client/database.h"
#include "log.h"
#include "utils.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────── local constants ───────────────────────────── */

/**
 * @brief Maximum characters accepted from the user for password input.
 *
 * Chosen to be large enough for any reasonable passphrase while keeping the
 * stack buffer manageable.  Shared by login and registration.
 */
enum { MaxInputLen = 512 };

/**
 * @brief Byte offset of the flexible password field within each payload struct.
 *
 * Used to compute the variable-length payload size as
 * @c HeaderSize @c + @c strlen(password) @c + @c 1 (NUL terminator).
 */
enum {
    LoginHeaderSize = offsetof(LoginRequestPayload, password),
    RegisterHeaderSize = offsetof(RegisterRequestPayload, password)
};

int clientLogin(Client *client) {
    /* ────────────────────── stage 1: collect credentials
     * ────────────────────── */

    char username[LOGIN_USERNAME_LEN];
    char password[MaxInputLen];

    printf("Username: ");
    fflush(stdout);
    if (fgets(username, (int)sizeof(username), stdin) == NULL) {
        return CLIENT_FAIL;
    }
    username[strcspn(username, "\n")] = '\0';

    printf("Password: ");
    fflush(stdout);
    if (readPasswordMasked(password, sizeof(password)) == 0) {
        OPENSSL_cleanse(password, sizeof(password));
        return CLIENT_FAIL;
    }
    printf("\n");

    /* ──────── stage 2: validate lengths, build and send login request
     * ───────── */

    size_t usernameLen = strlen(username);
    size_t pwLen = strlen(password);

    if (usernameLen >= LOGIN_USERNAME_LEN) {
        LOG_ERROR("clientLogin: username too long (%zu >= %d)", usernameLen,
                  LOGIN_USERNAME_LEN);
        OPENSSL_cleanse(password, sizeof(password));
        return CLIENT_FAIL;
    }

    /* Build login payload — username(32) + password(FAM). No uid or
     * nickname; the server returns those on success. */
    size_t payloadLen = LoginHeaderSize + pwLen + 1;
    LoginRequestPayload *login = calloc(1, payloadLen);
    if (login == NULL) {
        OPENSSL_cleanse(password, sizeof(password));
        return CLIENT_FAIL;
    }

    memcpy(login->username, username, usernameLen + 1);
    memcpy(login->password, password, pwLen + 1);
    OPENSSL_cleanse(password, sizeof(password));

    if (clientSendEncryptedPacket(client, MsgLoginReq, login, payloadLen) !=
        CLIENT_SUCC) {
        OPENSSL_cleanse(login, payloadLen);
        free(login);
        return CLIENT_FAIL;
    }
    OPENSSL_cleanse(login, payloadLen);
    free(login);

    /* ──────── stage 3: wait for login response (may be TOTP challenge)
     * ──────── */

    Packet respPkt;
    memset(&respPkt, 0, sizeof(respPkt));
    if (clientRecvEncryptedPacket(client, &respPkt) != PROTOCOL_SUCC) {
        LOG_ERROR("clientLogin: no response from server");
        return CLIENT_FAIL;
    }

    if (respPkt.header.messageType == MsgTOTPVerifyReq) {
        /* ─────────────────── stage 3a: TOTP challenge sub-flow
         * ──────────────────── */
        packetClear(&respPkt);
        char codeBuf[TOTP_SETUP_SECRET_LEN];
        printf("TOTP code: ");
        fflush(stdout);
        if (fgets(codeBuf, (int)sizeof(codeBuf), stdin) == NULL) {
            return CLIENT_FAIL;
        }
        /* strtol returns 0 on parse failure, filtered by range check. */
        enum { DecBase = 10, MinCode = 0, MaxCode = 999999 };
        long codeVal = strtol(codeBuf, NULL, DecBase);
        if (codeVal < MinCode || codeVal > MaxCode) {
            printf("Invalid TOTP code.\n");
            return CLIENT_FAIL;
        }

        TOTPVerifyPayload tvp;
        tvp.code = (uint32_t)codeVal;
        if (clientSendEncryptedPacket(client, MsgTOTPVerifyResp, &tvp,
                                      sizeof(tvp)) != CLIENT_SUCC) {
            return CLIENT_FAIL;
        }

        /* ──────────────── stage 3b: wait for final login response
         * ───────────────── */
        memset(&respPkt, 0, sizeof(respPkt));
        if (clientRecvEncryptedPacket(client, &respPkt) != PROTOCOL_SUCC) {
            LOG_ERROR("clientLogin: no response after TOTP");
            return CLIENT_FAIL;
        }
    }

    if (respPkt.header.messageType != MsgLoginResp ||
        respPkt.header.payloadLength < sizeof(LoginResponsePayload)) {
        LOG_ERROR("clientLogin: invalid login response (type=%d, len=%u)",
                  (int)respPkt.header.messageType,
                  respPkt.header.payloadLength);
        packetClear(&respPkt);
        return CLIENT_FAIL;
    }

    /* ──────────────────── stage 4: validate login response
     * ──────────────────── */
    LoginResponsePayload *resp = (LoginResponsePayload *)respPkt.payload;
    if (resp->uid == 0) {
        packetClear(&respPkt);
        printf("Login failed.\n");
        return CLIENT_FAIL;
    }

    client->uid = resp->uid;
    printf("Login successful. Welcome, %s!\n", resp->nickname);
    if (resp->totpEnabled == 0) {
        printf("Security tip: enable TOTP with [t]otp setup for "
               "stronger account protection.\n");
    }

    /* ───── stage 5: request per-user encryption key, init local database
     * ────── */
    if (clientSendEncryptedPacket(client, MsgDBKeyReq, NULL, 0) !=
        PROTOCOL_SUCC) {
        LOG_ERROR("clientLogin: send MsgDBKeyReq failed");
        packetClear(&respPkt);
        return CLIENT_FAIL;
    }

    Packet dbKeyPkt;
    memset(&dbKeyPkt, 0, sizeof(dbKeyPkt));
    if (clientRecvEncryptedPacket(client, &dbKeyPkt) != PROTOCOL_SUCC) {
        LOG_ERROR("clientLogin: recv MsgDBKeyResp failed");
        packetClear(&respPkt);
        return CLIENT_FAIL;
    }
    if (dbKeyPkt.header.messageType != MsgDBKeyResp ||
        dbKeyPkt.header.payloadLength != CLIENT_DB_KEY_LEN) {
        LOG_ERROR("clientLogin: invalid MsgDBKeyResp (mt=%d, len=%u)",
                  (int)dbKeyPkt.header.messageType,
                  dbKeyPkt.header.payloadLength);
        packetClear(&dbKeyPkt);
        packetClear(&respPkt);
        return CLIENT_FAIL;
    }
    memcpy(client->cdbkey, dbKeyPkt.payload, CLIENT_DB_KEY_LEN);
    packetClear(&dbKeyPkt);

    /* Initialise the encrypted local database with the CDBKey. */
    if (clientInitDB(client) != CLIENT_DB_SUCC) {
        LOG_ERROR("clientLogin: clientInitDB failed");
        OPENSSL_cleanse(client->cdbkey, sizeof(client->cdbkey));
        packetClear(&respPkt);
        return CLIENT_FAIL;
    }

    /* CDBKey transferred to ClientDB — wipe plaintext copy. */
    OPENSSL_cleanse(client->cdbkey, sizeof(client->cdbkey));

    packetClear(&respPkt);
    return CLIENT_SUCC;
}

int clientRegister(Client *client) {
    /* ────────────────────── stage 1: collect credentials
     * ────────────────────── */

    char username[LOGIN_USERNAME_LEN];
    char nickname[LOGIN_NICKNAME_LEN];
    char password[MaxInputLen];

    printf("Choose username: ");
    fflush(stdout);
    if (fgets(username, (int)sizeof(username), stdin) == NULL) {
        return CLIENT_FAIL;
    }
    username[strcspn(username, "\n")] = '\0';

    printf("Choose nickname: ");
    fflush(stdout);
    if (fgets(nickname, (int)sizeof(nickname), stdin) == NULL) {
        return CLIENT_FAIL;
    }
    nickname[strcspn(nickname, "\n")] = '\0';

    printf("Choose password: ");
    fflush(stdout);
    if (readPasswordMasked(password, sizeof(password)) == 0) {
        OPENSSL_cleanse(password, sizeof(password));
        return CLIENT_FAIL;
    }
    printf("\n");

    /* ─────── stage 2: validate lengths, build and send register request
     * ─────── */

    size_t usernameLen = strlen(username);
    size_t nicknameLen = strlen(nickname);
    size_t pwLen = strlen(password);

    if (usernameLen >= LOGIN_USERNAME_LEN) {
        LOG_ERROR("clientRegister: username too long (%zu >= %d)", usernameLen,
                  LOGIN_USERNAME_LEN);
        OPENSSL_cleanse(password, sizeof(password));
        return CLIENT_FAIL;
    }

    if (nicknameLen >= LOGIN_NICKNAME_LEN) {
        LOG_ERROR("clientRegister: nickname too long (%zu >= %d)", nicknameLen,
                  LOGIN_NICKNAME_LEN);
        OPENSSL_cleanse(password, sizeof(password));
        return CLIENT_FAIL;
    }

    /* Build register payload — username(32) + nickname(32) + password(FAM).
     * UID is server-assigned; the client does not send one. */
    size_t payloadLen = RegisterHeaderSize + pwLen + 1;
    RegisterRequestPayload *reg = calloc(1, payloadLen);
    if (reg == NULL) {
        OPENSSL_cleanse(password, sizeof(password));
        return CLIENT_FAIL;
    }

    memcpy(reg->username, username, usernameLen + 1);
    memcpy(reg->nickname, nickname, nicknameLen + 1);
    memcpy(reg->password, password, pwLen + 1);
    OPENSSL_cleanse(password, sizeof(password));

    if (clientSendEncryptedPacket(client, MsgRegisterReq, reg, payloadLen) !=
        CLIENT_SUCC) {
        OPENSSL_cleanse(reg, payloadLen);
        free(reg);
        return CLIENT_FAIL;
    }
    OPENSSL_cleanse(reg, payloadLen);
    free(reg);

    /* ───────────── stage 3: receive and interpret server response
     * ───────────── */
    int status = clientRecvStatusResponse(client, MsgRegisterResp);
    if (status < 0) {
        LOG_ERROR("clientRegister: no response from server");
        return CLIENT_FAIL;
    }

    if (status == 1) {
        printf("Registration failed. Username may already exist.\n");
        return CLIENT_FAIL;
    }

    printf("Registration successful. You can now login.\n");
    return CLIENT_SUCC;
}

int clientTOTPSetup(Client *client) {
    /* ──────────────── stage 1: request TOTP secret from server
     * ──────────────── */
    if (clientSendEncryptedPacket(client, MsgTOTPSetupReq, NULL, 0) !=
        PROTOCOL_SUCC) {
        LOG_ERROR("clientTOTPSetup: failed to send request");
        return CLIENT_FAIL;
    }

    /* ───────────────── stage 2: receive and validate response
     * ───────────────── */
    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (clientRecvEncryptedPacket(client, &resp) != PROTOCOL_SUCC) {
        LOG_ERROR("clientTOTPSetup: no response from server");
        return CLIENT_FAIL;
    }

    if (resp.header.messageType != MsgTOTPSetupResp ||
        resp.header.payloadLength < sizeof(TOTPSetupRespPayload)) {
        LOG_ERROR("clientTOTPSetup: invalid response (type=%d, len=%u)",
                  (int)resp.header.messageType, resp.header.payloadLength);
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    TOTPSetupRespPayload *payload = (TOTPSetupRespPayload *)resp.payload;

    /* Empty secret means TOTP is already enabled; not an error. */
    if (payload->secret[0] == '\0') {
        printf("TOTP is already enabled or setup failed.\n");
        packetClear(&resp);
        return CLIENT_SUCC;
    }

    /* ─────────────── stage 3: display secret and otpauth:// URI
     * ─────────────── */
    char *uri = NULL;
    char username[TOTP_SETUP_SECRET_LEN];
    snprintf(username, sizeof(username), "user%u", client->uid);
    if (generateOTPAuthURI(payload->secret, username, &uri) == CRYPTO_SUCC) {
        printf("\n--- TOTP Secret ---\n");
        printf("Base32: %s\n", payload->secret);
        printf("URI:    %s\n", uri);
        printf("--------------------\n");
        printf("Scan the URI with your authenticator app.\n");
        free(uri);
    } else {
        printf("\n--- TOTP Secret ---\n");
        printf("Base32: %s\n", payload->secret);
        printf("--------------------\n");
        printf("Manually enter this secret into your authenticator app.\n");
    }

    packetClear(&resp);
    return CLIENT_SUCC;
}
