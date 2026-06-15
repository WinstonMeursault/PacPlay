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

enum { MaxInputLen = 512 };

enum {
    LoginHeaderSize = offsetof(LoginRequestPayload, password),
    RegisterHeaderSize = offsetof(RegisterRequestPayload, password)
};

static int clientLoadDB(Client *client, char *response);

int clientLogin(Client *client, char *username, char *password, char *response,
                bool *totpEnabled, bool *totpRequest, char *outNickname) {
    size_t pwLen = strlen(password);

    // Build login payload — username(32) + password(FAM).
    // No uid or nickname; the server returns those on success.
    size_t payloadLen = LoginHeaderSize + pwLen + 1;
    LoginRequestPayload *loginPayload = calloc(1, payloadLen);
    if (loginPayload == NULL) {
        return CLIENT_FAIL;
    }

    memcpy(loginPayload->username, username, strlen(username) + 1);
    memcpy(loginPayload->password, password, pwLen + 1);
    OPENSSL_cleanse(password, sizeof(password));

    if (clientSendEncryptedPacket(client, MsgLoginReq, loginPayload,
                                  payloadLen) != CLIENT_SUCC) {
        strcpy(response, "Error when sending packet");
        LOG_ERROR("clientLogin: Cannot send packet");
        OPENSSL_cleanse(loginPayload, payloadLen);
        free(loginPayload);
        return CLIENT_FAIL;
    }
    OPENSSL_cleanse(loginPayload, payloadLen);
    free(loginPayload);

    // wait for login response

    Packet respPkt;
    memset(&respPkt, 0, sizeof(respPkt));
    if (clientRecvEncryptedPacket(client, &respPkt) != PROTOCOL_SUCC) {
        strcpy(response, "No response from server");
        LOG_ERROR("clientLogin: No response from server");
        packetClear(&respPkt);
        return CLIENT_FAIL;
    }

    if (respPkt.header.messageType == MsgTOTPVerifyReq) {
        *totpRequest = true;
        *totpEnabled = true;
        packetClear(&respPkt);
        return CLIENT_SUCC;
    } else {
        *totpRequest = false;
    }

    if (respPkt.header.messageType != MsgLoginResp ||
        respPkt.header.payloadLength < sizeof(LoginResponsePayload)) {
        LOG_ERROR("clientLogin: Invalid login response (type=%d, len=%u)",
                  (int)respPkt.header.messageType,
                  respPkt.header.payloadLength);
        strcpy(response, "Invalid response");
        packetClear(&respPkt);
        return CLIENT_FAIL;
    }

    // validate login response
    LoginResponsePayload *resp = (LoginResponsePayload *)respPkt.payload;
    if (resp->uid == 0) {
        packetClear(&respPkt);
        strcpy(response, "Incorrect password or unknown user");
        LOG_ERROR("clientLogin: Failed to login");
        return CLIENT_FAIL;
    }

    client->uid = resp->uid;
    *totpEnabled = resp->totpEnabled;

    strcpy(outNickname, resp->nickname);

    packetClear(&respPkt);
    return clientLoadDB(client, response);
}

static int clientLoadDB(Client *client, char *response) {
    // request per-user encryption key, init local database
    if (clientSendEncryptedPacket(client, MsgDBKeyReq, NULL, 0) !=
        PROTOCOL_SUCC) {
        LOG_ERROR("clientLogin: send MsgDBKeyReq failed");
        strcpy(response, "Send MsgDBKeyReq failed");
        return CLIENT_FAIL;
    }

    Packet dbKeyPkt;
    memset(&dbKeyPkt, 0, sizeof(dbKeyPkt));
    if (clientRecvEncryptedPacket(client, &dbKeyPkt) != PROTOCOL_SUCC) {
        LOG_ERROR("clientLogin: recv MsgDBKeyResp failed");
        strcpy(response, "Auth failed (maybe wrong TOTP code)");
        return CLIENT_FAIL;
    }
    if (dbKeyPkt.header.messageType != MsgDBKeyResp ||
        dbKeyPkt.header.payloadLength != CLIENT_DB_KEY_LEN) {
        LOG_ERROR("clientLogin: invalid MsgDBKeyResp (mt=%d, len=%u)",
                  (int)dbKeyPkt.header.messageType,
                  dbKeyPkt.header.payloadLength);
        strcpy(response, "Invalid response");
        packetClear(&dbKeyPkt);
        return CLIENT_FAIL;
    }
    memcpy(client->cdbkey, dbKeyPkt.payload, CLIENT_DB_KEY_LEN);
    packetClear(&dbKeyPkt);

    // Initialise the encrypted local database with the CDBKey.
    if (clientInitDB(client) != CLIENT_DB_SUCC) {
        LOG_ERROR("clientLogin: clientInitDB failed");
        strcpy(response, "ClientInitDB failed");
        OPENSSL_cleanse(client->cdbkey, sizeof(client->cdbkey));
        return CLIENT_FAIL;
    }

    // CDBKey transferred to ClientDB — wipe plaintext copy.
    OPENSSL_cleanse(client->cdbkey, sizeof(client->cdbkey));

    return CLIENT_SUCC;
}

int clientRegister(Client *client, char *username, char *nickname,
                   char *password, char *response) {
    size_t pwLen = strlen(password);

    // Build register payload — username(32) + nickname(32) + password(FAM).
    // UID is server-assigned; the client does not send one.
    size_t payloadLen = RegisterHeaderSize + pwLen + 1;
    RegisterRequestPayload *reg = calloc(1, payloadLen);
    if (reg == NULL) {
        strcpy(response, "Error when allocating memory");
        LOG_ERROR("clientRegister:  Cannot allocate memory");
        return CLIENT_FAIL;
    }

    memcpy(reg->username, username, strlen(username) + 1);
    memcpy(reg->nickname, nickname, strlen(nickname) + 1);
    memcpy(reg->password, password, pwLen + 1);

    if (clientSendEncryptedPacket(client, MsgRegisterReq, reg, payloadLen) !=
        CLIENT_SUCC) {
        strcpy(response, "Error when sending packet");
        LOG_ERROR("clientRegister:  Cannot send packet");
        OPENSSL_cleanse(reg, payloadLen);
        free(reg);
        return CLIENT_FAIL;
    }
    OPENSSL_cleanse(reg, payloadLen);
    free(reg);

    // receive and interpret server response
    int status = clientRecvStatusResponse(client, MsgRegisterResp);
    if (status < 0) {
        strcpy(response, "No response from server");
        LOG_ERROR("clientRegister:  No response from server");
        return CLIENT_FAIL;
    }

    if (status == 1) {
        strcpy(response, "Username may already exist");
        LOG_ERROR("clientRegister:  Username already exist");
        return CLIENT_FAIL;
    }

    strcpy(response, "Successful, now you can login");
    return CLIENT_SUCC;
}

// need to free uri after called
int clientTOTPSetup(Client *client, char *response, char *secret, char **uri,
                    bool *uriSucc, size_t *uriLen) {
    // request TOTP secret from server
    if (clientSendEncryptedPacket(client, MsgTOTPSetupReq, NULL, 0) !=
        PROTOCOL_SUCC) {
        LOG_ERROR("clientTOTPSetup: failed to send request");
        strcpy(response, "Failed to send request");
        return CLIENT_FAIL;
    }

    // receive and validate response
    Packet resp;
    memset(&resp, 0, sizeof(resp));

    if (clientRecvEncryptedPacket(client, &resp) != PROTOCOL_SUCC) {
        LOG_ERROR("clientTOTPSetup: no response from server");
        strcpy(response, "No response from server");
        return CLIENT_FAIL;
    }

    if (resp.header.messageType != MsgTOTPSetupResp ||
        resp.header.payloadLength < sizeof(TOTPSetupRespPayload)) {
        LOG_ERROR("clientTOTPSetup: invalid response (type=%d, len=%u)",
                  (int)resp.header.messageType, resp.header.payloadLength);
        strcpy(response, "Invalid response");
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    TOTPSetupRespPayload *payload = (TOTPSetupRespPayload *)resp.payload;

    // Empty secret means TOTP is already enabled; not an error.
    if (payload->secret[0] == '\0') {
        packetClear(&resp);
        return CLIENT_SUCC;
    }

    strcpy(secret, payload->secret);

    // display secret and otpauth:// URI
    char username[TOTP_SETUP_SECRET_LEN];
    snprintf(username, sizeof(username), "user%u", client->uid);
    *uriSucc = generateOTPAuthURI(payload->secret, username, uri, uriLen) ==
               CRYPTO_SUCC;

    packetClear(&resp);
    return CLIENT_SUCC;
}

int clientTOTPVerify(Client *client, char *code, char *response, char *outNickname) {
    Packet respPkt;
    memset(&respPkt, 0, sizeof(respPkt));

    packetClear(&respPkt);

    // strtol returns 0 on parse failure, filtered by range check
    enum { DecBase = 10, MinCode = 0, MaxCode = 999999 };
    long codeVal = strtol(code, NULL, DecBase);
    if (codeVal < MinCode || codeVal > MaxCode) {
        strcpy(response, "Invalid TOTP code");
        return CLIENT_FAIL;
    }

    TOTPVerifyPayload tvp;
    tvp.code = (uint32_t)codeVal;
    if (clientSendEncryptedPacket(client, MsgTOTPVerifyResp, &tvp,
                                  sizeof(tvp)) != CLIENT_SUCC) {
        LOG_ERROR("clientTOTPVerify: failed to send packet");
        strcpy(response, "Failed to send packet");
        return CLIENT_FAIL;
    }

    // wait for final login response
    memset(&respPkt, 0, sizeof(respPkt));
    if (clientRecvEncryptedPacket(client, &respPkt) != PROTOCOL_SUCC) {
        LOG_ERROR("clientTOTPVerify: no response after TOTP");
        strcpy(response, "No response after TOTP");
        return CLIENT_FAIL;
    }

    // validate login response
    LoginResponsePayload *resp = (LoginResponsePayload *)respPkt.payload;
    if (resp->uid == 0) {
        packetClear(&respPkt);
        strcpy(response, "Incorrect TOTP code");
        LOG_ERROR("clientTOTPVerify: Failed to login");
        return CLIENT_FAIL;
    }

    strcpy(outNickname, resp->nickname);

    packetClear(&respPkt);
    return clientLoadDB(client, response);
}