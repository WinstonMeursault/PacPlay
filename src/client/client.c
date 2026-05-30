/**
 * @file client.c
 * @brief PacPlay CLI client — connect, login, room management, chat loop.
 *
 * @date 2026-05-27
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

#include "client.h"
#include "client/communication.h"
#include "log.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <openssl/crypto.h>

/* ──────── internal constants ───────────────────────────────────────────── */

enum {
    LoginHeaderSize = offsetof(LoginRequestPayload, password),
    RegisterHeaderSize = offsetof(RegisterRequestPayload, password),
    MaxInputLen = 512,
    MaxRoomDisplay = 100,
    IdInputLen = 32
};

/* ──────── forward declarations ─────────────────────────────────────────── */

static int sendEncryptedPacket(Client *c, MessageType mt, const void *data,
                               size_t dataLen);
static int recvEncryptedPacket(Client *c, Packet *out);
static int recvStatusResp(Client *c, MessageType expectedMt);

/* ═══════════════════════  public API  ════════════════════════════════════ */

int clientConnect(Client *client, const char *addr, uint16_t port) {
    SocketFD fd = clientSetup(addr, port);
    if (fd == NULL_SOCKETFD) {
        LOG_ERROR("clientConnect: failed to connect to %s:%u", addr,
                  (unsigned int)port);
        return CLIENT_FAIL;
    }

    AESGCMKey key;
    if (clientExchangeAESKey(fd, &key) != COMM_SUCC) {
        LOG_ERROR("clientConnect: key exchange failed");
        socketClose(&fd);
        return CLIENT_FAIL;
    }

    client->fd = fd;
    memcpy(&client->aesKey, &key, sizeof(key));
    OPENSSL_cleanse(&key, sizeof(key));
    LOG_INFO("Connected and key exchanged with %s:%u", addr,
             (unsigned int)port);
    return CLIENT_SUCC;
}

int clientLogin(Client *client) {
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

    if (sendEncryptedPacket(client, MsgLoginReq, login, payloadLen) !=
        CLIENT_SUCC) {
        OPENSSL_cleanse(login, payloadLen);
        free(login);
        return CLIENT_FAIL;
    }
    OPENSSL_cleanse(login, payloadLen);
    free(login);

    /* Wait for response — may be a TOTP challenge or direct login response. */
    Packet respPkt;
    memset(&respPkt, 0, sizeof(respPkt));
    if (recvEncryptedPacket(client, &respPkt) != CLIENT_SUCC) {
        LOG_ERROR("clientLogin: no response from server");
        return CLIENT_FAIL;
    }

    if (respPkt.header.messageType == MsgTOTPVerifyReq) {
        packetClear(&respPkt);

        /* TOTP required — prompt for verification code */
        char codeBuf[TOTP_SETUP_SECRET_LEN];
        printf("TOTP code: ");
        fflush(stdout);
        if (fgets(codeBuf, (int)sizeof(codeBuf), stdin) == NULL) {
            return CLIENT_FAIL;
        }
        enum { DecBase = 10 };
        long codeVal = strtol(codeBuf, NULL, DecBase);
        enum { MinCode = 0, MaxCode = 999999 };
        if (codeVal < MinCode || codeVal > MaxCode) {
            printf("Invalid TOTP code.\n");
            return CLIENT_FAIL;
        }

        TOTPVerifyPayload tvp;
        tvp.code = (uint32_t)codeVal;
        if (sendEncryptedPacket(client, MsgTOTPVerifyResp, &tvp,
                                sizeof(tvp)) != CLIENT_SUCC) {
            return CLIENT_FAIL;
        }

        /* Wait for final login response */
        memset(&respPkt, 0, sizeof(respPkt));
        if (recvEncryptedPacket(client, &respPkt) != CLIENT_SUCC) {
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

    LoginResponsePayload *resp =
        (LoginResponsePayload *)respPkt.payload;
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
    packetClear(&respPkt);
    return CLIENT_SUCC;
}

int clientRegister(Client *client) {
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

    if (sendEncryptedPacket(client, MsgRegisterReq, reg, payloadLen) !=
        CLIENT_SUCC) {
        OPENSSL_cleanse(reg, payloadLen);
        free(reg);
        return CLIENT_FAIL;
    }
    OPENSSL_cleanse(reg, payloadLen);
    free(reg);

    int status = recvStatusResp(client, MsgRegisterResp);
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

int clientRoomMenu(Client *client) {

refresh:
    /* Request room list */
    if (sendEncryptedPacket(client, MsgRoomListReq, NULL, 0) != CLIENT_SUCC) {
        return CLIENT_FAIL;
    }

    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (recvEncryptedPacket(client, &resp) != CLIENT_SUCC) {
        return CLIENT_FAIL;
    }

    if (resp.header.messageType != MsgRoomListResp) {
        LOG_ERROR("clientRoomMenu: unexpected message type %d",
                  (int)resp.header.messageType);
        packetClear(&resp);
        return CLIENT_FAIL;
    }

    size_t roomCount = resp.header.payloadLength / sizeof(uint32_t);
    uint32_t *roomIds = (uint32_t *)resp.payload;

    printf("\n--- Available Rooms (%zu) ---\n", roomCount);
    for (size_t i = 0; i < roomCount && i < MaxRoomDisplay; i++) {
        printf("  Room %u\n", roomIds[i]);
    }
    if (roomCount == 0) {
        printf("  (none)\n");
    }

    packetClear(&resp);

    for (;;) {
        printf("\n[c]reate room  [j]oin room  [t]otp setup  [r]efresh  [q]uit\n");
        printf("Choice: ");
        fflush(stdout);

        char choice[MaxInputLen];
        if (fgets(choice, (int)sizeof(choice), stdin) == NULL) {
            return CLIENT_FAIL;
        }
        choice[strcspn(choice, "\n")] = '\0';

        if (strcmp(choice, "c") == 0) {
            printf("Room ID to create: ");
            fflush(stdout);
            uint32_t roomId = 0;
            {
                char idStr[IdInputLen];
                if (fgets(idStr, (int)sizeof(idStr), stdin) == NULL) {
                    return CLIENT_FAIL;
                }
                char *endPtr = NULL;
                enum { DecBase = 10 };
                unsigned long parsed = strtoul(idStr, &endPtr, DecBase);
                if (endPtr == idStr || parsed == 0 || parsed > UINT32_MAX) {
                    printf("Invalid room ID.\n");
                    continue;
                }
                roomId = (uint32_t)parsed;
            }

            if (sendEncryptedPacket(client, MsgCreateRoom, &roomId,
                                    sizeof(roomId)) != CLIENT_SUCC) {
                return CLIENT_FAIL;
            }
            int createStatus = recvStatusResp(client, MsgCreateRoomResp);
            if (createStatus != 0) {
                printf("Room %u already exists.\n", roomId);
                continue;
            }
            printf("Room %u created.\n", roomId);
            /* Auto-join the newly created room */
            if (sendEncryptedPacket(client, MsgJoinRoom, &roomId,
                                    sizeof(roomId)) != CLIENT_SUCC) {
                return CLIENT_FAIL;
            }
            int joinAfterCreate = recvStatusResp(client, MsgJoinRoomResp);
            if (joinAfterCreate != 0) {
                printf("Room %u created but join failed.\n", roomId);
                continue;
            }
            client->currentRoomId = roomId;
            printf("Joined room %u.\n", roomId);
            return CLIENT_SUCC;

        } else if (strcmp(choice, "j") == 0) {
            printf("Room ID to join: ");
            fflush(stdout);
            uint32_t roomId = 0;
            {
                char idStr[IdInputLen];
                if (fgets(idStr, (int)sizeof(idStr), stdin) == NULL) {
                    return CLIENT_FAIL;
                }
                char *endPtr = NULL;
                enum { DecBase = 10 };
                unsigned long parsed = strtoul(idStr, &endPtr, DecBase);
                if (endPtr == idStr || parsed == 0 || parsed > UINT32_MAX) {
                    printf("Invalid room ID.\n");
                    continue;
                }
                roomId = (uint32_t)parsed;
            }

            if (sendEncryptedPacket(client, MsgJoinRoom, &roomId,
                                    sizeof(roomId)) != CLIENT_SUCC) {
                return CLIENT_FAIL;
            }
            int joinStatus = recvStatusResp(client, MsgJoinRoomResp);
            if (joinStatus != 0) {
                printf("Failed to join room %u.\n", roomId);
                continue;
            }
            client->currentRoomId = roomId;
            printf("Joined room %u.\n", roomId);
            return CLIENT_SUCC;

        } else if (strcmp(choice, "t") == 0) {
            clientTOTPSetup(client);

        } else if (strcmp(choice, "r") == 0) {
            /* Refresh: re-request room list (goto label above) */
            goto refresh;

        } else if (strcmp(choice, "q") == 0) {
            sendEncryptedPacket(client, MsgLogout, NULL, 0);
            return CLIENT_FAIL; /* Signal disconnect */
        }
    }
}

int clientTOTPSetup(Client *client) {
    if (sendEncryptedPacket(client, MsgTOTPSetupReq, NULL, 0) != CLIENT_SUCC) {
        LOG_ERROR("clientTOTPSetup: failed to send request");
        return CLIENT_FAIL;
    }

    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (recvEncryptedPacket(client, &resp) != CLIENT_SUCC) {
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
    if (payload->secret[0] == '\0') {
        printf("TOTP is already enabled or setup failed.\n");
        packetClear(&resp);
        return CLIENT_SUCC;
    }

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

int clientChatLoop(Client *client) {
    printf("\n--- Chat Room %u ---\n", client->currentRoomId);
    printf("Type /exit to leave, /help for commands.\n\n");

    for (;;) {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(STDIN_FILENO, &readFds);
        FD_SET(client->fd, &readFds);
        int maxFd = (client->fd > STDIN_FILENO) ? client->fd : STDIN_FILENO;

        int ready = select(maxFd + 1, &readFds, NULL, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("clientChatLoop: select failed (errno=%d)", errno);
            return CLIENT_FAIL;
        }

        /* Incoming server message */
        if (FD_ISSET(client->fd, &readFds)) {
            Packet pkt;
            memset(&pkt, 0, sizeof(pkt));
            if (recvEncryptedPacket(client, &pkt) != CLIENT_SUCC) {
                return CLIENT_FAIL;
            }

            if (pkt.header.messageType == MsgChat) {
                /* Broadcast from server: ChatBroadcastPayload */
                if (pkt.header.payloadLength >=
                    sizeof(uint32_t) + sizeof(uint64_t) + sizeof(int64_t)) {
                    ChatBroadcastPayload *bc =
                        (ChatBroadcastPayload *)pkt.payload;
                    size_t msgLen =
                        pkt.header.payloadLength -
                        (sizeof(uint32_t) + sizeof(uint64_t) + sizeof(int64_t));
                    printf("[uid=%u msgId=%lu] %.*s\n", bc->uid,
                           (unsigned long)bc->msgId, (int)msgLen, bc->message);
                }
            }
            packetClear(&pkt);
        }

        /* User input */
        if (FD_ISSET(STDIN_FILENO, &readFds)) {
            char input[MaxInputLen];
            if (fgets(input, (int)sizeof(input), stdin) == NULL) {
                return CLIENT_FAIL;
            }
            input[strcspn(input, "\n")] = '\0';

            if (input[0] == '\0') {
                continue;
            }

            /* Commands */
            if (input[0] == '/') {
                if (strcmp(input, "/exit") == 0) {
                    sendEncryptedPacket(client, MsgLogout, NULL, 0);
                    return CLIENT_SUCC;
                }
                if (strcmp(input, "/help") == 0) {
                    printf("Commands: /exit, /help\n");
                    printf("Anything else is sent as a chat message.\n");
                    continue;
                }
                /* Unknown command — fall through to send as chat */
            }

            /* Send as a chat message */
            time_t now = getCurrentTimestamp();
            int64_t ts = (int64_t)now;
            size_t msgLen = strlen(input) + 1; /* +NUL */
            size_t payloadLen = sizeof(int64_t) + msgLen;

            ChatPacketPayload *chat = malloc(payloadLen);
            if (chat == NULL) {
                return CLIENT_FAIL;
            }
            memcpy(&chat->timestamp, &ts, sizeof(int64_t));
            memcpy(chat->message, input, msgLen);

            if (sendEncryptedPacket(client, MsgChat, chat, payloadLen) !=
                CLIENT_SUCC) {
                free(chat);
                return CLIENT_FAIL;
            }
            free(chat);
        }
    }
}

void clientDisconnect(Client *client) {
    if (client->fd != NULL_SOCKETFD) {
        OPENSSL_cleanse(&client->aesKey, sizeof(client->aesKey));
        socketClose(&client->fd);
    }
    LOG_INFO("Client disconnected");
}

/* ═══════════════════════  helpers  ═══════════════════════════════════════ */

static int sendEncryptedPacket(Client *c, MessageType mt, const void *data,
                               size_t dataLen) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    if (packetInit(&pkt, mt, c->seqID, PlaintextPacket, data, dataLen) !=
        PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    if (packetAESEncrypt(&pkt, c->aesKey.key) != PROTOCOL_SUCC) {
        packetClear(&pkt);
        return CLIENT_FAIL;
    }

    c->seqID++;

    int ret = packetSend(&pkt, c->fd);
    packetClear(&pkt);
    return (ret == PROTOCOL_SUCC) ? CLIENT_SUCC : CLIENT_FAIL;
}

static int recvEncryptedPacket(Client *c, Packet *out) {
    if (packetRecv(out, c->fd) != PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    if (out->header.packetType != AES256GCMPacket) {
        LOG_WARN("recvEncryptedPacket: received non-encrypted packet (type=%d)",
                 (int)out->header.packetType);
        packetClear(out);
        return CLIENT_FAIL;
    }

    if (packetAESDecrypt(out, c->aesKey.key) != PROTOCOL_SUCC) {
        LOG_WARN("recvEncryptedPacket: AES decrypt failed");
        packetClear(out);
        return CLIENT_FAIL;
    }

    return CLIENT_SUCC;
}

/**
 * @brief Receive a single-byte status response and return the value.
 *
 * @return 0 or 1 on success, -1 on failure.
 */
static int recvStatusResp(Client *c, MessageType expectedMt) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    if (recvEncryptedPacket(c, &pkt) != CLIENT_SUCC) {
        return -1;
    }

    if (pkt.header.messageType != expectedMt) {
        LOG_WARN("recvStatusResp: unexpected message type %d (expected %d)",
                 (int)pkt.header.messageType, (int)expectedMt);
        packetClear(&pkt);
        return -1;
    }

    if (pkt.header.payloadLength < sizeof(uint8_t)) {
        packetClear(&pkt);
        return -1;
    }

    int status = (int)pkt.payload[0];
    packetClear(&pkt);
    return status;
}

