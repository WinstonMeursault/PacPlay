/**
 * @file chat.c
 * @brief Client-side chat payload construction and parsing — implementation.
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
#include "chat.h"
#include "communication.h"
#include "utils.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    LoginHeaderSize = offsetof(LoginRequestPayload, password),
    RegisterHeaderSize = offsetof(RegisterRequestPayload, password),
    MaxInputLen = 512,
    MaxRoomDisplay = 100,
    IdInputLen = 32
};

int clientChatSend(Client *client, const char *message, int64_t timestamp) {
    size_t msgLen = strlen(message) + 1;
    size_t payloadLen = sizeof(int64_t) + msgLen;
    ChatPacketPayload *chat = malloc(payloadLen);
    if (chat == NULL)
        return CLIENT_FAIL;
    memcpy(&chat->timestamp, &timestamp, sizeof(int64_t));
    memcpy(chat->message, message, msgLen);
    int ret = clientSendEncryptedPacket(client, MsgChat, chat, payloadLen);
    free(chat);
    return ret;
}

int clientChatParseBroadcast(const Packet *pkt, ChatBroadcastPayload *out,
                             size_t *outLen) {
    if (pkt->header.payloadLength <
        sizeof(uint32_t) + sizeof(uint64_t) + sizeof(int64_t))
        return CLIENT_FAIL;
    const ChatBroadcastPayload *bc = (const ChatBroadcastPayload *)pkt->payload;
    *outLen = pkt->header.payloadLength -
              (sizeof(uint32_t) + sizeof(uint64_t) + sizeof(int64_t));
    memcpy(out, bc, offsetof(ChatBroadcastPayload, message) + *outLen);
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
            if (clientRecvEncryptedPacket(client, &pkt) != PROTOCOL_SUCC) {
                return CLIENT_FAIL;
            }

            if (pkt.header.messageType == MsgChat) {
                ChatBroadcastPayload bc;
                size_t bcMsgLen = 0;
                if (clientChatParseBroadcast(&pkt, &bc, &bcMsgLen) ==
                    CLIENT_SUCC) {
                    printf("[uid=%u msgId=%lu] %.*s\n", bc.uid,
                           (unsigned long)bc.msgId, (int)bcMsgLen, bc.message);
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
                    clientSendEncryptedPacket(client, MsgLogout, NULL, 0);
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
            if (clientChatSend(client, input, (int64_t)now) != PROTOCOL_SUCC) {
                return CLIENT_FAIL;
            }
        }
    }
}