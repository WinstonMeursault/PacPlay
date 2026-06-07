/**
 * @file room.c
 * @brief Client-side room menu module — implementation.
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
#include "client/room.h"
#include "client/auth.h"
#include "client/chat.h"
#include "client/communication.h"
#include "log.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MaxInputLen = 512, MaxRoomDisplay = 100, IdInputLen = 32, DecBase = 10 };

int clientRoomMenu(Client *client) {

refresh:
    /* Request room list */
    if (clientSendEncryptedPacket(client, MsgRoomListReq, NULL, 0) !=
        PROTOCOL_SUCC) {
        return CLIENT_FAIL;
    }

    Packet resp;
    memset(&resp, 0, sizeof(resp));
    if (clientRecvEncryptedPacket(client, &resp) != PROTOCOL_SUCC) {
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
        printf(
            "\n[c]reate room  [j]oin room  [t]otp setup  [r]efresh  [q]uit\n");
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

            if (clientSendEncryptedPacket(client, MsgCreateRoom, &roomId,
                                          sizeof(roomId)) != PROTOCOL_SUCC) {
                return CLIENT_FAIL;
            }
            int createStatus =
                clientRecvStatusResponse(client, MsgCreateRoomResp);
            if (createStatus != 0) {
                printf("Room %u already exists.\n", roomId);
                continue;
            }
            printf("Room %u created.\n", roomId);
            /* Auto-join the newly created room */
            if (clientSendEncryptedPacket(client, MsgJoinRoom, &roomId,
                                          sizeof(roomId)) != PROTOCOL_SUCC) {
                return CLIENT_FAIL;
            }
            int joinAfterCreate =
                clientRecvStatusResponse(client, MsgJoinRoomResp);
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

            if (clientSendEncryptedPacket(client, MsgJoinRoom, &roomId,
                                          sizeof(roomId)) != PROTOCOL_SUCC) {
                return CLIENT_FAIL;
            }
            int joinStatus = clientRecvStatusResponse(client, MsgJoinRoomResp);
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
            clientSendEncryptedPacket(client, MsgLogout, NULL, 0);
            return CLIENT_FAIL; /* Signal disconnect */
        }
    }
}
