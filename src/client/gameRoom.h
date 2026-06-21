/**
 * @file gameRoom.h
 * @brief Client-side game room module header.
 *
 * @date 2026-06-20
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

#ifndef CLIENT_GAMEROOM_H
#define CLIENT_GAMEROOM_H

#include "client.h"

int clientGameRoomList(Client *client, uint32_t gameId,
                       GameRoomListEntry **outEntries, size_t *outCount);

int clientGameRoomCreate(Client *client, uint32_t gameId,
                         uint32_t *outRoomId);

int clientGameRoomJoin(Client *client, uint32_t gameRoomId);

void clientGameRoomQuit(Client *client);

int clientGameRoomStart(Client *client, uint32_t gameRoomId);

void clientPollNotifications(Client *client);

#endif /* CLIENT_GAMEROOM_H */
