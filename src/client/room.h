/**
 * @file room.h
 * @brief Client-side room menu module header.
 *
 * Room functions are declared in @c client.h.  This header exists as
 * the module boundary for @c room.c and includes the parent header
 * for type definitions.
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

#ifndef CLIENT_ROOM_H
#define CLIENT_ROOM_H

#include "client.h"

int clientRoomList(Client *client, uint32_t **roomIds, size_t *roomCount);
int clientCreateRoom(Client *client, uint32_t id);
int clientJoinRoom(Client *client, uint32_t id);
void clientQuitRoom(Client *client);

#endif /* CLIENT_ROOM_H */
