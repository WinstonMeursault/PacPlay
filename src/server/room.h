/**
 * @file room.h
 * @brief Server-side active room lifecycle management.
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

#ifndef SERVER_ROOM_H
#define SERVER_ROOM_H

#include "server.h"

/* ────────────────────────────── room helpers ────────────────────────────── */

/**
 * @brief Find an active room by its room ID.
 *
 * Linear search through the server's dynamic activeRoom array.
 *
 * @param s       Server instance.
 * @param roomId  Room identifier.
 * @return Pointer to the ActiveRoom, or NULL if not found.
 */
ActiveRoom *serverFindActiveRoom(const Server *s, uint32_t roomId);

/**
 * @brief Find an active room or create a new one.
 *
 * If @p roomId is not currently active, allocates a new ActiveRoom and
 * appends it to the server's dynamic array (resizing if necessary).
 *
 * @param s       Server instance.
 * @param roomId  Room identifier.
 * @return Pointer to the ActiveRoom, or NULL on allocation failure.
 */
ActiveRoom *serverGetOrCreateActiveRoom(Server *s, uint32_t roomId);

/**
 * @brief Remove an active room and compact the array.
 *
 * Frees the ActiveRoom.  If the room is not found this is a no-op.
 *
 * @param s       Server instance.
 * @param roomId  Room identifier.
 */
void serverRemoveActiveRoom(Server *s, uint32_t roomId);

/**
 * @brief Remove a client from their current room.
 *
 * If the room becomes empty it is removed automatically.  If the client
 * is not in a room (@c currentRoomId == 0) this is a no-op.
 *
 * @param s   Server instance.
 * @param cs  Client session to remove.
 */
void serverRemoveClientFromRoom(Server *s, ClientSession *cs);

/* ───────────────────────────── room handlers ────────────────────────────── */

/**
 * @brief Handle MsgRoomListReq — query GameDB and return all room IDs.
 *
 * @param s   Server instance (must have an open GameDB).
 * @param cs  Authenticated client session.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on error.
 */
int serverHandleRoomList(Server *s, ClientSession *cs);

/**
 * @brief Handle MsgCreateRoom — persist a new room in GameDB.
 *
 * Expects a single uint32_t room ID as payload.  Sends a single-byte
 * status response (0 = success, 1 = failure).
 *
 * @param s   Server instance.
 * @param cs  Authenticated client session.
 * @param pkt Decrypted incoming MsgCreateRoom packet (uint32_t roomId).
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on error.
 */
int serverHandleRoomCreate(Server *s, ClientSession *cs, const Packet *pkt);

/**
 * @brief Handle MsgJoinRoom — verify room existence, leave current room,
 * join the target room, and advance to SessionChat.
 *
 * Expects a single uint32_t room ID as payload.  If the room is full
 * (MAX_CLIENTS_PER_ROOM) the join is rejected.
 *
 * @param s   Server instance.
 * @param cs  Authenticated client session.
 * @param pkt Decrypted incoming MsgJoinRoom packet (uint32_t roomId).
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on error.
 */
int serverHandleRoomJoin(Server *s, ClientSession *cs, const Packet *pkt);

#endif /* SERVER_ROOM_H */
