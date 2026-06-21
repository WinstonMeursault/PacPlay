/**
 * @file chat.h
 * @brief Server-side chat message handling.
 *
 * Validates, persists, and broadcasts chat messages within active rooms.
 * This module owns chat business logic; raw packet I/O is delegated to
 * the communication module.
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

#ifndef SERVER_CHAT_H
#define SERVER_CHAT_H

#include "protocol.h"
#include "server.h"

/**
 * @brief Handle an incoming chat message from a client.
 *
 * Validates the chat payload, stores the message in ChatHistoryDB,
 * and broadcasts it to all other members of the sender's current room.
 *
 * @param server  Server instance (must have open databases).
 * @param sender  The sending client session.
 * @param pkt     Decrypted incoming packet with MsgChat payload.
 * @return @c SERVER_SUCC on success, @c SERVER_FAIL on failure.
 */
int serverHandleChatMessage(Server *server, ClientSession *sender,
                            const Packet *pkt);

#endif /* SERVER_CHAT_H */
