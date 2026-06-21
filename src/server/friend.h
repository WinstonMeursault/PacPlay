/**
 * @file friend.h
 * @brief Server-side friend system handlers.
 *
 * Validates and processes friend requests, accept/reject/delete operations,
 * and friend list queries.  Business logic is delegated to the FriendDB
 * layer; raw packet I/O is handled by the communication module.
 *
 * @date 2026-06-21
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

#ifndef SERVER_FRIEND_H
#define SERVER_FRIEND_H

#include "protocol.h"
#include "server.h"

int serverHandleFriendRequest(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleFriendAccept(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleFriendReject(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleFriendDelete(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleFriendList(Server *s, ClientSession *cs);

#endif /* SERVER_FRIEND_H */
