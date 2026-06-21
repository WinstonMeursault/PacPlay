/**
 * @file group.h
 * @brief Server-side group chat lifecycle management.
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

#ifndef SERVER_GROUP_H
#define SERVER_GROUP_H

#include "protocol.h"
#include "server.h"

int serverHandleGroupCreate(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGroupJoin(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGroupQuit(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGroupList(Server *s, ClientSession *cs);
int serverHandleGroupChat(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGroupKick(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGroupDisband(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGroupChatHistory(Server *s, ClientSession *cs,
                                 const Packet *pkt);

#endif
