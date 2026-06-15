/**
 * @file connection.h
 * @brief PacPlay client public connection API.
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

#ifndef CONNECTION_H
#define CONNECTION_H

#include "client.h"

struct ClientDB; /* forward — full definition in client/database.h */

#include <stdint.h>

/**
 * @brief Connect to the server and perform ECDH+HKDF key exchange.
 *
 * @param client  Must be zero-initialised.
 * @param addr    Server IPv4 address (e.g. "127.0.0.1").
 * @param port    Server port.
 * @return @c CLIENT_SUCC on success, @c CLIENT_FAIL on failure.
 */
int clientConnect(Client *client, const char *addr, uint16_t port);

/**
 * @brief Disconnect and clean up client resources.
 *
 * @param client  Client to tear down.
 */
void clientDisconnect(Client *client);

#endif // CONNECTION_H
