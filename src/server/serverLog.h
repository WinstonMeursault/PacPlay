/**
 * @file serverLog.h
 * @brief Server file-logging subsystem — thin wrapper around autoLog.
 *
 * The shared autoLog engine handles the log thread, ring buffer,
 * UTC-day file rotation, zlib-ng compression, automatic restart,
 * and the TUI-facing fetch API.  This module pins the server-specific
 * configuration (prefix = "server", TUI buffer enabled).
 *
 * @date 2026-06-10
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

#ifndef SERVER_LOG_H
#define SERVER_LOG_H

#include "log.h"

int  serverLogInit(void);
void serverLogCheckAndRestart(void);
void serverLogClose(void);

int  serverLogFetch(LogLevel minLevel, char ***outLines, int *outCount);
void serverLogFetchFree(char **lines, int count);

#endif /* SERVER_LOG_H */
