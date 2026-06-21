/**
 * @file serverTUI.h
 * @brief
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

#ifndef SERVER_TUI_H
#define SERVER_TUI_H

#include "tui/tuiapp.h"
#include "../server.h"

#include <stdbool.h>

/**
 * @brief Enter the server TUI for key management and server control.
 *
 * Runs a single continuous TUI session.  On first run shows the Init
 * Page displaying @p masterKeyHex, then transitions to the Start Page.
 * On subsequent runs, shows the Start Page directly.
 *
 * After the user successfully unlocks with the Master Key, the server
 * is launched in a background thread (via serverLaunch) and the TUI
 * transitions to the Main Page with a live log viewer and command box.
 *
 * Blocks until the user issues the 'exit' command, which stops the
 * background server thread before returning.
 *
 * @param serverInstance  The server instance (must have serverDB open).
 * @param isFirstRun      Whether this is the first server launch.
 * @param masterKeyHex    64-char hex Master Key (only valid when
 *                        isFirstRun, ignored otherwise).
 */
void tuiServerEntry(Server *serverInstance, bool isFirstRun,
                    const char *masterKeyHex);

#endif // SERVER_TUI_H
