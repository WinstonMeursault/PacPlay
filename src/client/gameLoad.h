/**
 * @file gameLoad.h
 * @brief Load game from .so
 *
 * @date 2026-06-15
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

#ifndef GAMELOAD_H
#define GAMELOAD_H

#include <stddef.h>
#include <stdint.h>

#define MAX_CLIENT_DOWNLOADS 4
#include "vterm.h"

int clientRunGame(VTerm **vterm, VTermScreen **vscreen, const char *path,
                  int height, int width, pid_t *pid, int *ptyFD);

void clientStopGame(VTerm **vterm, pid_t *pid, int *ptyFD);

#endif // GAMELOAD_H
