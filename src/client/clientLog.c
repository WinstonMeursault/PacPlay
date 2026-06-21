/**
 * @file clientLog.c
 * @brief Client log wrapper — delegates to the shared autoLog engine.
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

#include "clientLog.h"
#include "common/autoLog.h"

int clientLogInit(void) {
    AutoLogConfig cfg = {0};
    cfg.fileNamePrefix = "client";
    cfg.enableTuiBuffer = false;
    return autoLogInit(&cfg);
}

void clientLogClose(void) { autoLogClose(); }
