/**
 * @file serverLog.c
 * @brief Server log wrapper — delegates to the shared autoLog engine.
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

#include "server/serverLog.h"
#include "common/autoLog.h"

int serverLogInit(void) {
    AutoLogConfig cfg = {0};
    cfg.fileNamePrefix = "server";
    cfg.enableTuiBuffer = true;
    return autoLogInit(&cfg);
}

void serverLogCheckAndRestart(void) { autoLogCheckAndRestart(); }

void serverLogClose(void) { autoLogClose(); }

int serverLogFetch(LogLevel minLevel, char ***outLines, int *outCount) {
    return autoLogFetch(minLevel, outLines, outCount);
}

void serverLogFetchFree(char **lines, int count) {
    autoLogFetchFree(lines, count);
}
