/**
 * @file autoLog.h
 * @brief Shared auto-rotating compressed log engine — dedicated log thread
 *        with UTC-day file rotation, background zlib-ng compression, automatic
 *        restart on thread failure, and an optional TUI-facing log fetch API.
 *
 * Used by both server and client via thin wrappers (serverLog, clientLog).
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

#ifndef AUTOLOG_H
#define AUTOLOG_H

#include "log.h"

#include <stdbool.h>

typedef struct {
    const char *logDir;
    const char *fileNamePrefix;
    int queueCapacity;
    int maxMsgLen;
    int compressRetentionDays;
    int maxRestarts;
    bool enableTuiBuffer;
    int tuiBufferCapacity;
} AutoLogConfig;

int  autoLogInit(const AutoLogConfig *cfg);
void autoLogCheckAndRestart(void);
void autoLogClose(void);

int  autoLogFetch(LogLevel minLevel, char ***outLines, int *outCount);
void autoLogFetchFree(char **lines, int count);

#endif /* AUTOLOG_H */
