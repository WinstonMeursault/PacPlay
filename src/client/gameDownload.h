/**
 * @file gameDownload.h
 * @brief Client-side game download manager with resume support.
 *
 * @date 2026-06-17
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

#ifndef GAMEDOWNLOAD_H
#define GAMEDOWNLOAD_H

#include "archive.h"
#include "client.h"
#include "protocol.h"
#include <stddef.h>
#include <stdint.h>

#define MAX_CLIENT_DOWNLOADS 4
#define CLIENT_GAME_LIB_DIR "./gameLib"

typedef enum {
    DlPending = 0,
    DlDownloading,
    DlVerifying,
    DlDone,
    DlFailed,
    DlCancelled
} DownloadStatus;

typedef struct {
    uint32_t gameId;
    char gameName[GAME_NAME_LEN];
    char gameVersion[GAME_VERSION_LEN];
    char platform[PLATFORM_NAME_LEN];
    uint64_t fileSize;
    uint32_t totalChunks;
    uint32_t receivedChunks;
    DownloadStatus status;
} DownloadProgress;

#pragma pack(push, 1)
typedef struct {
    uint32_t gameId;
    char hash[GAME_HASH_LEN];
    uint32_t totalChunks;
    uint32_t receivedChunks;
    uint64_t fileSize;
    uint16_t dataPort;
} DownloadResumeInfo;
#pragma pack(pop)

typedef struct DownloadManager DownloadManager;

int downloadManagerInit(DownloadManager **mgr, Client *client);
int downloadManagerStartDownload(DownloadManager *mgr, uint32_t gameId,
                                 const char *platform);
int downloadManagerCancel(DownloadManager *mgr, uint32_t gameId);
int downloadManagerGetProgress(DownloadManager *mgr, DownloadProgress *out,
                               size_t *count);
void downloadManagerDestroy(DownloadManager *mgr);

int clientRequestGameList(Client *client, uint32_t rangeStart,
                          uint32_t rangeEnd, const char *platform,
                          GameInfoEntry **outList, size_t *outCount);
void clientFreeGameList(GameInfoEntry *list);

#endif // GAMEDOWNLOAD_H
