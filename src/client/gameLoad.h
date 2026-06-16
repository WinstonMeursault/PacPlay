/**
 * @file gameLoad.h
 * @brief Download manager interface for client-side game acquisition.
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

typedef struct DownloadManager DownloadManager;

int downloadManagerInit(DownloadManager **mgr, Client *client);
int downloadManagerStartDownload(DownloadManager *mgr, uint32_t gameId,
                                 const char *platform);
int downloadManagerCancel(DownloadManager *mgr, uint32_t gameId);
int downloadManagerGetProgress(DownloadManager *mgr,
                               DownloadProgress *out, size_t *count);
void downloadManagerDestroy(DownloadManager *mgr);

int clientRequestGameList(Client *client, const char *platform,
                          GameListEntry **outList, size_t *outCount);
void clientFreeGameList(GameListEntry *list);

#endif // GAMELOAD_H
