/**
 * @file main.c
 * @brief PacPlay client entrypoint.
 *
 * @date 2026-05-16
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

#include "client.h"

#include <stdio.h>
#include <string.h>

enum {
    ServerPort = 12345
};

static const char *serverAddr = "127.0.0.1";

int main(void) {
    Client client;
    memset(&client, 0, sizeof(client));

    if (clientConnect(&client, serverAddr, ServerPort) != CLIENT_SUCC) {
        return 1;
    }

    for (;;) {
        printf("\n[L]ogin or [R]egister? ");
        fflush(stdout);
        char choice = (char)getchar();
        int cc;
        while ((cc = getchar()) != '\n' && cc != EOF) {
        }

        if (choice == 'r' || choice == 'R') {
            if (clientRegister(&client) == CLIENT_SUCC) {
                printf("\n");
                /* fall through to login after successful registration */
            }
            continue;
        }

        if (choice != 'l' && choice != 'L') {
            printf("Invalid choice.\n");
            continue;
        }

        if (clientLogin(&client) == CLIENT_SUCC) {
            break;
        }
        printf("Login failed. Try again? [y/n]: ");
        fflush(stdout);
        char c = (char)getchar();
        while ((cc = getchar()) != '\n' && cc != EOF) {
        }
        if (c != 'y' && c != 'Y') {
            clientDisconnect(&client);
            return 1;
        }
    }

    if (clientRoomMenu(&client) != CLIENT_SUCC) {
        clientDisconnect(&client);
        return 0;
    }

    clientChatLoop(&client);
    clientDisconnect(&client);
    return 0;
}
