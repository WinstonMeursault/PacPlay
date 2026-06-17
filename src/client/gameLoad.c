/**
 * @file gameLoad.c
 * @brief
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

#include "gameLoad.h"
#include "client.h"
#include "log.h"
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#define SUBPROCESS_EXIT_NUM 127

int clientRunGame(VTerm **vterm, VTermScreen **vscreen, const char *path,
                  int height, int width, pid_t *pid, int *ptyFD) {
    if (height <= 0 || width <= 0) {
        LOG_ERROR("clientRunGame: width(%d) and height(%d) cannot below 1",
                  width, height);
    }
    int slaveFD;
    if (openpty(ptyFD, &slaveFD, NULL, NULL, NULL) < 0) {
        LOG_ERROR("clientRunGame: cannot create pty");
        return CLIENT_FAIL;
    }

    int flags = fcntl(*ptyFD, F_GETFL, 0);
    fcntl(*ptyFD, F_SETFL, flags | O_NONBLOCK);

    *vterm = vterm_new(height, width);
    vterm_set_utf8(*vterm, 1);

    // solve the seg fault in libvterm
    VTermState *state = vterm_obtain_state(*vterm);
    vterm_state_reset(state, 1);
    vterm_input_write(*vterm, "\x1b[?7h", 5); // NOLINT

    *vscreen = vterm_obtain_screen(*vterm);

    *pid = fork();
    if (*pid == 0) {
        close(*ptyFD);
        dup2(slaveFD, STDIN_FILENO);
        dup2(slaveFD, STDOUT_FILENO);
        close(slaveFD);
        execl("./loader", "loader", path, NULL);
        // execl("/home/kiraterin/playgroun d/ncursesplg/bin/main", path, NULL);

        // code below will be executed when execl failed
        LOG_ERROR("clientRunGame: cannot execute loader");
        _exit(SUBPROCESS_EXIT_NUM);
    }
    close(slaveFD);

    return CLIENT_SUCC;
}

void clientStopGame(VTerm **vterm, pid_t *pid, int *ptyFD) {
    close(*ptyFD);
    *ptyFD = -1;
    vterm_free(*vterm);
    *vterm = NULL;
    kill(*pid, SIGTERM);
    waitpid(*pid, NULL, 0);
    *pid = 0;
}
