/**
 * @file main.c
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

#include "loader.h"
#include "log.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

GameFunctions gameFunctions;

int main(int argc, const char *argv[]) {
    setenv("TERM", "xterm-256color", 1);

    if (argc != 2) {
        LOG_ERROR("loader: invalid argument count");
        return EXIT_FAILURE;
    }

    void *handle = dlopen(argv[1], RTLD_LAZY);

    if (!handle) {
        char cwd[PATH_MAX];
        LOG_ERROR("loader: cannot open game shared object: %s", argv[1]);
        LOG_ERROR("dlopen failed: %s", dlerror());
        LOG_ERROR("pwd: %s", getcwd(cwd, PATH_MAX));
        return EXIT_FAILURE;
    }

    gameFunctions.pacplayMain = (void (*)())dlsym(handle, "pacplayMain");

    if (gameFunctions.pacplayMain == NULL) {
        LOG_ERROR("loader: cannot find symbol 'pacplayMain' in %s", argv[1]);
    }

    gameFunctions.pacplayMain();

    usleep(10000000); // NOLINT
    dlclose(handle);
    return EXIT_SUCCESS;
}