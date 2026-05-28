/**
 * @file utils.c
 * @brief Implementation of general-purpose utility functions for PacPlay.
 *
 * @date 2026-05-24
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

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <termios.h>
#endif

/* ASCII DEL character (used for backspace on some terminals). */
#define ASCII_DEL 0x7F

time_t getCurrentTimestamp(void) { return time(NULL); }

size_t readPasswordMasked(char *buf, size_t bufsize) {
    if (buf == NULL || bufsize == 0) {
        return 0;
    }

    /* Not a terminal — fallback to plain fgets (e.g. piped input). */
    if (isatty(STDIN_FILENO) == 0) {
        if (fgets(buf, (int)bufsize, stdin) == NULL) {
            buf[0] = '\0';
            return 0;
        }
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
            len--;
        }
        return len;
    }

#ifdef __linux__
    struct termios oldTerm, newTerm;
    if (tcgetattr(STDIN_FILENO, &oldTerm) != 0) {
        buf[0] = '\0';
        return 0;
    }

    newTerm = oldTerm;
    /* Disable canonical mode (read byte-by-byte) and echo. */
    newTerm.c_lflag &= (tcflag_t)(~(ECHO | ICANON));
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
        buf[0] = '\0';
        return 0;
    }

    size_t pos = 0;
    for (;;) {
        char ch;
        ssize_t n = read(STDIN_FILENO, &ch, 1);
        if (n <= 0) {
            break; /* EOF or error */
        }

        /* Enter / newline — finish input. */
        if (ch == '\n' || ch == '\r') {
            break;
        }

        /* Backspace / DEL — erase last character. */
        if (ch == '\b' || ch == (char)ASCII_DEL) {
            if (pos > 0) {
                pos--;
                /* Erase the displayed '*': move left, space, move left. */
                const char eraseSeq[] = "\b \b";
                (void)!write(STDERR_FILENO, eraseSeq, sizeof(eraseSeq) - 1);
            }
            continue;
        }

        /* Regular character — store and echo '*'. */
        if (pos + 1 < bufsize) {
            buf[pos] = ch;
            pos++;
            const char asterisk = '*';
            (void)!write(STDERR_FILENO, &asterisk, 1);
        }
    }

    buf[pos] = '\0';

    /* Restore original terminal settings. */
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm);

    return pos;
#else
    /* Non-Linux fallback — plain fgets, no masking. */
    if (fgets(buf, (int)bufsize, stdin) == NULL) {
        buf[0] = '\0';
        return 0;
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        len--;
    }
    return len;
#endif
}
