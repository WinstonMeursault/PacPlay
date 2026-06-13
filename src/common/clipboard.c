/**
 * @file clipboard.c
 * @brief Clipboard implementation using OSC 52 escape sequences with Base64
 *        encoding. Writes directly to /dev/tty to avoid conflicts with ncurses.
 *
 * @date 2026-06-11
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

#include "clipboard.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    B64BytesPerGroup = 3,
    B64CharsPerGroup = 4,
    B64Shift16 = 16,
    B64Shift8 = 8,
    B64Shift18 = 18,
    B64Shift12 = 12,
    B64Shift6 = 6,
    B64Mask6 = 0x3F,
    B64PadOne = 1,
    B64PadTwo = 2
};

static const char gBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static FILE *gTtyFile;

bool clipboardInit(void) {
    gTtyFile = fopen("/dev/tty", "w");
    return gTtyFile != NULL;
}

void clipboardDeinit(void) {
    if (gTtyFile != NULL) {
        fclose(gTtyFile);
        gTtyFile = NULL;
    }
}

void clipboardWriteRaw(const char *data) {
    if (data == NULL || gTtyFile == NULL) {
        return;
    }
    fputs(data, gTtyFile);
    fflush(gTtyFile);
}

void clipboardCopy(const char *text) {
    size_t len;
    size_t padCount;
    size_t outLen;
    size_t i;
    size_t j;
    char *b64;

    if (text == NULL || gTtyFile == NULL) {
        return;
    }
    len = strlen(text);
    if (len == 0) {
        return;
    }

    outLen = B64CharsPerGroup * ((len + B64BytesPerGroup) / B64BytesPerGroup);
    b64 = malloc(outLen + 1);
    if (b64 == NULL) {
        return;
    }

    i = 0;
    j = 0;
    while (i < len) {
        uint8_t a;
        uint8_t b;
        uint8_t c;
        uint32_t triple;

        a = (uint8_t)text[i++];
        b = (i < len) ? (uint8_t)text[i++] : 0;
        c = (i < len) ? (uint8_t)text[i++] : 0;
        triple = ((uint32_t)a << B64Shift16) | ((uint32_t)b << B64Shift8) | c;

        b64[j++] = gBase64Alphabet[(triple >> B64Shift18) & B64Mask6];
        b64[j++] = gBase64Alphabet[(triple >> B64Shift12) & B64Mask6];
        b64[j++] = gBase64Alphabet[(triple >> B64Shift6) & B64Mask6];
        b64[j++] = gBase64Alphabet[triple & B64Mask6];
    }

    padCount = (B64BytesPerGroup - (len % B64BytesPerGroup)) % B64BytesPerGroup;
    if (padCount >= B64PadOne) {
        b64[outLen - 1] = '=';
    }
    if (padCount >= B64PadTwo) {
        b64[outLen - 2] = '=';
    }
    b64[outLen] = '\0';

    fprintf(gTtyFile, "\033]52;c;%s\a", b64);
    fflush(gTtyFile);

    free(b64);
}
