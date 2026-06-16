#include "archive.h"
#include "microtar.h"
#include "platform.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WITH_GZFILEOP
#define WITH_GZFILEOP
#endif
#include <zlib-ng.h>

enum { GzBufSize = 65536, PathBufSize = 512 };

int extractTarGz(const char *tarGzPath, const char *destDir) {
    if (tarGzPath == NULL || destDir == NULL) {
        return ARCHIVE_FAIL;
    }

    gzFile gz = zng_gzopen(tarGzPath, "rb");
    if (gz == NULL) {
        return ARCHIVE_FAIL;
    }

    char tarPath[PathBufSize];
    (void)snprintf(tarPath, sizeof(tarPath), "%s/temp.tar", destDir);

    FILE *tarFile = fopen(tarPath, "wb");
    if (tarFile == NULL) {
        zng_gzclose(gz);
        return ARCHIVE_FAIL;
    }

    uint8_t buf[GzBufSize];
    int32_t bytesRead;
    while ((bytesRead = zng_gzread(gz, buf, sizeof(buf))) > 0) {
        if (fwrite(buf, 1, (size_t)bytesRead, tarFile) != (size_t)bytesRead) {
            fclose(tarFile);
            zng_gzclose(gz);
            remove(tarPath);
            return ARCHIVE_FAIL;
        }
    }
    fclose(tarFile);
    zng_gzclose(gz);

    mtar_t tar;
    if (mtar_open(&tar, tarPath, "r") != MTAR_ESUCCESS) {
        remove(tarPath);
        return ARCHIVE_FAIL;
    }

    mtar_header_t header;
    while (mtar_read_header(&tar, &header) == MTAR_ESUCCESS) {
        if (header.type == MTAR_TDIR) {
            char dirPath[PathBufSize];
            (void)snprintf(dirPath, sizeof(dirPath), "%s/%s", destDir,
                           header.name);
            platformMkdirp(dirPath);
        } else if (header.type == MTAR_TREG) {
            char filePath[PathBufSize];
            (void)snprintf(filePath, sizeof(filePath), "%s/%s", destDir,
                           header.name);

            void *data = malloc(header.size);
            if (data == NULL) {
                mtar_close(&tar);
                remove(tarPath);
                return ARCHIVE_FAIL;
            }

            if (mtar_read_data(&tar, data, header.size) != MTAR_ESUCCESS) {
                free(data);
                mtar_close(&tar);
                remove(tarPath);
                return ARCHIVE_FAIL;
            }

            FILE *outFile = fopen(filePath, "wb");
            if (outFile == NULL) {
                free(data);
                mtar_close(&tar);
                remove(tarPath);
                return ARCHIVE_FAIL;
            }
            fwrite(data, 1, header.size, outFile);
            fclose(outFile);
            free(data);
        }
        mtar_next(&tar);
    }

    mtar_close(&tar);
    remove(tarPath);
    return ARCHIVE_SUCC;
}
