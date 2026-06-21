#include "archive.h"
#include "log.h"
#include "microtar.h"
#include "platform.h"

#include <dirent.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
        if (strstr(header.name, "..") != NULL) {
            LOG_ERROR("extractTarGz: path traversal detected: %s",
                      header.name);
            mtar_close(&tar);
            remove(tarPath);
            return ARCHIVE_FAIL;
        }
        if (header.type == MTAR_TDIR) {
            char dirPath[PathBufSize];
            (void)snprintf(dirPath, sizeof(dirPath), "%s/%s", destDir,
                           header.name);
            platformMkdirp(dirPath);
        } else if (header.type == MTAR_TREG) {
            char filePath[PathBufSize];
            (void)snprintf(filePath, sizeof(filePath), "%s/%s", destDir,
                           header.name);

            if (header.size == 0) {
                FILE *emptyFile = fopen(filePath, "wb");
                if (emptyFile == NULL) {
                    mtar_close(&tar);
                    remove(tarPath);
                    return ARCHIVE_FAIL;
                }
                fclose(emptyFile);
                mtar_next(&tar);
                continue;
            }

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
            size_t written =
                fwrite(data, 1, header.size, outFile);
            if (written != header.size) {
                LOG_ERROR("extractTarGz: write failed for %s", filePath);
                free(data);
                fclose(outFile);
                mtar_close(&tar);
                remove(tarPath);
                return ARCHIVE_FAIL;
            }

            fclose(outFile);
            free(data);
        }
        mtar_next(&tar);
    }

    mtar_close(&tar);
    remove(tarPath);
    return ARCHIVE_SUCC;
}

static int addEntryToTar(mtar_t *tar, const char *baseDir,
                         const char *relPath) {
    char fullPath[PathBufSize];
    snprintf(fullPath, sizeof(fullPath), "%s/%s", baseDir, relPath);

    struct stat st;
    if (stat(fullPath, &st) != 0) {
        return ARCHIVE_FAIL;
    }

    if (S_ISDIR(st.st_mode)) {
        if (mtar_write_dir_header(tar, relPath) != MTAR_ESUCCESS) {
            return ARCHIVE_FAIL;
        }

        DIR *dir = opendir(fullPath);
        if (dir == NULL) {
            return ARCHIVE_FAIL;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char childRel[PathBufSize];
            snprintf(childRel, sizeof(childRel), "%s/%s", relPath,
                     entry->d_name);
            if (addEntryToTar(tar, baseDir, childRel) != ARCHIVE_SUCC) {
                closedir(dir);
                return ARCHIVE_FAIL;
            }
        }
        closedir(dir);
    } else if (S_ISREG(st.st_mode)) {
        if (st.st_size > (off_t)UINT_MAX) {
            LOG_ERROR("createTarGz: file too large: %s", relPath);
            return ARCHIVE_FAIL;
        }
        if (mtar_write_file_header(tar, relPath,
                                   (unsigned)st.st_size) != MTAR_ESUCCESS) {
            return ARCHIVE_FAIL;
        }

        FILE *fp = fopen(fullPath, "rb");
        if (fp == NULL) {
            return ARCHIVE_FAIL;
        }

        uint8_t buf[GzBufSize];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
            if (mtar_write_data(tar, buf, (unsigned)n) != MTAR_ESUCCESS) {
                fclose(fp);
                return ARCHIVE_FAIL;
            }
        }
        fclose(fp);
    }

    return ARCHIVE_SUCC;
}

int createTarGz(const char *sourceDir, const char *destPath) {
    if (sourceDir == NULL || destPath == NULL) {
        return ARCHIVE_FAIL;
    }

    char tarPath[PathBufSize];
    snprintf(tarPath, sizeof(tarPath), "%s.tmp.tar", destPath);

    mtar_t tar;
    if (mtar_open(&tar, tarPath, "w") != MTAR_ESUCCESS) {
        return ARCHIVE_FAIL;
    }

    DIR *dir = opendir(sourceDir);
    if (dir == NULL) {
        mtar_close(&tar);
        remove(tarPath);
        return ARCHIVE_FAIL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (addEntryToTar(&tar, sourceDir,
                          entry->d_name) != ARCHIVE_SUCC) {
            closedir(dir);
            mtar_close(&tar);
            remove(tarPath);
            return ARCHIVE_FAIL;
        }
    }
    closedir(dir);

    if (mtar_finalize(&tar) != MTAR_ESUCCESS) {
        mtar_close(&tar);
        remove(tarPath);
        return ARCHIVE_FAIL;
    }
    mtar_close(&tar);

    gzFile gz = zng_gzopen(destPath, "wb");
    if (gz == NULL) {
        remove(tarPath);
        return ARCHIVE_FAIL;
    }

    FILE *tarFile = fopen(tarPath, "rb");
    if (tarFile == NULL) {
        zng_gzclose(gz);
        remove(tarPath);
        return ARCHIVE_FAIL;
    }

    uint8_t buf[GzBufSize];
    int bytesRead;
    while ((bytesRead = (int)fread(buf, 1, sizeof(buf), tarFile)) > 0) {
        if (zng_gzwrite(gz, buf, (unsigned)bytesRead) != bytesRead) {
            fclose(tarFile);
            zng_gzclose(gz);
            remove(tarPath);
            return ARCHIVE_FAIL;
        }
    }
    fclose(tarFile);
    zng_gzclose(gz);
    remove(tarPath);

    return ARCHIVE_SUCC;
}
