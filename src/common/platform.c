#include "platform.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

enum { PathBufSize = 4096 };
enum { MkdirMode = 0755 };

int platformMkdtemp(char *tmpl, size_t tmplSize) {
    if (tmpl == NULL || tmplSize == 0) {
        return PLATFORM_FAIL;
    }
#ifdef _WIN32
    char tmpPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmpPath) == 0) {
        return PLATFORM_FAIL;
    }
    size_t len = strlen(tmpl);
    enum { SUFFIX_LEN = 6 };
    if (len < SUFFIX_LEN) {
        return PLATFORM_FAIL;
    }
    srand((unsigned)GetTickCount());
    for (int i = 0; i < SUFFIX_LEN; i++) {
        tmpl[len - SUFFIX_LEN + i] =
            (char)('a' + (rand() % 26)); // NOLINT(cert-msc30-c,cert-msc50-cpp)
    }
    if (!CreateDirectoryA(tmpl, NULL)) {
        return PLATFORM_FAIL;
    }
    return PLATFORM_SUCC;
#else
    (void)tmplSize;
    if (mkdtemp(tmpl) == NULL) {
        return PLATFORM_FAIL;
    }
    return PLATFORM_SUCC;
#endif
}

int platformFileSize(const char *path, uint64_t *outSize) {
    if (path == NULL || outSize == NULL) {
        return PLATFORM_FAIL;
    }
#ifdef _WIN32
    struct _stat64 st;
    if (_stat64(path, &st) != 0) {
        return PLATFORM_FAIL;
    }
    *outSize = (uint64_t)st.st_size;
#else
    struct stat st;
    if (stat(path, &st) != 0) {
        return PLATFORM_FAIL;
    }
    *outSize = (uint64_t)st.st_size;
#endif
    return PLATFORM_SUCC;
}

int platformMkdirp(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return PLATFORM_FAIL;
    }

    char buf[PathBufSize];
    size_t len = strlen(path);
    if (len >= PathBufSize) {
        return PLATFORM_FAIL;
    }
    memcpy(buf, path, len + 1);

    for (size_t i = 1; i <= len; i++) {
        if (buf[i] == '/' || buf[i] == '\0') {
            char saved = buf[i];
            buf[i] = '\0';

            if (PLATFORM_MKDIR(buf, MkdirMode) != 0) {
                if (errno != EEXIST) {
                    return PLATFORM_FAIL;
                }
            }

            buf[i] = saved;
        }
    }
    return PLATFORM_SUCC;
}

#ifndef _WIN32
static int platformRmrfRecurse(const char *path) {
    DIR *dir = opendir(path);
    if (dir == NULL) {
        return PLATFORM_FAIL;
    }

    struct dirent *entry;
    char childPath[PathBufSize];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        int written =
            snprintf(childPath, sizeof(childPath), "%s/%s", path, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(childPath)) {
            closedir(dir);
            return PLATFORM_FAIL;
        }

        struct stat st;
        if (lstat(childPath, &st) != 0) {
            closedir(dir);
            return PLATFORM_FAIL;
        }

        if (S_ISDIR(st.st_mode)) {
            if (platformRmrfRecurse(childPath) != PLATFORM_SUCC) {
                closedir(dir);
                return PLATFORM_FAIL;
            }
        } else {
            if (unlink(childPath) != 0) {
                closedir(dir);
                return PLATFORM_FAIL;
            }
        }
    }

    closedir(dir);
    if (rmdir(path) != 0) {
        return PLATFORM_FAIL;
    }
    return PLATFORM_SUCC;
}
#endif

int platformRmrf(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return PLATFORM_FAIL;
    }
#ifdef _WIN32
    char searchPath[PathBufSize];
    int written =
        snprintf(searchPath, sizeof(searchPath), "%s\\*", path);
    if (written < 0 || (size_t)written >= sizeof(searchPath)) {
        return PLATFORM_FAIL;
    }

    struct _finddata_t findData;
    intptr_t handle = _findfirst(searchPath, &findData);
    if (handle == -1) {
        return PLATFORM_FAIL;
    }

    char childPath[PathBufSize];
    do {
        if (strcmp(findData.name, ".") == 0 ||
            strcmp(findData.name, "..") == 0) {
            continue;
        }

        written = snprintf(childPath, sizeof(childPath), "%s\\%s", path,
                           findData.name);
        if (written < 0 || (size_t)written >= sizeof(childPath)) {
            _findclose(handle);
            return PLATFORM_FAIL;
        }

        if (findData.attrib & _A_SUBDIR) {
            if (platformRmrf(childPath) != PLATFORM_SUCC) {
                _findclose(handle);
                return PLATFORM_FAIL;
            }
        } else {
            if (!DeleteFileA(childPath)) {
                _findclose(handle);
                return PLATFORM_FAIL;
            }
        }
    } while (_findnext(handle, &findData) == 0);

    _findclose(handle);
    if (!RemoveDirectoryA(path)) {
        return PLATFORM_FAIL;
    }
    return PLATFORM_SUCC;
#else
    return platformRmrfRecurse(path);
#endif
}
