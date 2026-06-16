#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#define PLATFORM_SUCC (0)
#define PLATFORM_FAIL (-1)

int platformMkdtemp(char *tmpl, size_t tmplSize);
int platformFileSize(const char *path, uint64_t *outSize);
int platformMkdirp(const char *path);
int platformRmrf(const char *path);

#endif
