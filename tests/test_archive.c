#include "test_utils.h"

#include "archive.h"
#include "microtar.h"
#include "platform.h"

#ifndef WITH_GZFILEOP
#define WITH_GZFILEOP
#endif
#include <zlib-ng.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { TmplBufSize = 256 };
enum { PathBufSize = 512 };
enum { BigPathBufSize = 1024 };
enum { GzBufSize = 65536 };
enum { FileContentSize = 4096 };
enum { MaxFileNameLen = 99 };
enum { FileCountRoundTrip = 4 };
enum { TypicalFileSize = 256 };
enum { ContentByteRange = 256 };
enum { ContentSeedMultiplier = 64 };

static int writeFile(const char *path, const char *content, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return ARCHIVE_FAIL;
    }
    size_t written = fwrite(content, 1, len, fp);
    fclose(fp);
    if (written != len) {
        return ARCHIVE_FAIL;
    }
    return ARCHIVE_SUCC;
}

static int fileExists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int fileSizeEq(const char *path, size_t expected) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return (size_t)st.st_size == expected;
}

static int readWholeFile(const char *path, char *buf, size_t bufSize,
                         size_t *outLen) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return ARCHIVE_FAIL;
    }
    size_t n = fread(buf, 1, bufSize - 1, fp);
    int readErr = ferror(fp);
    fclose(fp);
    if (readErr) {
        return ARCHIVE_FAIL;
    }
    buf[n] = '\0';
    if (outLen != NULL) {
        *outLen = n;
    }
    return ARCHIVE_SUCC;
}

static int createMaliciousTgz(const char *destPath) {
    char tarPath[PathBufSize];
    (void)snprintf(tarPath, sizeof(tarPath), "%s.tmp.tar", destPath);

    mtar_t tar;
    if (mtar_open(&tar, tarPath, "w") != MTAR_ESUCCESS) {
        return ARCHIVE_FAIL;
    }

    (void)mtar_write_dir_header(&tar, "foo");

    const char *evilName = "../../etc/evil";
    const char *evilContent = "pwned";
    unsigned evilSize = (unsigned)strlen(evilContent);

    if (mtar_write_file_header(&tar, evilName, evilSize) != MTAR_ESUCCESS) {
        mtar_close(&tar);
        (void)remove(tarPath);
        return ARCHIVE_FAIL;
    }
    if (mtar_write_data(&tar, evilContent, evilSize) != MTAR_ESUCCESS) {
        mtar_close(&tar);
        (void)remove(tarPath);
        return ARCHIVE_FAIL;
    }

    if (mtar_finalize(&tar) != MTAR_ESUCCESS) {
        mtar_close(&tar);
        (void)remove(tarPath);
        return ARCHIVE_FAIL;
    }
    mtar_close(&tar);

    gzFile gz = zng_gzopen(destPath, "wb");
    if (gz == NULL) {
        (void)remove(tarPath);
        return ARCHIVE_FAIL;
    }

    FILE *tarFile = fopen(tarPath, "rb");
    if (tarFile == NULL) {
        zng_gzclose(gz);
        (void)remove(tarPath);
        return ARCHIVE_FAIL;
    }

    uint8_t buf[GzBufSize];
    int bytesRead;
    while ((bytesRead = (int)fread(buf, 1, sizeof(buf), tarFile)) > 0) {
        if (zng_gzwrite(gz, buf, (unsigned)bytesRead) != bytesRead) {
            fclose(tarFile);
            zng_gzclose(gz);
            (void)remove(tarPath);
            return ARCHIVE_FAIL;
        }
    }
    fclose(tarFile);
    zng_gzclose(gz);
    (void)remove(tarPath);

    return ARCHIVE_SUCC;
}

static void test_path_traversal_rejection(void) {
    char tmpl[TmplBufSize];
    (void)snprintf(tmpl, sizeof(tmpl), "/tmp/pacplay_arctest_XXXXXX");
    int ret = platformMkdtemp(tmpl, sizeof(tmpl));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char destDir[PathBufSize];
    (void)snprintf(destDir, sizeof(destDir), "%s/sub/level/dst", tmpl);
    ret = platformMkdirp(destDir);
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char tgzPath[PathBufSize];
    (void)snprintf(tgzPath, sizeof(tgzPath), "%s/evil.tar.gz", tmpl);

    ret = createMaliciousTgz(tgzPath);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
    ASSERT_TRUE(fileExists(tgzPath));

    int extractRet = extractTarGz(tgzPath, destDir);
    ASSERT_INT_EQ(extractRet, ARCHIVE_FAIL);

    /* Verify the evil file was NOT created at the traversed location.
     * destDir = .../sub/level/dst, evilName = ../../etc/evil
     * resolved = .../sub/etc/evil */
    char traversedPath[PathBufSize];
    (void)snprintf(traversedPath, sizeof(traversedPath), "%s/sub/etc/evil",
                   tmpl);
    ASSERT_FALSE(fileExists(traversedPath));

    /* Also verify it was not created inside destDir */
    char insideDest[BigPathBufSize];
    (void)snprintf(insideDest, sizeof(insideDest), "%s/evil", destDir);
    ASSERT_FALSE(fileExists(insideDest));

    platformRmrf(tmpl);
}

static void test_normal_extraction(void) {
    char src[TmplBufSize];
    (void)snprintf(src, sizeof(src), "/tmp/pacplay_arcsrc_XXXXXX");
    int ret = platformMkdtemp(src, sizeof(src));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char dst[TmplBufSize];
    (void)snprintf(dst, sizeof(dst), "/tmp/pacplay_arcdst_XXXXXX");
    ret = platformMkdtemp(dst, sizeof(dst));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    const char *fileNames[] = {"alpha.txt", "beta.txt", "gamma.txt"};
    const char *contents[] = {"hello world", "lorem ipsum dolor", "0123456789"};
    enum { FileCount = 3 };

    for (int i = 0; i < FileCount; i++) {
        char filePath[PathBufSize];
        (void)snprintf(filePath, sizeof(filePath), "%s/%s", src, fileNames[i]);
        ret = writeFile(filePath, contents[i], strlen(contents[i]));
        ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
    }

    char tgzPath[PathBufSize];
    (void)snprintf(tgzPath, sizeof(tgzPath), "%s/normal.tar.gz", src);
    ret = createTarGz(src, tgzPath);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
    ASSERT_TRUE(fileExists(tgzPath));

    ret = extractTarGz(tgzPath, dst);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    for (int i = 0; i < FileCount; i++) {
        char extractedPath[PathBufSize];
        (void)snprintf(extractedPath, sizeof(extractedPath), "%s/%s", dst,
                       fileNames[i]);
        ASSERT_TRUE(fileExists(extractedPath));

        char buf[FileContentSize];
        size_t outLen = 0;
        ret = readWholeFile(extractedPath, buf, sizeof(buf), &outLen);
        ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
        ASSERT_UINT_EQ(outLen, strlen(contents[i]));
        ASSERT_STR_EQ(buf, contents[i]);
    }

    platformRmrf(src);
    platformRmrf(dst);
}

static void test_round_trip(void) {
    char src[TmplBufSize];
    (void)snprintf(src, sizeof(src), "/tmp/pacplay_arort_XXXXXX");
    int ret = platformMkdtemp(src, sizeof(src));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char dst[TmplBufSize];
    (void)snprintf(dst, sizeof(dst), "/tmp/pacplay_arodt_XXXXXX");
    ret = platformMkdtemp(dst, sizeof(dst));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    /* File with varied sizes: empty, 1-byte, typical, large-ish */
    const char *fileNames[FileCountRoundTrip] = {"zero.dat", "one.dat", "typ.dat",
                                           "large.dat"};
    size_t fileSizes[FileCountRoundTrip] = {0, 1, TypicalFileSize, FileContentSize};

    /* Generate deterministically varied content */
    char contentBuf[FileContentSize];
    for (int i = 0; i < FileCountRoundTrip; i++) {
        size_t sz = fileSizes[i];
        for (size_t j = 0; j < sz; j++) {
            contentBuf[j] = (char)((i * ContentSeedMultiplier + j) % ContentByteRange);
        }
        char filePath[PathBufSize];
        (void)snprintf(filePath, sizeof(filePath), "%s/%s", src, fileNames[i]);
        ret = writeFile(filePath, contentBuf, sz);
        ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
    }

    char tgzPath[PathBufSize];
    (void)snprintf(tgzPath, sizeof(tgzPath), "%s/roundtrip.tar.gz", src);
    ret = createTarGz(src, tgzPath);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    ret = extractTarGz(tgzPath, dst);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    /* Rebuild original content and compare byte-for-byte */
    for (int i = 0; i < FileCountRoundTrip; i++) {
        size_t sz = fileSizes[i];
        char expected[FileContentSize];
        for (size_t j = 0; j < sz; j++) {
            expected[j] = (char)((i * ContentSeedMultiplier + j) % ContentByteRange);
        }

        char extractedPath[PathBufSize];
        (void)snprintf(extractedPath, sizeof(extractedPath), "%s/%s", dst,
                       fileNames[i]);
        ASSERT_TRUE(fileExists(extractedPath));

        char actualBuf[FileContentSize + 1];
        size_t outLen = 0;
        ret = readWholeFile(extractedPath, actualBuf, sizeof(actualBuf),
                            &outLen);
        ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
        ASSERT_UINT_EQ(outLen, sz);
        ASSERT_MEM_EQ(actualBuf, expected, sz);
    }

    platformRmrf(src);
    platformRmrf(dst);
}

static void test_empty_archive(void) {
    char src[TmplBufSize];
    (void)snprintf(src, sizeof(src), "/tmp/pacplay_arem_XXXXXX");
    int ret = platformMkdtemp(src, sizeof(src));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char dst[TmplBufSize];
    (void)snprintf(dst, sizeof(dst), "/tmp/pacplay_ared_XXXXXX");
    ret = platformMkdtemp(dst, sizeof(dst));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char tgzPath[PathBufSize];
    (void)snprintf(tgzPath, sizeof(tgzPath), "%s/empty.tar.gz", src);
    ret = createTarGz(src, tgzPath);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
    ASSERT_TRUE(fileExists(tgzPath));

    ret = extractTarGz(tgzPath, dst);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    platformRmrf(src);
    platformRmrf(dst);
}

static void test_null_params(void) {
    ASSERT_INT_EQ(extractTarGz(NULL, "/tmp"), ARCHIVE_FAIL);
    ASSERT_INT_EQ(extractTarGz("/tmp", NULL), ARCHIVE_FAIL);
    ASSERT_INT_EQ(createTarGz(NULL, "/tmp"), ARCHIVE_FAIL);
    ASSERT_INT_EQ(createTarGz("/tmp", NULL), ARCHIVE_FAIL);
}

static void test_nonexistent_source(void) {
    char dst[TmplBufSize];
    (void)snprintf(dst, sizeof(dst), "/tmp/pacplay_arnx_XXXXXX");
    int ret = platformMkdtemp(dst, sizeof(dst));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    int extractRet = extractTarGz("/tmp/no_such_archive_pacplay.tar.gz", dst);
    ASSERT_INT_EQ(extractRet, ARCHIVE_FAIL);

    platformRmrf(dst);
}

static void test_nonexistent_dest(void) {
    char src[TmplBufSize];
    (void)snprintf(src, sizeof(src), "/tmp/pacplay_arnds_XXXXXX");
    int ret = platformMkdtemp(src, sizeof(src));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char filePath[PathBufSize];
    (void)snprintf(filePath, sizeof(filePath), "%s/data.txt", src);
    ret = writeFile(filePath, "content", strlen("content"));
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    char tgzPath[PathBufSize];
    (void)snprintf(tgzPath, sizeof(tgzPath), "%s/test.tar.gz", src);
    ret = createTarGz(src, tgzPath);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    int extractRet = extractTarGz(tgzPath, "/tmp/no_such_dir_pacplay_xyz");
    ASSERT_INT_EQ(extractRet, ARCHIVE_FAIL);

    platformRmrf(src);
}

static void test_large_filename(void) {
    char src[TmplBufSize];
    (void)snprintf(src, sizeof(src), "/tmp/pacplay_arlf_XXXXXX");
    int ret = platformMkdtemp(src, sizeof(src));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char dst[TmplBufSize];
    (void)snprintf(dst, sizeof(dst), "/tmp/pacplay_arld_XXXXXX");
    ret = platformMkdtemp(dst, sizeof(dst));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    /* 99-char filename (`name[100]` in ustar header, max 99 + null) */
    char longName[MaxFileNameLen + 1];
    (void)memset(longName, 'x', MaxFileNameLen);
    longName[MaxFileNameLen] = '\0';

    char filePath[PathBufSize];
    (void)snprintf(filePath, sizeof(filePath), "%s/%s", src, longName);
    const char *content = "data in a long-named file";
    ret = writeFile(filePath, content, strlen(content));
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    char tgzPath[PathBufSize];
    (void)snprintf(tgzPath, sizeof(tgzPath), "%s/longname.tar.gz", src);
    ret = createTarGz(src, tgzPath);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    ret = extractTarGz(tgzPath, dst);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    char extractedPath[PathBufSize];
    (void)snprintf(extractedPath, sizeof(extractedPath), "%s/%s", dst,
                   longName);
    ASSERT_TRUE(fileExists(extractedPath));

    char buf[FileContentSize];
    size_t outLen = 0;
    ret = readWholeFile(extractedPath, buf, sizeof(buf), &outLen);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
    ASSERT_UINT_EQ(outLen, strlen(content));
    ASSERT_STR_EQ(buf, content);

    platformRmrf(src);
    platformRmrf(dst);
}

static void test_zero_size_file(void) {
    char src[TmplBufSize];
    (void)snprintf(src, sizeof(src), "/tmp/pacplay_arzf_XXXXXX");
    int ret = platformMkdtemp(src, sizeof(src));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char dst[TmplBufSize];
    (void)snprintf(dst, sizeof(dst), "/tmp/pacplay_arzd_XXXXXX");
    ret = platformMkdtemp(dst, sizeof(dst));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char filePath[PathBufSize];
    (void)snprintf(filePath, sizeof(filePath), "%s/empty.dat", src);
    ret = writeFile(filePath, "", 0);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);
    ASSERT_TRUE(fileExists(filePath));

    char tgzPath[PathBufSize];
    (void)snprintf(tgzPath, sizeof(tgzPath), "%s/zerosize.tar.gz", src);
    ret = createTarGz(src, tgzPath);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    ret = extractTarGz(tgzPath, dst);
    ASSERT_INT_EQ(ret, ARCHIVE_SUCC);

    char extractedPath[PathBufSize];
    (void)snprintf(extractedPath, sizeof(extractedPath), "%s/empty.dat", dst);
    ASSERT_TRUE(fileExists(extractedPath));
    ASSERT_TRUE(fileSizeEq(extractedPath, 0));

    platformRmrf(src);
    platformRmrf(dst);
}

int main(void) {
    RUN_TEST(test_path_traversal_rejection);
    RUN_TEST(test_normal_extraction);
    RUN_TEST(test_round_trip);
    RUN_TEST(test_empty_archive);
    RUN_TEST(test_null_params);
    RUN_TEST(test_nonexistent_source);
    RUN_TEST(test_nonexistent_dest);
    RUN_TEST(test_large_filename);
    RUN_TEST(test_zero_size_file);
    return TEST_REPORT();
}
