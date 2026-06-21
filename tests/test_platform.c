#include "test_utils.h"

#include "platform.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { TestFileSize = 1024 };
enum { TmplBufSize = 256 };

static void test_mkdtemp_creates_directory(void) {
    char tmpl[TmplBufSize];
    snprintf(tmpl, sizeof(tmpl), "/tmp/pacplay_test_XXXXXX");

    int ret = platformMkdtemp(tmpl, sizeof(tmpl));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    struct stat st;
    int exists = stat(tmpl, &st);
    ASSERT_INT_EQ(exists, 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));

    platformRmrf(tmpl);
}

static void test_file_size_regular_file(void) {
    char tmpl[TmplBufSize];
    snprintf(tmpl, sizeof(tmpl), "/tmp/pacplay_fsize_XXXXXX");
    int ret = platformMkdtemp(tmpl, sizeof(tmpl));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char filePath[TmplBufSize];
    snprintf(filePath, sizeof(filePath), "%s/testfile.bin", tmpl);

    FILE *fp = fopen(filePath, "wb");
    ASSERT_TRUE(fp != NULL);

    char buf[TestFileSize];
    memset(buf, 'A', sizeof(buf));
    size_t written = fwrite(buf, 1, sizeof(buf), fp);
    ASSERT_UINT_EQ(written, TestFileSize);
    fclose(fp);

    uint64_t outSize = 0;
    ret = platformFileSize(filePath, &outSize);
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);
    ASSERT_UINT_EQ(outSize, TestFileSize);

    platformRmrf(tmpl);
}

static void test_file_size_nonexistent(void) {
    uint64_t outSize = 0;
    int ret = platformFileSize("/tmp/nonexistent_pacplay_xyz", &outSize);
    ASSERT_INT_EQ(ret, PLATFORM_FAIL);
}

static void test_mkdirp_nested(void) {
    char tmpl[TmplBufSize];
    snprintf(tmpl, sizeof(tmpl), "/tmp/pacplay_mkdirp_XXXXXX");
    int ret = platformMkdtemp(tmpl, sizeof(tmpl));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char nested[TmplBufSize];
    snprintf(nested, sizeof(nested), "%s/a/b/c", tmpl);

    ret = platformMkdirp(nested);
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    struct stat st;
    ASSERT_INT_EQ(stat(nested, &st), 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));

    char mid[TmplBufSize];
    snprintf(mid, sizeof(mid), "%s/a/b", tmpl);
    ASSERT_INT_EQ(stat(mid, &st), 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));

    snprintf(mid, sizeof(mid), "%s/a", tmpl);
    ASSERT_INT_EQ(stat(mid, &st), 0);
    ASSERT_TRUE(S_ISDIR(st.st_mode));

    platformRmrf(tmpl);
}

static void test_mkdirp_existing(void) {
    char tmpl[TmplBufSize];
    snprintf(tmpl, sizeof(tmpl), "/tmp/pacplay_exist_XXXXXX");
    int ret = platformMkdtemp(tmpl, sizeof(tmpl));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    ret = platformMkdirp(tmpl);
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    platformRmrf(tmpl);
}

static void test_rmrf_directory_tree(void) {
    char tmpl[TmplBufSize];
    snprintf(tmpl, sizeof(tmpl), "/tmp/pacplay_rmrf_XXXXXX");
    int ret = platformMkdtemp(tmpl, sizeof(tmpl));
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char nested[TmplBufSize];
    snprintf(nested, sizeof(nested), "%s/x/y", tmpl);
    ret = platformMkdirp(nested);
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    char filePath[TmplBufSize];
    snprintf(filePath, sizeof(filePath), "%s/x/y/data.txt", tmpl);
    FILE *fp = fopen(filePath, "w");
    ASSERT_TRUE(fp != NULL);
    fprintf(fp, "hello");
    fclose(fp);

    snprintf(filePath, sizeof(filePath), "%s/x/top.txt", tmpl);
    fp = fopen(filePath, "w");
    ASSERT_TRUE(fp != NULL);
    fprintf(fp, "world");
    fclose(fp);

    ret = platformRmrf(tmpl);
    ASSERT_INT_EQ(ret, PLATFORM_SUCC);

    struct stat st;
    ASSERT_INT_EQ(stat(tmpl, &st), -1);
}

static void test_rmrf_nonexistent(void) {
    int ret = platformRmrf("/tmp/nonexistent_pacplay_rmrf_xyz");
    ASSERT_INT_EQ(ret, PLATFORM_FAIL);
}

int main(void) {
    RUN_TEST(test_mkdtemp_creates_directory);
    RUN_TEST(test_file_size_regular_file);
    RUN_TEST(test_file_size_nonexistent);
    RUN_TEST(test_mkdirp_nested);
    RUN_TEST(test_mkdirp_existing);
    RUN_TEST(test_rmrf_directory_tree);
    RUN_TEST(test_rmrf_nonexistent);
    return TEST_REPORT();
}
