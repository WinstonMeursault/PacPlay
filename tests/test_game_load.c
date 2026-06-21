#include "test_utils.h"

#include "client/client.h"
#include "client/gameLoad.h"
#include "platform.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    PathBufSize = 512,
    TestVtermHeight = 24,
    TestVtermWidth = 80,
    SuccessExitCode = 0,
    InvalidFd = -1,
    WaitFailed = -1
};

static const char *expectedGamePath = "/tmp/pacplay_fake_game.so";

static void testClientRunGamePassesGamePathToLoader(void) {
    char oldCwd[PATH_MAX];
    char tmpDir[PathBufSize] = "/tmp/pacplay_load_XXXXXX";
    char loaderPath[PathBufSize];
    VTerm *vterm = NULL;
    VTermScreen *vscreen = NULL;
    pid_t pid = (pid_t)0;
    int ptyFD = InvalidFd;
    int status = 0;
    pid_t waited;

    ASSERT_TRUE(getcwd(oldCwd, sizeof(oldCwd)) != NULL);
    ASSERT_INT_EQ(platformMkdtemp(tmpDir, sizeof(tmpDir)), PLATFORM_SUCC);

    (void)snprintf(loaderPath, sizeof(loaderPath), "%s/loader", tmpDir);
    FILE *fp = fopen(loaderPath, "w");
    ASSERT_TRUE(fp != NULL);
    (void)fprintf(fp,
                  "#!/bin/sh\n"
                  "if [ \"$1\" = \"%s\" ]; then\n"
                  "    exit 0\n"
                  "fi\n"
                  "exit 42\n",
                  expectedGamePath);
    fclose(fp);
    ASSERT_INT_EQ(chmod(loaderPath, S_IRWXU), SuccessExitCode);

    ASSERT_INT_EQ(chdir(tmpDir), SuccessExitCode);
    ASSERT_INT_EQ(clientRunGame(&vterm, &vscreen, expectedGamePath,
                                TestVtermHeight, TestVtermWidth, &pid, &ptyFD),
                  CLIENT_SUCC);

    waited = waitpid(pid, &status, 0);

    if (ptyFD != InvalidFd) {
        close(ptyFD);
    }
    if (vterm != NULL) {
        vterm_free(vterm);
    }
    ASSERT_INT_EQ(chdir(oldCwd), SuccessExitCode);
    platformRmrf(tmpDir);

    ASSERT_TRUE(waited != (pid_t)WaitFailed);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_INT_EQ(WEXITSTATUS(status), SuccessExitCode);
}

int main(void) {
    RUN_TEST(testClientRunGamePassesGamePathToLoader);
    return TEST_REPORT();
}
