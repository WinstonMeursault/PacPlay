#include "server/gameRunner.h"

#include "log.h"
#include "pacplay_sdk.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    Server *s;
    char *soPath;
} GameThreadArg;

static void *gameThreadFunc(void *arg) {
    GameThreadArg *gtArg = (GameThreadArg *)arg;
    Server *s = gtArg->s;

    void *handle = dlopen(gtArg->soPath, RTLD_LAZY);
    if (handle == NULL) {
        LOG_ERROR("gameRunner: dlopen failed: %s", dlerror());
        s->sdk = NULL;
        s->gameRunning = false;
        free(gtArg->soPath);
        free(gtArg);
        return NULL;
    }

    typedef void (*PacPlayMain)(void);
    PacPlayMain entry = (PacPlayMain)dlsym(handle, "pacplayMain");
    if (entry == NULL) {
        LOG_ERROR("gameRunner: dlsym('pacplayMain') failed: %s", dlerror());
        dlclose(handle);
        s->sdk = NULL;
        s->gameRunning = false;
        free(gtArg->soPath);
        free(gtArg);
        return NULL;
    }

    s->gameHandle = handle;
    LOG_INFO("gameRunner: calling pacplayMain()");
    entry();
    LOG_INFO("gameRunner: pacplayMain() returned");

    dlclose(handle);
    s->gameHandle = NULL;

    if (s->sdk != NULL) {
        pacplay_srv_destroy(s->sdk);
        s->sdk = NULL;
    }

    s->gameRunning = false;
    free(gtArg->soPath);
    free(gtArg);
    return NULL;
}

int serverStartGame(Server *s, const char *soPath) {
    if (s == NULL || soPath == NULL) {
        return SERVER_FAIL;
    }

    if (s->gameRunning) {
        LOG_WARN("gameRunner: a game is already running");
        return SERVER_FAIL;
    }

    s->sdk = pacplay_srv_create();
    if (s->sdk == NULL) {
        LOG_ERROR("gameRunner: pacplay_srv_create failed");
        return SERVER_FAIL;
    }

    GameThreadArg *gtArg = malloc(sizeof(GameThreadArg));
    if (gtArg == NULL) {
        pacplay_srv_destroy(s->sdk);
        s->sdk = NULL;
        return SERVER_FAIL;
    }

    gtArg->s = s;
    gtArg->soPath = strdup(soPath);
    if (gtArg->soPath == NULL) {
        pacplay_srv_destroy(s->sdk);
        s->sdk = NULL;
        free(gtArg);
        return SERVER_FAIL;
    }

    if (pthread_create(&s->gameThread, NULL, gameThreadFunc, gtArg) != 0) {
        LOG_ERROR("gameRunner: pthread_create failed (errno=%d)", errno);
        pacplay_srv_destroy(s->sdk);
        s->sdk = NULL;
        free(gtArg->soPath);
        free(gtArg);
        return SERVER_FAIL;
    }

    s->gameRunning = true;
    LOG_INFO("gameRunner: started game thread for %s", soPath);
    return SERVER_SUCC;
}

void serverStopGame(Server *s) {
    if (s == NULL || !s->gameRunning) {
        return;
    }

    s->running = false;

    pthread_join(s->gameThread, NULL);

    if (s->gameHandle != NULL) {
        dlclose(s->gameHandle);
        s->gameHandle = NULL;
    }

    if (s->sdk != NULL) {
        pacplay_srv_destroy(s->sdk);
        s->sdk = NULL;
    }

    s->gameRunning = false;
    LOG_INFO("gameRunner: game thread stopped");
}
