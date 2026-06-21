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
        pacplay_srv_destroy(s->sdk);
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
        pacplay_srv_destroy(s->sdk);
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

    s->gameRunning = true;

    if (pthread_create(&s->gameThread, NULL, gameThreadFunc, gtArg) != 0) {
        LOG_ERROR("gameRunner: pthread_create failed (errno=%d)", errno);
        s->gameRunning = false;
        pacplay_srv_destroy(s->sdk);
        s->sdk = NULL;
        free(gtArg->soPath);
        free(gtArg);
        return SERVER_FAIL;
    }
    LOG_INFO("gameRunner: started game thread for %s", soPath);
    return SERVER_SUCC;
}

void serverStopGame(Server *s) {
    if (s == NULL || !s->gameRunning) {
        return;
    }

    s->gameRunning = false;

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

typedef struct {
    ActiveGameRoom *gr;
    char *soPath;
} GameRoomThreadArg;

static void *gameRoomThreadFunc(void *arg) {
    GameRoomThreadArg *grArg = (GameRoomThreadArg *)arg;
    ActiveGameRoom *gr = grArg->gr;

    void *handle = dlopen(grArg->soPath, RTLD_LAZY);
    if (handle == NULL) {
        LOG_ERROR("gameRoom[%u]: dlopen failed: %s", gr->gameRoomId, dlerror());
        pacplay_srv_destroy(gr->sdk);
        gr->sdk = NULL;
        gr->gameRunning = false;
        free(grArg->soPath);
        free(grArg);
        return NULL;
    }

    typedef void (*PacPlayMain)(void);
    PacPlayMain entry = (PacPlayMain)dlsym(handle, "pacplayMain");
    if (entry == NULL) {
        LOG_ERROR("gameRoom[%u]: dlsym('pacplayMain') failed: %s",
                  gr->gameRoomId, dlerror());
        dlclose(handle);
        pacplay_srv_destroy(gr->sdk);
        gr->sdk = NULL;
        gr->gameRunning = false;
        free(grArg->soPath);
        free(grArg);
        return NULL;
    }

    gr->gameHandle = handle;
    LOG_INFO("gameRoom[%u]: calling pacplayMain()", gr->gameRoomId);
    entry();
    LOG_INFO("gameRoom[%u]: pacplayMain() returned", gr->gameRoomId);

    dlclose(handle);
    gr->gameHandle = NULL;

    if (gr->sdk != NULL) {
        pacplay_srv_destroy(gr->sdk);
        gr->sdk = NULL;
    }

    gr->gameRunning = false;
    free(grArg->soPath);
    free(grArg);
    return NULL;
}

int gameRoomStartGame(ActiveGameRoom *gr, const char *soPath) {
    if (gr == NULL || soPath == NULL) {
        return SERVER_FAIL;
    }

    if (gr->gameRunning) {
        LOG_WARN("gameRoom[%u]: a game is already running", gr->gameRoomId);
        return SERVER_FAIL;
    }

    gr->sdk = pacplay_srv_create();
    if (gr->sdk == NULL) {
        LOG_ERROR("gameRoom[%u]: pacplay_srv_create failed", gr->gameRoomId);
        return SERVER_FAIL;
    }

    GameRoomThreadArg *grArg = malloc(sizeof(GameRoomThreadArg));
    if (grArg == NULL) {
        pacplay_srv_destroy(gr->sdk);
        gr->sdk = NULL;
        return SERVER_FAIL;
    }

    grArg->gr = gr;
    grArg->soPath = strdup(soPath);
    if (grArg->soPath == NULL) {
        pacplay_srv_destroy(gr->sdk);
        gr->sdk = NULL;
        free(grArg);
        return SERVER_FAIL;
    }

    gr->gameRunning = true;

    if (pthread_create(&gr->gameThread, NULL, gameRoomThreadFunc, grArg) != 0) {
        LOG_ERROR("gameRoom[%u]: pthread_create failed (errno=%d)",
                  gr->gameRoomId, errno);
        gr->gameRunning = false;
        pacplay_srv_destroy(gr->sdk);
        gr->sdk = NULL;
        free(grArg->soPath);
        free(grArg);
        return SERVER_FAIL;
    }
    LOG_INFO("gameRoom[%u]: started game thread for %s", gr->gameRoomId,
             soPath);
    return SERVER_SUCC;
}

void gameRoomStopGame(ActiveGameRoom *gr) {
    if (gr == NULL || !gr->gameRunning) {
        return;
    }

    gr->gameRunning = false;

    pthread_join(gr->gameThread, NULL);

    if (gr->gameHandle != NULL) {
        dlclose(gr->gameHandle);
        gr->gameHandle = NULL;
    }

    if (gr->sdk != NULL) {
        pacplay_srv_destroy(gr->sdk);
        gr->sdk = NULL;
    }

    LOG_INFO("gameRoom[%u]: game thread stopped", gr->gameRoomId);
}
