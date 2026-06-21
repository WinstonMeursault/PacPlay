#include "pacplay_sdk.h"
#include "snake_common.h"
#include <time.h>
#include <unistd.h>

void pacplayMain(void) {
    PacPlaySDK *sdk = pacplay_srv_create();
    if (sdk == NULL)
        return;

    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = SNAKE_SRV_POLL_US * SNAKE_NS_PER_US,
    };

    while (1) {
        pacplay_srv_poll(sdk);
        nanosleep(&ts, NULL);
    }

    pacplay_srv_destroy(sdk);
}
