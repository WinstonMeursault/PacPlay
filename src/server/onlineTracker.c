#include "onlineTracker.h"
#include "log.h"
#include "server.h"

#include <stdlib.h>
#include <string.h>

enum { TrackerBucketCount = 512 };

typedef struct OnlineEntry {
    uint32_t uid;
    struct ClientSession *cs;
    struct OnlineEntry *next;
} OnlineEntry;

struct OnlineTracker {
    OnlineEntry *buckets[TrackerBucketCount];
};

static size_t hashUid(uint32_t uid) {
    return uid % TrackerBucketCount;
}

OnlineTracker *onlineTrackerCreate(void) {
    OnlineTracker *trk = calloc(1, sizeof(OnlineTracker));
    if (trk == NULL) {
        LOG_ERROR("onlineTrackerCreate: calloc failed");
        return NULL;
    }
    return trk;
}

void onlineTrackerDestroy(OnlineTracker *trk) {
    if (trk == NULL) return;
    for (size_t i = 0; i < TrackerBucketCount; i++) {
        OnlineEntry *entry = trk->buckets[i];
        while (entry != NULL) {
            OnlineEntry *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(trk);
}

void onlineTrackerAdd(OnlineTracker *trk, uint32_t uid, struct ClientSession *cs) {
    if (trk == NULL || cs == NULL) return;
    /* Remove any existing entry first (idempotent) */
    onlineTrackerRemove(trk, uid);
    OnlineEntry *entry = malloc(sizeof(OnlineEntry));
    if (entry == NULL) return;
    entry->uid = uid;
    entry->cs = cs;
    size_t idx = hashUid(uid);
    entry->next = trk->buckets[idx];
    trk->buckets[idx] = entry;
}

void onlineTrackerRemove(OnlineTracker *trk, uint32_t uid) {
    if (trk == NULL) return;
    size_t idx = hashUid(uid);
    OnlineEntry **prev = &trk->buckets[idx];
    OnlineEntry *entry = trk->buckets[idx];
    while (entry != NULL) {
        if (entry->uid == uid) {
            *prev = entry->next;
            free(entry);
            return;
        }
        prev = &entry->next;
        entry = entry->next;
    }
}

struct ClientSession *onlineTrackerFind(OnlineTracker *trk, uint32_t uid) {
    if (trk == NULL) return NULL;
    size_t idx = hashUid(uid);
    OnlineEntry *entry = trk->buckets[idx];
    while (entry != NULL) {
        if (entry->uid == uid) return entry->cs;
        entry = entry->next;
    }
    return NULL;
}

bool onlineTrackerIsOnline(OnlineTracker *trk, uint32_t uid) {
    return onlineTrackerFind(trk, uid) != NULL;
}
