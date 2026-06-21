#ifndef SERVER_ONLINETRACKER_H
#define SERVER_ONLINETRACKER_H

#include <stdbool.h>
#include <stdint.h>

struct ClientSession;

typedef struct OnlineTracker OnlineTracker;

OnlineTracker *onlineTrackerCreate(void);
void onlineTrackerDestroy(OnlineTracker *trk);
void onlineTrackerAdd(OnlineTracker *trk, uint32_t uid,
                      struct ClientSession *cs);
void onlineTrackerRemove(OnlineTracker *trk, uint32_t uid);
struct ClientSession *onlineTrackerFind(OnlineTracker *trk, uint32_t uid);
bool onlineTrackerIsOnline(OnlineTracker *trk, uint32_t uid);

#endif
