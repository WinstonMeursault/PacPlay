#ifndef GAME_DISTRIBUTION_H
#define GAME_DISTRIBUTION_H
#include "server.h"

int serverHandleGameList(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGameDownload(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGameDownloadCancel(Server *s, ClientSession *cs,
                                   const Packet *pkt);
#endif
