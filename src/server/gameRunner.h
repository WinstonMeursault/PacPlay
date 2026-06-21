#ifndef GAME_RUNNER_H
#define GAME_RUNNER_H

#include "server.h"

int serverStartGame(Server *s, const char *soPath);
void serverStopGame(Server *s);

int gameRoomStartGame(ActiveGameRoom *gr, const char *soPath);
void gameRoomStopGame(ActiveGameRoom *gr);

#endif
