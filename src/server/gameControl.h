#ifndef GAME_CONTROL_H
#define GAME_CONTROL_H

#include "server.h"
#include "tui/control.h"

#define GAME_LIB_DIR "./gameLib"
#define GAME_CONTROL_SUCC 0
#define GAME_CONTROL_FAIL (-1)

int gameCtlList(Server *s, ControlScrollTextBox *outBox);
int gameCtlUpdate(Server *s, const char *tarGzPath, ControlScrollTextBox *outBox);
int gameCtlDelete(Server *s, uint32_t gameId, ControlScrollTextBox *outBox);
int gameCtlScan(Server *s, ControlScrollTextBox *outBox);
int gameCtlInfo(Server *s, uint32_t gameId, ControlScrollTextBox *outBox);

#endif
