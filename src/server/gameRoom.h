#ifndef SERVER_GAME_ROOM_H
#define SERVER_GAME_ROOM_H

#include "server.h"

ActiveGameRoom *serverFindActiveGameRoom(const Server *s, uint32_t gameRoomId);

ActiveGameRoom *serverGetOrCreateActiveGameRoom(Server *s, uint32_t gameRoomId,
                                                uint32_t gameId,
                                                uint32_t hostUid);

void serverRemoveActiveGameRoom(Server *s, uint32_t gameRoomId);

void serverRemoveClientFromGameRoom(Server *s, ClientSession *cs);

void serverDissolveGameRoom(Server *s, uint32_t gameRoomId,
                            ClientSession *exclude);

int serverHandleGameRoomList(Server *s, ClientSession *cs);
int serverHandleGameRoomCreate(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGameRoomJoin(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGameRoomQuit(Server *s, ClientSession *cs);
int serverHandleGameRoomStart(Server *s, ClientSession *cs, const Packet *pkt);
int serverHandleGameRoomPlayData(Server *s, ClientSession *cs,
                                 const Packet *pkt);

#endif /* SERVER_GAME_ROOM_H */
