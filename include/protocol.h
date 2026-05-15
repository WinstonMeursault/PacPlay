#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define PACKET_MAGIC 0x5050504D // 'PPPM' in ASCII, PacPlay Packet Magic

#define MAX_PAYLOAD_SIZE 1024

typedef enum {
    MsgLoginReq = 1,
    MsgLoginResp,

    MsgChat,

    MsgCreateRoom,
    MsgJoinRoom,

    MsgGameStart,

    MsgHeartbeat
} MessageType;

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;
    uint32_t length;
    uint16_t type;
    uint32_t seq;
} PacketHeader;

#pragma pack(pop)

#endif
