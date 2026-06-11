#ifndef TUIMSG_H
#define TUIMSG_H

#include <stddef.h>

typedef enum {
    MsgCursorPrev = 1,
    MsgCursorNext,
    MsgFocusEnter,
    MsgFocusLeave,
    MsgInput,
    MsgResize,
    MsgFetch, // Send direct child control ptr to container
    MsgRefresh,
    MsgMouse
} MsgType;

typedef union {
    size_t index;
    int input;
    void (*fetchRecv)(void *self, void *child);
} MsgArg;

typedef struct {
    MsgType type;
    MsgArg arg1;
    MsgArg arg2;
    int mouseY;
    int mouseX;
} TuiMsg;

#endif // TUIMSG_H