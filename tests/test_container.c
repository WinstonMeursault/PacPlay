/**
 * @file test_container.c
 * @brief Unit tests for the PacPlay container module (Queue and Array).
 *
 * Instantiated types: QueuePacket, QueueInt, ArrayPacket, ArrayInt.
 *
 * @date 2026-05-31
 * @copyright GPLv3 License
 */

#include "container.h"
#include "protocol.h"
#include "test_utils.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────── type instantiations ─────────────────────────── */

typedef int Int;
QUEUE_DEFINE(Packet)
QUEUE_DEFINE(Int)
ARRAY_DEFINE(Packet)
ARRAY_DEFINE(Int)

/* ──────────────────────────── helper constants ──────────────────────────── */

enum {
    DefaultCap = 8,
    TestCap = 4,
    MinCap = 1,
    LargeCap = 10000,
    SentinelSeq = 0x0DEAD,
    SeqA = 42,
    SeqB = 7,
    SeqC = 30,
    SeqFirst = 0,
    SeqSecond = 1,
    IntNegMax = INT_MIN,
    IntPosMax = INT_MAX,
    IntNegOne = -1,
    IntZero = 0,
    IntOne = 1,
    IntValA = 100,
    IntValB = 200,
    IntValC = 300,
    IntBogus = 999,
    PayloadFillByte = 0xAB
};

/* ───────────────────────────── Packet helper ────────────────────────────── */

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static Packet makeTestPacket(MessageType msgType, uint32_t seqID) {
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = PACKET_MAGIC;
    pkt.header.packetType = (uint32_t)PlaintextPacket;
    pkt.header.messageType = (uint32_t)msgType;
    pkt.header.payloadLength = 0;
    pkt.header.sequenceID = seqID;
    pkt.payload = NULL;
    return pkt;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static Packet makeTestPacketWithPayload(MessageType msgType, uint32_t seqID,
                                        size_t payloadLen) {
    Packet pkt = makeTestPacket(msgType, seqID);
    pkt.header.payloadLength = (uint32_t)payloadLen;
    pkt.payload = malloc(payloadLen);
    if (pkt.payload != NULL) {
        memset(pkt.payload, PayloadFillByte, payloadLen);
    }
    return pkt;
}

/* ════════════════════════════════════════════════════════════════════════
   QueuePacket tests
   ════════════════════════════════════════════════════════════════════════ */

static void testQueuePacketConstants(void) {
    ASSERT_INT_EQ(ContainerSucc, 0);
    ASSERT_INT_EQ(ContainerFail, -1);
    ASSERT_UINT_EQ(QUEUE_DEFAULT_CAPACITY, DefaultCap);
}

static void testQueuePacketInitValid(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ContainerRes res = queuePacketInit(&q, TestCap);
    ASSERT_INT_EQ(res, ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, TestCap);
    ASSERT_UINT_EQ(q.head, 0);
    ASSERT_UINT_EQ(q.tail, 0);
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    ASSERT_TRUE(q.buf != NULL);
    queuePacketDeinit(&q);
}

static void testQueuePacketInitZeroDefault(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queuePacketInit(&q, USE_DEFAULT_CAPACITY), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, QUEUE_DEFAULT_CAPACITY);
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

static void testQueuePacketInitCapacityOne(void) {
    enum { ExpectedAfterTwoPushes = 4 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queuePacketInit(&q, MinCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, MinCap);

    Packet pkt = makeTestPacket(MsgChat, SeqFirst);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    Packet pkt2 = makeTestPacket(MsgChat, SeqSecond);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt2), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, ExpectedAfterTwoPushes);

    Packet front;
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.sequenceID, SeqFirst);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.sequenceID, SeqSecond);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);

    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

static void testQueuePacketInitOverflow(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ContainerRes res = queuePacketInit(&q, SIZE_MAX);
    ASSERT_INT_EQ(res, ContainerFail);
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerFail);

    Packet dest = makeTestPacket(MsgChat, SentinelSeq);
    ASSERT_INT_EQ(queuePacketFront(&q, &dest), ContainerFail);
    ASSERT_UINT_EQ(dest.header.sequenceID, SentinelSeq);

    res = queuePacketInit(&q, TestCap);
    ASSERT_INT_EQ(res, ContainerSucc);
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

static void testQueuePacketDoubleInitLeak(void) {
    enum { SecondCap = 8 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queuePacketInit(&q, TestCap), ContainerSucc);
    void *firstBuf = q.buf;
    ASSERT_TRUE(firstBuf != NULL);

    ASSERT_INT_EQ(queuePacketInit(&q, SecondCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, SecondCap);
    ASSERT_TRUE(q.buf != firstBuf);
    ASSERT_TRUE(q.buf != NULL);

    queuePacketDeinit(&q);
}

static void testQueuePacketDeinitSafety(void) {
    queuePacketDeinit(NULL);

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketDeinit(&q);
}

static void testQueuePacketDeinitDoubleSafe(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);
    queuePacketDeinit(&q);
    queuePacketDeinit(&q);
}

static void testQueuePacketLifecycleReuse(void) {
    enum { SecondCap = 16 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queuePacketInit(&q, TestCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, TestCap);
    queuePacketDeinit(&q);

    ASSERT_INT_EQ(queuePacketInit(&q, SecondCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, SecondCap);
    ASSERT_TRUE(queuePacketIsEmpty(&q));

    Packet pkt = makeTestPacket(MsgChat, SeqA);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    ASSERT_FALSE(queuePacketIsEmpty(&q));

    queuePacketDeinit(&q);
}

static void testQueuePacketPostDeinitStaleFields(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);
    queuePacketPush(&q, makeTestPacket(MsgChat, SeqA));
    queuePacketPush(&q, makeTestPacket(MsgChat, SeqB));

    size_t savedHead = q.head;
    size_t savedTail = q.tail;
    size_t savedCapacity = q.capacity;
    queuePacketDeinit(&q);

    ASSERT_TRUE(q.buf == NULL);
    ASSERT_UINT_EQ(q.capacity, savedCapacity);
    ASSERT_UINT_EQ(q.head, savedHead);
    ASSERT_UINT_EQ(q.tail, savedTail);
    ASSERT_FALSE(queuePacketIsEmpty(&q));

    ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    ASSERT_UINT_EQ(q.head, savedHead + 1);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerFail);
}

static void testQueuePacketEmptyOperations(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    ASSERT_TRUE(queuePacketIsEmpty(&q));
    Packet dest;
    ASSERT_INT_EQ(queuePacketFront(&q, &dest), ContainerFail);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerFail);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerFail);
    ASSERT_TRUE(queuePacketIsEmpty(&q));

    queuePacketDeinit(&q);
}

static void testQueuePacketPushFrontRoundTrip(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    Packet pkt = makeTestPacket(MsgChat, SeqA);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    ASSERT_FALSE(queuePacketIsEmpty(&q));

    Packet front;
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.magic, PACKET_MAGIC);
    ASSERT_UINT_EQ(front.header.packetType, (uint32_t)PlaintextPacket);
    ASSERT_UINT_EQ(front.header.messageType, (uint32_t)MsgChat);
    ASSERT_UINT_EQ(front.header.sequenceID, SeqA);
    ASSERT_TRUE(front.payload == NULL);

    /* Front is idempotent. */
    Packet pkt2 = makeTestPacket(MsgLoginReq, SeqB);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt2), ContainerSucc);
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.sequenceID, SeqA);

    queuePacketDeinit(&q);
}

static void testQueuePacketFifoOrder(void) {
    enum { NumPkts = 5 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    for (uint32_t i = 0; i < NumPkts; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }

    for (uint32_t i = 0; i < NumPkts; i++) {
        Packet front;
        ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
        ASSERT_UINT_EQ(front.header.sequenceID, i);
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }

    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

static void testQueuePacketPushToFullCapacity(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    for (uint32_t i = 0; i < (uint32_t)(TestCap - 1); i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, TestCap);

    Packet last = makeTestPacket(MsgChat, (uint32_t)(TestCap - 1));
    ASSERT_INT_EQ(queuePacketPush(&q, last), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, TestCap * 2);

    for (uint32_t i = 0; i < TestCap; i++) {
        Packet front;
        ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
        ASSERT_UINT_EQ(front.header.sequenceID, i);
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

static void testQueuePacketMultipleReserveCycles(void) {
    enum { TotalPushes = 11, ExpectedFinalCap = 16 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    for (uint32_t i = 0; i < TotalPushes; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, ExpectedFinalCap);

    for (uint32_t i = 0; i < TotalPushes; i++) {
        Packet front;
        ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
        ASSERT_UINT_EQ(front.header.sequenceID, i);
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

static void testQueuePacketEmptyAndRefill(void) {
    enum { NewSeq = 99 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    for (uint32_t i = 0; i < TestCap; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    for (uint32_t i = 0; i < TestCap; i++) {
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    size_t capAfterDrain = q.capacity;

    Packet newPkt = makeTestPacket(MsgLoginReq, NewSeq);
    ASSERT_INT_EQ(queuePacketPush(&q, newPkt), ContainerSucc);
    ASSERT_FALSE(queuePacketIsEmpty(&q));
    ASSERT_UINT_EQ(q.capacity, capAfterDrain);

    Packet front;
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.sequenceID, NewSeq);
    ASSERT_UINT_EQ(front.header.messageType, (uint32_t)MsgLoginReq);

    queuePacketDeinit(&q);
}

static void testQueuePacketReserveFromNonZeroHead(void) {
    enum { PopCount = 2, PushAfterPop = 6, InitCap = 4 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, InitCap);

    for (uint32_t i = 0; i < InitCap; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, InitCap * 2);

    for (int i = 0; i < PopCount; i++) {
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.head, (size_t)PopCount);

    for (uint32_t i = InitCap; i < InitCap + (uint32_t)PushAfterPop; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, InitCap * 2 * 2);

    for (uint32_t i = (uint32_t)PopCount; i < InitCap + (uint32_t)PushAfterPop;
         i++) {
        Packet front;
        ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
        ASSERT_UINT_EQ(front.header.sequenceID, i);
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

static void testQueuePacketInterleavedPushPop(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    ASSERT_INT_EQ(queuePacketPush(&q, makeTestPacket(MsgChat, SeqA)),
                  ContainerSucc);
    ASSERT_INT_EQ(queuePacketPush(&q, makeTestPacket(MsgChat, SeqB)),
                  ContainerSucc);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queuePacketPush(&q, makeTestPacket(MsgChat, SeqC)),
                  ContainerSucc);

    Packet front;
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.sequenceID, SeqB);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.sequenceID, SeqC);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    ASSERT_TRUE(queuePacketIsEmpty(&q));

    queuePacketDeinit(&q);
}

static void testQueuePacketLargeCapacityStress(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queuePacketInit(&q, LargeCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, LargeCap);

    for (uint32_t i = 0; i < (uint32_t)(LargeCap - 1); i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, LargeCap);

    Packet last = makeTestPacket(MsgChat, (uint32_t)(LargeCap - 1));
    ASSERT_INT_EQ(queuePacketPush(&q, last), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, LargeCap * 2);

    for (uint32_t i = 0; i < LargeCap; i++) {
        Packet front;
        ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
        ASSERT_UINT_EQ(front.header.sequenceID, i);
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

static void testQueuePacketDeinitWithElements(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    /* Deinit with elements still queued — buf is freed, struct fields are
     * stale but the call does not crash. */
    queuePacketPush(&q, makeTestPacket(MsgChat, SeqA));
    queuePacketDeinit(&q);
}

static void testQueuePacketNonPayloadRoundTrip(void) {
    enum { PayloadLen = 5 };
    /* PayloadLen is small to avoid magic numbers in memcmp. */

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    Packet pkt = makeTestPacketWithPayload(MsgChat, SeqA, PayloadLen);
    ASSERT_TRUE(pkt.payload != NULL);
    ASSERT_UINT_EQ(pkt.header.payloadLength, PayloadLen);

    ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);

    Packet front;
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.sequenceID, SeqA);
    ASSERT_UINT_EQ(front.header.payloadLength, PayloadLen);
    ASSERT_TRUE(front.payload != NULL);
    ASSERT_TRUE(front.payload == pkt.payload);
    ASSERT_MEM_EQ(front.payload, pkt.payload, PayloadLen);

    ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    ASSERT_TRUE(queuePacketIsEmpty(&q));

    free(pkt.payload);
    queuePacketDeinit(&q);
}

static void testQueuePacketFrontFailureLeavesDestUnchanged(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    Packet dest = makeTestPacket(MsgChat, SentinelSeq);
    ASSERT_INT_EQ(queuePacketFront(&q, &dest), ContainerFail);
    ASSERT_UINT_EQ(dest.header.sequenceID, SentinelSeq);
    ASSERT_UINT_EQ(dest.header.magic, PACKET_MAGIC);

    queuePacketDeinit(&q);
}

/* ════════════════════════════════════════════════════════════════════════
   QueueInt tests
   ════════════════════════════════════════════════════════════════════════ */

static void testQueueIntInitValid(void) {
    QueueInt q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queueIntInit(&q, TestCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, TestCap);
    ASSERT_UINT_EQ(q.head, 0);
    ASSERT_UINT_EQ(q.tail, 0);
    ASSERT_TRUE(queueIntIsEmpty(&q));
    ASSERT_TRUE(q.buf != NULL);
    queueIntDeinit(&q);
}

static void testQueueIntInitZeroDefault(void) {
    QueueInt q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queueIntInit(&q, USE_DEFAULT_CAPACITY), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, QUEUE_DEFAULT_CAPACITY);
    ASSERT_TRUE(queueIntIsEmpty(&q));
    queueIntDeinit(&q);
}

static void testQueueIntInitOverflow(void) {
    QueueInt q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queueIntInit(&q, SIZE_MAX), ContainerFail);
    ASSERT_TRUE(queueIntIsEmpty(&q));

    ASSERT_INT_EQ(queueIntInit(&q, TestCap), ContainerSucc);
    ASSERT_TRUE(queueIntIsEmpty(&q));
    queueIntDeinit(&q);
}

static void testQueueIntDeinitSafety(void) {
    queueIntDeinit(NULL);

    QueueInt q;
    memset(&q, 0, sizeof(q));
    queueIntInit(&q, TestCap);
    queueIntDeinit(&q);
    queueIntDeinit(&q);
}

static void testQueueIntEmptyOperations(void) {
    QueueInt q;
    memset(&q, 0, sizeof(q));
    queueIntInit(&q, TestCap);

    ASSERT_TRUE(queueIntIsEmpty(&q));
    Int val;
    ASSERT_INT_EQ(queueIntFront(&q, &val), ContainerFail);
    ASSERT_INT_EQ(queueIntPop(&q), ContainerFail);

    queueIntDeinit(&q);
}

static void testQueueIntPushFrontRoundTrip(void) {
    QueueInt q;
    memset(&q, 0, sizeof(q));
    queueIntInit(&q, TestCap);

    ASSERT_INT_EQ(queueIntPush(&q, (Int)SeqA), ContainerSucc);
    ASSERT_FALSE(queueIntIsEmpty(&q));

    Int front;
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)SeqA);

    /* Idempotent Front. */
    ASSERT_INT_EQ(queueIntPush(&q, (Int)SeqB), ContainerSucc);
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)SeqA);

    queueIntDeinit(&q);
}

static void testQueueIntExtremeValues(void) {
    QueueInt q;
    memset(&q, 0, sizeof(q));
    queueIntInit(&q, TestCap);

    ASSERT_INT_EQ(queueIntPush(&q, (Int)IntNegMax), ContainerSucc);
    ASSERT_INT_EQ(queueIntPush(&q, (Int)IntNegOne), ContainerSucc);
    ASSERT_INT_EQ(queueIntPush(&q, (Int)IntZero), ContainerSucc);
    ASSERT_INT_EQ(queueIntPush(&q, (Int)IntOne), ContainerSucc);
    ASSERT_INT_EQ(queueIntPush(&q, (Int)IntPosMax), ContainerSucc);

    Int front;
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)IntNegMax);
    ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)IntNegOne);
    ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)IntZero);
    ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)IntOne);
    ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)IntPosMax);

    queueIntDeinit(&q);
}

static void testQueueIntFifoOrder(void) {
    enum { NumVals = 5 };

    QueueInt q;
    memset(&q, 0, sizeof(q));
    queueIntInit(&q, TestCap);

    for (Int i = 0; i < (Int)NumVals; i++) {
        ASSERT_INT_EQ(queueIntPush(&q, i * (Int)10), ContainerSucc);
    }

    for (Int i = 0; i < (Int)NumVals; i++) {
        Int front;
        ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
        ASSERT_INT_EQ(front, i * (Int)10);
        ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    }

    ASSERT_TRUE(queueIntIsEmpty(&q));
    queueIntDeinit(&q);
}

static void testQueueIntReserveAndRefill(void) {
    enum { TotalPushes = 10, ExpectedFinalCap = 16 };

    QueueInt q;
    memset(&q, 0, sizeof(q));
    queueIntInit(&q, TestCap);

    for (Int i = 0; i < (Int)TotalPushes; i++) {
        ASSERT_INT_EQ(queueIntPush(&q, i), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, ExpectedFinalCap);

    for (Int i = 0; i < (Int)TotalPushes; i++) {
        Int front;
        ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
        ASSERT_INT_EQ(front, i);
        ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queueIntIsEmpty(&q));

    /* Refill. */
    ASSERT_INT_EQ(queueIntPush(&q, (Int)IntValA), ContainerSucc);
    Int front;
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)IntValA);

    queueIntDeinit(&q);
}

static void testQueueIntInterleavedPushPop(void) {
    QueueInt q;
    memset(&q, 0, sizeof(q));
    queueIntInit(&q, TestCap);

    ASSERT_INT_EQ(queueIntPush(&q, (Int)10), ContainerSucc);
    ASSERT_INT_EQ(queueIntPush(&q, (Int)20), ContainerSucc);
    ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queueIntPush(&q, (Int)30), ContainerSucc);

    Int front;
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)20);
    ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    ASSERT_INT_EQ(queueIntFront(&q, &front), ContainerSucc);
    ASSERT_INT_EQ(front, (Int)30);
    ASSERT_INT_EQ(queueIntPop(&q), ContainerSucc);
    ASSERT_TRUE(queueIntIsEmpty(&q));

    queueIntDeinit(&q);
}

/* ════════════════════════════════════════════════════════════════════════
   ArrayPacket tests
   ════════════════════════════════════════════════════════════════════════ */

static void testArrayPacketConstants(void) {
    ASSERT_UINT_EQ(ARRAY_DEFAULT_CAPACITY, DefaultCap);
}

static void testArrayPacketInitValid(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    ASSERT_INT_EQ(arrayPacketInit(&a, TestCap), ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, TestCap);
    ASSERT_UINT_EQ(a.size, 0);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);
    ASSERT_TRUE(a.buf != NULL);
    arrayPacketDeinit(&a);
}

static void testArrayPacketInitZeroDefault(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    ASSERT_INT_EQ(arrayPacketInit(&a, USE_DEFAULT_CAPACITY), ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, ARRAY_DEFAULT_CAPACITY);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);
    arrayPacketDeinit(&a);
}

static void testArrayPacketInitOverflow(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    ASSERT_INT_EQ(arrayPacketInit(&a, SIZE_MAX), ContainerFail);

    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);
    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerFail);

    Packet dest = makeTestPacket(MsgChat, SentinelSeq);
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &dest), ContainerFail);
    ASSERT_UINT_EQ(dest.header.sequenceID, SentinelSeq);

    ASSERT_INT_EQ(arrayPacketInit(&a, TestCap), ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);
    arrayPacketDeinit(&a);
}

static void testArrayPacketDoubleInitLeak(void) {
    enum { SecondCap = 8 };

    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    ASSERT_INT_EQ(arrayPacketInit(&a, TestCap), ContainerSucc);
    void *firstBuf = a.buf;
    ASSERT_TRUE(firstBuf != NULL);

    ASSERT_INT_EQ(arrayPacketInit(&a, SecondCap), ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, SecondCap);
    ASSERT_TRUE(a.buf != firstBuf);
    ASSERT_TRUE(a.buf != NULL);

    arrayPacketDeinit(&a);
}

static void testArrayPacketDeinitSafety(void) {
    arrayPacketDeinit(NULL);

    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketDeinit(&a);
}

static void testArrayPacketDeinitDoubleSafe(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);
    arrayPacketDeinit(&a);
    arrayPacketDeinit(&a);
}

static void testArrayPacketLifecycleReuse(void) {
    enum { SecondCap = 16 };

    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    ASSERT_INT_EQ(arrayPacketInit(&a, TestCap), ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, TestCap);
    arrayPacketDeinit(&a);

    ASSERT_INT_EQ(arrayPacketInit(&a, SecondCap), ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, SecondCap);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);

    Packet pkt = makeTestPacket(MsgChat, SeqA);
    ASSERT_INT_EQ(arrayPacketPushBack(&a, pkt), ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 1);

    arrayPacketDeinit(&a);
}

static void testArrayPacketPostDeinitStaleFields(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);
    arrayPacketPushBack(&a, makeTestPacket(MsgChat, SeqA));

    size_t savedCapacity = a.capacity;
    size_t savedSize = a.size;
    arrayPacketDeinit(&a);

    ASSERT_TRUE(a.buf == NULL);
    ASSERT_UINT_EQ(a.capacity, savedCapacity);
    ASSERT_UINT_EQ(a.size, savedSize);
    ASSERT_UINT_EQ(arrayPacketSize(&a), savedSize);

    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerSucc);
    ASSERT_UINT_EQ(a.size, savedSize - 1);
    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerFail);
}

static void testArrayPacketEmptyOperations(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);
    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerFail);
    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerFail);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);

    Packet dest = makeTestPacket(MsgChat, SentinelSeq);
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &dest), ContainerFail);
    ASSERT_UINT_EQ(dest.header.sequenceID, SentinelSeq);

    ASSERT_INT_EQ(arrayPacketSet(&a, 0, dest), ContainerFail);

    arrayPacketDeinit(&a);
}

static void testArrayPacketPushBackGetRoundTrip(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    Packet pkt = makeTestPacket(MsgChat, SeqA);
    ASSERT_INT_EQ(arrayPacketPushBack(&a, pkt), ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 1);

    Packet got;
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &got), ContainerSucc);
    ASSERT_UINT_EQ(got.header.magic, PACKET_MAGIC);
    ASSERT_UINT_EQ(got.header.sequenceID, SeqA);
    ASSERT_TRUE(got.payload == NULL);

    arrayPacketDeinit(&a);
}

static void testArrayPacketMultiPushBackOrder(void) {
    enum { NumPkts = 5 };

    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    for (uint32_t i = 0; i < NumPkts; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(arrayPacketPushBack(&a, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(arrayPacketSize(&a), NumPkts);

    for (uint32_t i = 0; i < NumPkts; i++) {
        Packet got;
        ASSERT_INT_EQ(arrayPacketGet(&a, (size_t)i, &got), ContainerSucc);
        ASSERT_UINT_EQ(got.header.sequenceID, i);
    }

    arrayPacketDeinit(&a);
}

static void testArrayPacketSetGetRoundTrip(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, SeqA)),
                  ContainerSucc);

    Packet replacement = makeTestPacket(MsgLoginReq, SeqB);
    ASSERT_INT_EQ(arrayPacketSet(&a, 0, replacement), ContainerSucc);

    Packet got;
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &got), ContainerSucc);
    ASSERT_UINT_EQ(got.header.sequenceID, SeqB);
    ASSERT_UINT_EQ(got.header.messageType, (uint32_t)MsgLoginReq);

    /* OOB Set must fail and leave existing data intact. */
    ASSERT_INT_EQ(arrayPacketSet(&a, 1, makeTestPacket(MsgChat, IntBogus)),
                  ContainerFail);
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &got), ContainerSucc);
    ASSERT_UINT_EQ(got.header.sequenceID, SeqB);

    arrayPacketDeinit(&a);
}

static void testArrayPacketPopBackSequence(void) {
    enum { PushCount = 3 };

    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, 10)),
                  ContainerSucc);
    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, 20)),
                  ContainerSucc);
    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, 30)),
                  ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), PushCount);

    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), PushCount - 1);

    /* Index 2 now OOB. */
    Packet got;
    ASSERT_INT_EQ(arrayPacketGet(&a, 2, &got), ContainerFail);

    /* Index 1 still valid. */
    ASSERT_INT_EQ(arrayPacketGet(&a, 1, &got), ContainerSucc);
    ASSERT_UINT_EQ(got.header.sequenceID, 20);

    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerSucc);
    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);
    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerFail);

    arrayPacketDeinit(&a);
}

static void testArrayPacketCapacityReserve(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    for (uint32_t i = 0; i < TestCap; i++) {
        ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, i)),
                      ContainerSucc);
    }
    ASSERT_UINT_EQ(a.capacity, TestCap);
    ASSERT_UINT_EQ(arrayPacketSize(&a), TestCap);

    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, TestCap)),
                  ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, TestCap * 2);

    for (uint32_t i = 0; i <= TestCap; i++) {
        Packet got;
        ASSERT_INT_EQ(arrayPacketGet(&a, (size_t)i, &got), ContainerSucc);
        ASSERT_UINT_EQ(got.header.sequenceID, i);
    }

    arrayPacketDeinit(&a);
}

static void testArrayPacketMultipleReserveCycles(void) {
    enum { TotalPushes = 10, ExpectedFinalCap = 16 };

    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    for (uint32_t i = 0; i < TotalPushes; i++) {
        ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, i)),
                      ContainerSucc);
    }
    ASSERT_UINT_EQ(a.capacity, ExpectedFinalCap);

    for (uint32_t i = 0; i < TotalPushes; i++) {
        Packet got;
        ASSERT_INT_EQ(arrayPacketGet(&a, (size_t)i, &got), ContainerSucc);
        ASSERT_UINT_EQ(got.header.sequenceID, i);
    }

    arrayPacketDeinit(&a);
}

static void testArrayPacketEmptyAndRefill(void) {
    enum { NewSeq = 99 };

    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    for (uint32_t i = 0; i < TestCap; i++) {
        ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, i)),
                      ContainerSucc);
    }
    for (uint32_t i = 0; i < TestCap; i++) {
        ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerSucc);
    }
    ASSERT_UINT_EQ(arrayPacketSize(&a), 0);
    size_t capAfterDrain = a.capacity;

    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgLoginReq, NewSeq)),
                  ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 1);
    ASSERT_UINT_EQ(a.capacity, capAfterDrain);

    Packet got;
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &got), ContainerSucc);
    ASSERT_UINT_EQ(got.header.sequenceID, NewSeq);

    arrayPacketDeinit(&a);
}

static void testArrayPacketAdversarialIndexBounds(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, SeqA)),
                  ContainerSucc);

    Packet dest = makeTestPacket(MsgChat, SentinelSeq);
    ASSERT_INT_EQ(arrayPacketGet(&a, 1, &dest), ContainerFail);
    ASSERT_UINT_EQ(dest.header.sequenceID, SentinelSeq);

    ASSERT_INT_EQ(arrayPacketSet(&a, 1, makeTestPacket(MsgChat, IntBogus)),
                  ContainerFail);
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &dest), ContainerSucc);
    ASSERT_UINT_EQ(dest.header.sequenceID, SeqA);

    ASSERT_INT_EQ(arrayPacketGet(&a, SIZE_MAX, &dest), ContainerFail);
    ASSERT_INT_EQ(arrayPacketSet(&a, SIZE_MAX, makeTestPacket(MsgChat, 0)),
                  ContainerFail);

    arrayPacketDeinit(&a);
}

static void testArrayPacketNonPayloadRoundTrip(void) {
    enum { PayloadLen = 16 };

    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    Packet pkt = makeTestPacketWithPayload(MsgChat, SeqA, PayloadLen);
    ASSERT_TRUE(pkt.payload != NULL);

    ASSERT_INT_EQ(arrayPacketPushBack(&a, pkt), ContainerSucc);

    Packet got;
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &got), ContainerSucc);
    ASSERT_UINT_EQ(got.header.payloadLength, PayloadLen);
    ASSERT_TRUE(got.payload != NULL);
    ASSERT_TRUE(got.payload == pkt.payload);
    ASSERT_MEM_EQ(got.payload, pkt.payload, PayloadLen);

    free(pkt.payload);
    arrayPacketDeinit(&a);
}

static void testArrayPacketInterleavedPushPop(void) {
    ArrayPacket a;
    memset(&a, 0, sizeof(a));
    arrayPacketInit(&a, TestCap);

    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, 10)),
                  ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 1);
    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, 20)),
                  ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 2);

    ASSERT_INT_EQ(arrayPacketPopBack(&a), ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 1);

    ASSERT_INT_EQ(arrayPacketPushBack(&a, makeTestPacket(MsgChat, 30)),
                  ContainerSucc);
    ASSERT_UINT_EQ(arrayPacketSize(&a), 2);

    Packet got;
    ASSERT_INT_EQ(arrayPacketGet(&a, 0, &got), ContainerSucc);
    ASSERT_UINT_EQ(got.header.sequenceID, 10);
    ASSERT_INT_EQ(arrayPacketGet(&a, 1, &got), ContainerSucc);
    ASSERT_UINT_EQ(got.header.sequenceID, 30);

    arrayPacketDeinit(&a);
}

/* ════════════════════════════════════════════════════════════════════════
   ArrayInt tests
   ════════════════════════════════════════════════════════════════════════ */

static void testArrayIntInitValid(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    ASSERT_INT_EQ(arrayIntInit(&a, TestCap), ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, TestCap);
    ASSERT_UINT_EQ(a.size, 0);
    ASSERT_UINT_EQ(arrayIntSize(&a), 0);
    ASSERT_TRUE(a.buf != NULL);
    arrayIntDeinit(&a);
}

static void testArrayIntInitZeroDefault(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    ASSERT_INT_EQ(arrayIntInit(&a, USE_DEFAULT_CAPACITY), ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, ARRAY_DEFAULT_CAPACITY);
    ASSERT_UINT_EQ(arrayIntSize(&a), 0);
    arrayIntDeinit(&a);
}

static void testArrayIntInitOverflow(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    ASSERT_INT_EQ(arrayIntInit(&a, SIZE_MAX), ContainerFail);

    ASSERT_UINT_EQ(arrayIntSize(&a), 0);
    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerFail);

    Int dest = (Int)IntBogus;
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &dest), ContainerFail);
    ASSERT_INT_EQ(dest, (Int)IntBogus);

    ASSERT_INT_EQ(arrayIntInit(&a, TestCap), ContainerSucc);
    ASSERT_TRUE(a.buf != NULL);
    arrayIntDeinit(&a);
}

static void testArrayIntDeinitSafety(void) {
    arrayIntDeinit(NULL);

    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);
    arrayIntDeinit(&a);
    arrayIntDeinit(&a);
}

static void testArrayIntEmptyOperations(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    ASSERT_UINT_EQ(arrayIntSize(&a), 0);
    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerFail);
    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerFail);
    ASSERT_UINT_EQ(arrayIntSize(&a), 0);

    Int dest = (Int)IntBogus;
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &dest), ContainerFail);
    ASSERT_INT_EQ(dest, (Int)IntBogus);

    ASSERT_INT_EQ(arrayIntSet(&a, 0, (Int)IntValA), ContainerFail);

    arrayIntDeinit(&a);
}

static void testArrayIntPushBackGetRoundTrip(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntNegMax), ContainerSucc);
    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntNegOne), ContainerSucc);
    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntZero), ContainerSucc);
    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntOne), ContainerSucc);
    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntPosMax), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), 5);

    Int val;
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntNegMax);
    ASSERT_INT_EQ(arrayIntGet(&a, 1, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntNegOne);
    ASSERT_INT_EQ(arrayIntGet(&a, 2, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntZero);
    ASSERT_INT_EQ(arrayIntGet(&a, 3, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntOne);
    ASSERT_INT_EQ(arrayIntGet(&a, 4, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntPosMax);

    arrayIntDeinit(&a);
}

static void testArrayIntMultiPushBackOrder(void) {
    enum { NumVals = 5 };

    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    for (Int i = 0; i < (Int)NumVals; i++) {
        ASSERT_INT_EQ(arrayIntPushBack(&a, i * (Int)10), ContainerSucc);
    }
    ASSERT_UINT_EQ(arrayIntSize(&a), NumVals);

    for (Int i = 0; i < (Int)NumVals; i++) {
        Int val;
        ASSERT_INT_EQ(arrayIntGet(&a, (size_t)i, &val), ContainerSucc);
        ASSERT_INT_EQ(val, i * (Int)10);
    }

    arrayIntDeinit(&a);
}

static void testArrayIntSetGetRoundTrip(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValA), ContainerSucc);
    ASSERT_INT_EQ(arrayIntSet(&a, 0, (Int)IntValB), ContainerSucc);

    Int val;
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntValB);

    ASSERT_INT_EQ(arrayIntSet(&a, 1, (Int)IntBogus), ContainerFail);
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntValB);

    arrayIntDeinit(&a);
}

static void testArrayIntPopBackSequence(void) {
    enum { PushCount = 3 };

    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValA), ContainerSucc);
    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValB), ContainerSucc);
    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValC), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), PushCount);

    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), PushCount - 1);

    Int val;
    ASSERT_INT_EQ(arrayIntGet(&a, 2, &val), ContainerFail);
    ASSERT_INT_EQ(arrayIntGet(&a, 1, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntValB);

    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerSucc);
    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), 0);
    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerFail);
    ASSERT_UINT_EQ(arrayIntSize(&a), 0);

    arrayIntDeinit(&a);
}

static void testArrayIntCapacityReserve(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    for (uint32_t i = 0; i < TestCap; i++) {
        ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)i), ContainerSucc);
    }
    ASSERT_UINT_EQ(a.capacity, TestCap);

    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)TestCap), ContainerSucc);
    ASSERT_UINT_EQ(a.capacity, TestCap * 2);

    for (uint32_t i = 0; i <= TestCap; i++) {
        Int val;
        ASSERT_INT_EQ(arrayIntGet(&a, (size_t)i, &val), ContainerSucc);
        ASSERT_INT_EQ(val, (Int)i);
    }

    arrayIntDeinit(&a);
}

static void testArrayIntMultipleReserveCycles(void) {
    enum { TotalPushes = 10, ExpectedFinalCap = 16 };

    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    for (Int i = 0; i < (Int)TotalPushes; i++) {
        ASSERT_INT_EQ(arrayIntPushBack(&a, i), ContainerSucc);
    }
    ASSERT_UINT_EQ(a.capacity, ExpectedFinalCap);

    for (Int i = 0; i < (Int)TotalPushes; i++) {
        Int val;
        ASSERT_INT_EQ(arrayIntGet(&a, (size_t)i, &val), ContainerSucc);
        ASSERT_INT_EQ(val, i);
    }

    arrayIntDeinit(&a);
}

static void testArrayIntEmptyAndRefill(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    for (uint32_t i = 0; i < TestCap; i++) {
        ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)i), ContainerSucc);
    }
    for (uint32_t i = 0; i < TestCap; i++) {
        ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerSucc);
    }
    ASSERT_UINT_EQ(arrayIntSize(&a), 0);
    size_t capAfterDrain = a.capacity;

    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValC), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), 1);
    ASSERT_UINT_EQ(a.capacity, capAfterDrain);

    Int val;
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntValC);

    arrayIntDeinit(&a);
}

static void testArrayIntAdversarialIndexBounds(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValA), ContainerSucc);

    Int dest = (Int)IntBogus;
    ASSERT_INT_EQ(arrayIntGet(&a, 1, &dest), ContainerFail);
    ASSERT_INT_EQ(dest, (Int)IntBogus);

    ASSERT_INT_EQ(arrayIntSet(&a, 1, (Int)IntBogus), ContainerFail);
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &dest), ContainerSucc);
    ASSERT_INT_EQ(dest, (Int)IntValA);

    ASSERT_INT_EQ(arrayIntGet(&a, SIZE_MAX, &dest), ContainerFail);
    ASSERT_INT_EQ(arrayIntSet(&a, SIZE_MAX, (Int)IntBogus), ContainerFail);

    arrayIntDeinit(&a);
}

static void testArrayIntInterleavedPushPop(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);

    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValA), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), 1);
    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValB), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), 2);

    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), 1);

    ASSERT_INT_EQ(arrayIntPushBack(&a, (Int)IntValC), ContainerSucc);
    ASSERT_UINT_EQ(arrayIntSize(&a), 2);

    Int val;
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntValA);
    ASSERT_INT_EQ(arrayIntGet(&a, 1, &val), ContainerSucc);
    ASSERT_INT_EQ(val, (Int)IntValC);

    arrayIntDeinit(&a);
}

static void testArrayIntPostDeinitSizeZero(void) {
    ArrayInt a;
    memset(&a, 0, sizeof(a));
    arrayIntInit(&a, TestCap);
    arrayIntDeinit(&a);

    ASSERT_UINT_EQ(arrayIntSize(&a), 0);
    ASSERT_INT_EQ(arrayIntPopBack(&a), ContainerFail);

    Int dest = (Int)IntBogus;
    ASSERT_INT_EQ(arrayIntGet(&a, 0, &dest), ContainerFail);
    ASSERT_INT_EQ(dest, (Int)IntBogus);
    ASSERT_INT_EQ(arrayIntSet(&a, 0, (Int)IntBogus), ContainerFail);
}

/* ════════════════════════════════════════════════════════════════════════
   main
   ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_container:\n");

    /* QueuePacket */
    RUN_TEST(testQueuePacketConstants);
    RUN_TEST(testQueuePacketInitValid);
    RUN_TEST(testQueuePacketInitZeroDefault);
    RUN_TEST(testQueuePacketInitCapacityOne);
    RUN_TEST(testQueuePacketInitOverflow);
    RUN_TEST(testQueuePacketDoubleInitLeak);
    RUN_TEST(testQueuePacketDeinitSafety);
    RUN_TEST(testQueuePacketDeinitDoubleSafe);
    RUN_TEST(testQueuePacketLifecycleReuse);
    RUN_TEST(testQueuePacketPostDeinitStaleFields);
    RUN_TEST(testQueuePacketEmptyOperations);
    RUN_TEST(testQueuePacketPushFrontRoundTrip);
    RUN_TEST(testQueuePacketFifoOrder);
    RUN_TEST(testQueuePacketPushToFullCapacity);
    RUN_TEST(testQueuePacketMultipleReserveCycles);
    RUN_TEST(testQueuePacketEmptyAndRefill);
    RUN_TEST(testQueuePacketReserveFromNonZeroHead);
    RUN_TEST(testQueuePacketInterleavedPushPop);
    RUN_TEST(testQueuePacketLargeCapacityStress);
    RUN_TEST(testQueuePacketDeinitWithElements);
    RUN_TEST(testQueuePacketNonPayloadRoundTrip);
    RUN_TEST(testQueuePacketFrontFailureLeavesDestUnchanged);

    /* QueueInt */
    RUN_TEST(testQueueIntInitValid);
    RUN_TEST(testQueueIntInitZeroDefault);
    RUN_TEST(testQueueIntInitOverflow);
    RUN_TEST(testQueueIntDeinitSafety);
    RUN_TEST(testQueueIntEmptyOperations);
    RUN_TEST(testQueueIntPushFrontRoundTrip);
    RUN_TEST(testQueueIntExtremeValues);
    RUN_TEST(testQueueIntFifoOrder);
    RUN_TEST(testQueueIntReserveAndRefill);
    RUN_TEST(testQueueIntInterleavedPushPop);

    /* ArrayPacket */
    RUN_TEST(testArrayPacketConstants);
    RUN_TEST(testArrayPacketInitValid);
    RUN_TEST(testArrayPacketInitZeroDefault);
    RUN_TEST(testArrayPacketInitOverflow);
    RUN_TEST(testArrayPacketDoubleInitLeak);
    RUN_TEST(testArrayPacketDeinitSafety);
    RUN_TEST(testArrayPacketDeinitDoubleSafe);
    RUN_TEST(testArrayPacketLifecycleReuse);
    RUN_TEST(testArrayPacketPostDeinitStaleFields);
    RUN_TEST(testArrayPacketEmptyOperations);
    RUN_TEST(testArrayPacketPushBackGetRoundTrip);
    RUN_TEST(testArrayPacketMultiPushBackOrder);
    RUN_TEST(testArrayPacketSetGetRoundTrip);
    RUN_TEST(testArrayPacketPopBackSequence);
    RUN_TEST(testArrayPacketCapacityReserve);
    RUN_TEST(testArrayPacketMultipleReserveCycles);
    RUN_TEST(testArrayPacketEmptyAndRefill);
    RUN_TEST(testArrayPacketAdversarialIndexBounds);
    RUN_TEST(testArrayPacketNonPayloadRoundTrip);
    RUN_TEST(testArrayPacketInterleavedPushPop);

    /* ArrayInt */
    RUN_TEST(testArrayIntInitValid);
    RUN_TEST(testArrayIntInitZeroDefault);
    RUN_TEST(testArrayIntInitOverflow);
    RUN_TEST(testArrayIntDeinitSafety);
    RUN_TEST(testArrayIntEmptyOperations);
    RUN_TEST(testArrayIntPushBackGetRoundTrip);
    RUN_TEST(testArrayIntMultiPushBackOrder);
    RUN_TEST(testArrayIntSetGetRoundTrip);
    RUN_TEST(testArrayIntPopBackSequence);
    RUN_TEST(testArrayIntCapacityReserve);
    RUN_TEST(testArrayIntMultipleReserveCycles);
    RUN_TEST(testArrayIntEmptyAndRefill);
    RUN_TEST(testArrayIntAdversarialIndexBounds);
    RUN_TEST(testArrayIntInterleavedPushPop);
    RUN_TEST(testArrayIntPostDeinitSizeZero);

    return TEST_REPORT();
}
