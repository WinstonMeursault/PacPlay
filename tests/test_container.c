/**
 * @file test_container.c
 * @brief Comprehensive unit tests for the PacPlay container module.
 *
 * Covers QueuePacket (circular buffer with automatic growth via Reserve)
 * for the Packet type.  Tests include boundary conditions, Reserve from
 * non-zero head, lifecycle safety, lifecycle reuse, and adversarial
 * scenarios.
 *
 * @date 2026-05-30
 * @copyright GPLv3 License
 * @section LICENSE
 * PacPlay
 * Copyright (C) 2026 Winston Meursault & Kiraterin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#include "container.h"
#include "test_utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ───────────── helper constants ────────────────────────────────────────── */

enum { ExpectedDefaultCap = 8 };

/* ───────────── helpers ─────────────────────────────────────────────────── */

/**
 * @brief Create a stack-allocated Packet with a zero-length payload for
 *        testing.
 *
 * The returned Packet has @c payload set to @c NULL and requires no
 * separate cleanup.  Callers that push this Packet into a QueuePacket own
 * the responsibility to manage any heap payloads independently — the
 * queue copies the Packet struct (shallow copy) and never frees
 * individual element payloads during Pop or Deinit.
 */
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

/* ═══════════════════════  1. Constants  ══════════════════════════════════ */

/** @brief ContainerRes and QUEUE_DEFAULT_CAPACITY have stable values. */
static void testContainerConstants(void) {
    ASSERT_INT_EQ(ContainerSucc, 0);
    ASSERT_INT_EQ(ContainerFail, -1);
    ASSERT_UINT_EQ(QUEUE_DEFAULT_CAPACITY, ExpectedDefaultCap);
}

/* ═══════════════════════  2. Init basics & boundaries  ═══════════════════ */

/** @brief Init with a normal capacity sets up fields correctly. */
static void testInitValidCapacity(void) {
    enum { TestCap = 4 };

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

/** @brief Init with capacity 0 falls back to QUEUE_DEFAULT_CAPACITY. */
static void testInitZeroCapacityDefault(void) {
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ContainerRes res = queuePacketInit(&q, 0);

    ASSERT_INT_EQ(res, ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, QUEUE_DEFAULT_CAPACITY);
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

/** @brief Init with capacity 1 — the minimum that does not trigger the
 *         default fallback — works correctly.  With cap=1 every push
 *         triggers Reserve because tail immediately wraps to head;
 *         after two pushes capacity reaches 1→2→4. */
static void testInitCapacityOne(void) {
    enum { MinCap = 1, ExpectedAfterTwoPushes = 4 };
    enum { SeqFirst = 0, SeqSecond = 1 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queuePacketInit(&q, MinCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, MinCap);

    /* First push: tail wraps to 0 == head → Reserve (cap 1→2). */
    Packet pkt = makeTestPacket(MsgChat, SeqFirst);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);

    /* Second push: head=0,tail=1,cap=2. Push writes buf[1], tail wraps to
     * 0 == head → Reserve (cap 2→4). */
    Packet pkt2 = makeTestPacket(MsgChat, SeqSecond);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt2), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, ExpectedAfterTwoPushes);

    /* Verify FIFO order survived the Reserve. */
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

/* ═══════════════════════  3. Init error paths  ═══════════════════════════ */

/** @brief Init with a capacity huge enough to overflow the allocation
 *         size returns ContainerFail and leaves the queue usable for a
 *         subsequent valid Init. */
static void testInitOverflowCapacity(void) {
    enum { ValidCap = 4 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ContainerRes res = queuePacketInit(&q, SIZE_MAX);

    /* malloc(sizeof(Packet) * SIZE_MAX) must fail on any real system. */
    ASSERT_INT_EQ(res, ContainerFail);

    /* The queue must still be usable after a failed Init. */
    res = queuePacketInit(&q, ValidCap);
    ASSERT_INT_EQ(res, ContainerSucc);
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

/** @brief Calling Init on an already-initialised queue leaks the old
 *         buffer — this test documents the lack of a defensive guard. */
static void testDoubleInitLeak(void) {
    enum { FirstCap = 4, SecondCap = 8 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queuePacketInit(&q, FirstCap), ContainerSucc);
    void *firstBuf = q.buf;
    ASSERT_TRUE(firstBuf != NULL);

    /* Second Init overwrites buf — firstBuf is leaked. */
    ASSERT_INT_EQ(queuePacketInit(&q, SecondCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, SecondCap);
    ASSERT_TRUE(q.buf != firstBuf);
    ASSERT_TRUE(q.buf != NULL);

    queuePacketDeinit(&q);
}

/* ═══════════════════════  4. Deinit safety  ══════════════════════════════ */

/** @brief Deinit on NULL or a zero-initialised struct is safe. */
static void testDeinitNullSafety(void) {
    /* NULL pointer — explicitly guarded. */
    queuePacketDeinit(NULL);

    /* Zero-initialised stack struct — buf is NULL, free(NULL) is safe. */
    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketDeinit(&q);
}

/** @brief Calling Deinit twice on the same queue is safe — the second
 *         call sees buf == NULL and free(NULL) is a no-op. */
static void testDeinitDoubleSafety(void) {
    enum { TestCap = 4 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);
    queuePacketDeinit(&q);
    queuePacketDeinit(&q);
}

/* ═══════════════════════  5. Lifecycle  ══════════════════════════════════ */

/** @brief Init → Deinit → Init with a different capacity reuses the
 *         queue struct correctly. */
static void testInitDeinitInitReuse(void) {
    enum { FirstCap = 4, SecondCap = 16 };
    enum { TestSeq = 42 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));

    ASSERT_INT_EQ(queuePacketInit(&q, FirstCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, FirstCap);
    queuePacketDeinit(&q);

    ASSERT_INT_EQ(queuePacketInit(&q, SecondCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, SecondCap);
    ASSERT_TRUE(queuePacketIsEmpty(&q));

    Packet pkt = makeTestPacket(MsgChat, TestSeq);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    ASSERT_FALSE(queuePacketIsEmpty(&q));

    queuePacketDeinit(&q);
}

/* ═══════════════════════  6. Memory safety  ══════════════════════════════ */

/** @brief Operations on a Deinit-ed queue that avoid dereferencing the
 *         now-NULL buf are safe; Push would crash and is documented as
 *         undefined behaviour after Deinit. */
static void testUseAfterDeinit(void) {
    enum { TestCap = 4 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);
    queuePacketDeinit(&q);

    /* IsEmpty reads head == tail (still 0 from Init) → true. */
    ASSERT_TRUE(queuePacketIsEmpty(&q));

    /* Pop checks IsEmpty first — returns ContainerFail without touching buf. */
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerFail);
}

/* ═══════════════════════  7. Empty queue operations  ═════════════════════ */

/** @brief Front and Pop on an empty queue both return ContainerFail. */
static void testEmptyQueueOperations(void) {
    enum { TestCap = 4 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    ASSERT_TRUE(queuePacketIsEmpty(&q));

    Packet result;
    ASSERT_INT_EQ(queuePacketFront(&q, &result), ContainerFail);
    ASSERT_INT_EQ(queuePacketPop(&q), ContainerFail);

    queuePacketDeinit(&q);
}

/* ═══════════════════════  8. Push / Front round-trip  ════════════════════ */

/** @brief Push followed by Front returns an identical Packet struct
 *         (header fields and payload pointer).  Front on a non-empty
 *         queue is idempotent. */
static void testPushFrontRoundTrip(void) {
    enum { TestCap = 4 };
    enum { SeqA = 42, SeqB = 7 };

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

    /* Front is idempotent — still returns the first element. */
    Packet pkt2 = makeTestPacket(MsgLoginReq, SeqB);
    ASSERT_INT_EQ(queuePacketPush(&q, pkt2), ContainerSucc);
    ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
    ASSERT_UINT_EQ(front.header.sequenceID, SeqA);

    queuePacketDeinit(&q);
}

/* ═══════════════════════  9. FIFO order  ═════════════════════════════════ */

/** @brief Push N elements, then Front + Pop N times yields the elements
 *         in the same order.  Pop genuinely advances — Front afterwards
 *         returns the next element. */
static void testPushPopFifoOrder(void) {
    enum { TestCap = 4, NumPkts = 3 };

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

/* ═══════════════════════ 10. Capacity boundary  ══════════════════════════ */

/** @brief Pushing capacity elements triggers Reserve on the last push;
 *         all elements survive the reallocation and are retrievable in
 *         FIFO order. */
static void testPushToFullCapacity(void) {
    enum { TestCap = 4 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    /* Push TestCap-1 elements — no Reserve yet. */
    for (uint32_t i = 0; i < (uint32_t)(TestCap - 1); i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_FALSE(queuePacketIsEmpty(&q));
    ASSERT_UINT_EQ(q.capacity, TestCap);

    /* The TestCap-th push wraps tail → Reserve doubles capacity. */
    Packet last = makeTestPacket(MsgChat, (uint32_t)(TestCap - 1));
    ASSERT_INT_EQ(queuePacketPush(&q, last), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, TestCap * 2);

    /* All elements still in FIFO order. */
    for (uint32_t i = 0; i < TestCap; i++) {
        Packet front;
        ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
        ASSERT_UINT_EQ(front.header.sequenceID, i);
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

/* ═══════════════════════ 11. Reserve from non-zero head  ═════════════════ */

/** @brief The most complex code path in Reserve: head > 0 when the
 *         buffer fills up.  The do-while copy loop must correctly
 *         linearise elements that wrap around the old circular buffer. */
static void testReserveFromNonZeroHead(void) {
    enum { InitCap = 4, PopCount = 2, PushAfterPop = 6 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, InitCap);

    /* Fill to capacity → Reserve: head=0, tail=4, cap=8. */
    for (uint32_t i = 0; i < InitCap; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, InitCap * 2);

    /* Pop 2 elements — head moves to 2. */
    for (int i = 0; i < PopCount; i++) {
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.head, (size_t)PopCount);

    /* Push 6 more.  tail wraps past capacity end and catches head at
     * position 2, triggering a second Reserve from head=2. */
    for (uint32_t i = InitCap; i < InitCap + (uint32_t)PushAfterPop; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, InitCap * 2 * 2);

    /* Verify FIFO order: elements 2 through 9. */
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

/* ═══════════════════════ 12. Multiple Reserve cycles  ════════════════════ */

/** @brief Pushing well beyond initial capacity triggers multiple
 *         successive Reserve calls; capacity doubles each time and all
 *         data survives. */
static void testMultipleReserveCycles(void) {
    enum { InitCap = 4, TotalPushes = 10 };
    /* Expected: 4 → Reserve on push #4 → 8 → Reserve on push #8 → 16. */
    enum { ExpectedFinalCap = 16 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, InitCap);

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

/* ═══════════════════════ 13. Empty and refill  ═══════════════════════════ */

/** @brief After draining a queue completely, pushing new elements
 *         reuses the existing buffer without triggering Reserve and
 *         without leaking stale data. */
static void testEmptyAndRefill(void) {
    enum { TestCap = 4 };
    enum { NewSeq = 99 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    queuePacketInit(&q, TestCap);

    /* Fill and drain. */
    for (uint32_t i = 0; i < TestCap; i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    for (uint32_t i = 0; i < TestCap; i++) {
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    size_t capAfterDrain = q.capacity;

    /* Refill with a single element. */
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

/* ═══════════════════════ 14. Large capacity stress  ══════════════════════ */

/** @brief A queue initialised with a large capacity survives a full
 *         Reserve cycle and all elements remain retrievable. */
static void testLargeCapacityStress(void) {
    enum { LargeCap = 10000 };

    QueuePacket q;
    memset(&q, 0, sizeof(q));
    ASSERT_INT_EQ(queuePacketInit(&q, LargeCap), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, LargeCap);

    /* Push LargeCap-1 elements — no Reserve yet. */
    for (uint32_t i = 0; i < (uint32_t)(LargeCap - 1); i++) {
        Packet pkt = makeTestPacket(MsgChat, i);
        ASSERT_INT_EQ(queuePacketPush(&q, pkt), ContainerSucc);
    }
    ASSERT_UINT_EQ(q.capacity, LargeCap);

    /* The LargeCap-th push triggers Reserve. */
    Packet last = makeTestPacket(MsgChat, (uint32_t)(LargeCap - 1));
    ASSERT_INT_EQ(queuePacketPush(&q, last), ContainerSucc);
    ASSERT_UINT_EQ(q.capacity, LargeCap * 2);

    /* Verify every element. */
    for (uint32_t i = 0; i < LargeCap; i++) {
        Packet front;
        ASSERT_INT_EQ(queuePacketFront(&q, &front), ContainerSucc);
        ASSERT_UINT_EQ(front.header.sequenceID, i);
        ASSERT_INT_EQ(queuePacketPop(&q), ContainerSucc);
    }
    ASSERT_TRUE(queuePacketIsEmpty(&q));
    queuePacketDeinit(&q);
}

/* ═══════════════════════  main  ══════════════════════════════════════════ */

int main(void) {
    printf("test_container:\n");

    /* 1. Constants */
    RUN_TEST(testContainerConstants);

    /* 2. Init basics & boundaries */
    RUN_TEST(testInitValidCapacity);
    RUN_TEST(testInitZeroCapacityDefault);
    RUN_TEST(testInitCapacityOne);

    /* 3. Init error paths */
    RUN_TEST(testInitOverflowCapacity);
    RUN_TEST(testDoubleInitLeak);

    /* 4. Deinit safety */
    RUN_TEST(testDeinitNullSafety);
    RUN_TEST(testDeinitDoubleSafety);

    /* 5. Lifecycle */
    RUN_TEST(testInitDeinitInitReuse);

    /* 6. Memory safety */
    RUN_TEST(testUseAfterDeinit);

    /* 7. Empty queue operations */
    RUN_TEST(testEmptyQueueOperations);

    /* 8. Push / Front round-trip */
    RUN_TEST(testPushFrontRoundTrip);

    /* 9. FIFO order */
    RUN_TEST(testPushPopFifoOrder);

    /* 10. Capacity boundary */
    RUN_TEST(testPushToFullCapacity);

    /* 11. Reserve from non-zero head */
    RUN_TEST(testReserveFromNonZeroHead);

    /* 12. Multiple Reserve cycles */
    RUN_TEST(testMultipleReserveCycles);

    /* 13. Empty and refill */
    RUN_TEST(testEmptyAndRefill);

    /* 14. Large capacity stress */
    RUN_TEST(testLargeCapacityStress);

    return TEST_REPORT();
}
