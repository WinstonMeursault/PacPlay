/**
 * @file container.h
 * @brief Container data structures for PacPlay.
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

#ifndef CONTAINER_H
#define CONTAINER_H

#include <stdbool.h>
#include <stdlib.h>

#include "protocol.h"

typedef enum { ContainerSucc = 0, ContainerFail = -1 } ContainerRes;

#define QUEUE_DEFAULT_CAPACITY 8

/**
 * @brief Declare a circular queue type @c Queue##T and its full API for
 *        element type @c T.
 *
 * The queue is a circular buffer that stores elements by @b value (shallow
 * copy via struct assignment).  It grows automatically when full: the
 * internal @c Reserve function doubles the capacity.
 *
 * @param T The element type stored in the queue.  Must be copy-assignable.
 *
 * ### Generated type
 *
 * @c struct @c Queue##T with the following fields:
 *   - @c T @c *buf — underlying heap-allocated element array.
 *   - @c size_t @c capacity — number of element slots currently allocated.
 *   - @c size_t @c head — index of the front element (FIFO dequeue point).
 *   - @c size_t @c tail — index one past the last element (FIFO enqueue point).
 *
 * ### Generated functions
 *
 * | Function           | Signature                                   | Brief                                                       |
 * |--------------------|---------------------------------------------|-------------------------------------------------------------|
 * | @c queueT##Init    | @c ContainerRes @c (QueueT @c *, @c size_t) | Allocate capacity slots (0 uses @c QUEUE_DEFAULT_CAPACITY). |
 * | @c queueT##Deinit  | @c void @c (QueueT @c *)                    | Free the internal buffer (NULL-safe, double-call safe).     |
 * | @c queueT##Front   | @c ContainerRes @c (QueueT @c *, @c T @c *) | Copy the front element into @c *result (shallow copy).      |
 * | @c queueT##Push    | @c ContainerRes @c (QueueT @c *, @c T)      | Enqueue an element; auto-resizes if full.                   |
 * | @c queueT##Pop     | @c ContainerRes @c (QueueT @c *)            | Advance head (does @b not return or free the element).      |
 * | @c queueT##IsEmpty | @c bool @c (QueueT @c *)                    | Return @c true if @c head @c == @c tail.                    |
 *
 * @note @c Deinit only frees @c self->buf; it does @b not free memory
 *       owned by individual elements (e.g. @c Packet::payload).  Callers
 *       queuing elements that contain heap-allocated pointers must clean
 *       them up manually before calling @c Deinit.
 *
 * @warning Calling @c Init on an already-initialised queue leaks the old
 *          buffer.  Always @c Deinit before re-initialising, or ensure
 *          the struct is zero-filled on first use.
 *
 * @warning @c Pop does @b not return or free the popped element.  To
 *          retrieve the value first, call @c Front then @c Pop.
 */
#define QUEUE_DECLARE(T)                                                                        \
    typedef struct {                                                                            \
        T *buf; /*NOLINT(bugprone-macro-parentheses)*/ /**< Heap-allocated element array. */    \
        size_t capacity; /**< Number of allocated element slots. */                             \
        size_t head; /**< Index of the front element (FIFO dequeue). */                         \
        size_t tail; /**< Index one past the last element (FIFO enqueue). */                    \
    } Queue##T;                                                                                 \
    ContainerRes queue##T##Init(Queue##T *self, size_t capacity);                               \
    void queue##T##Deinit(Queue##T *self);                                                      \
    ContainerRes queue##T##Front(                                                               \
        Queue##T *self, T *result); /*NOLINT(bugprone-macro-parentheses)*/                      \
    ContainerRes queue##T##Push(Queue##T *self, T data);                                        \
    ContainerRes queue##T##Pop(Queue##T *self);                                                 \
    bool queue##T##IsEmpty(Queue##T *self);

QUEUE_DECLARE(Packet)

#endif // CONTAINER_H
