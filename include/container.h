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

#include "log.h"
#include <stdbool.h>
#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
#define FUNC_UNUSED __attribute__((unused))
#else
#define FUNC_UNUSED
#endif

typedef enum { ContainerSucc = 0, ContainerFail = -1 } ContainerRes;

#define QUEUE_DEFAULT_CAPACITY 8
#define ARRAY_DEFAULT_CAPACITY 8

#define USE_DEFAULT_CAPACITY 0

/**
 * @brief Define a circular queue type @c Queue##T with its full @c static
 *        @c inline API for element type @c T.
 *
 * This is a single-step macro: include @c container.h and call
 * @c QUEUE_DEFINE(T) — no separate @c .c implementation file is needed.
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
 * | Function          | Signature                            | Brief |
 * |-------------------|--------------------------------------|-------|
 * | queueT##Init    | ContainerRes(QueueT *, size_t)     | Allocate capacity
 * slots (0 fallback to QUEUE_DEFAULT_CAPACITY). | | queueT##Deinit  |
 * void(QueueT *)                     | Free internal buffer (NULL-safe,
 * double-call safe). | | queueT##Front   | ContainerRes(QueueT *, T *)        |
 * Shallow-copy front element to *result; fail if empty. | | queueT##Push    |
 * ContainerRes(QueueT *, T)          | Enqueue an element; auto-resizes if
 * full. | | queueT##Pop     | ContainerRes(QueueT *)             | Advance head
 * (does NOT return or free the element). | | queueT##IsEmpty | bool(QueueT *)
 * | Return true iff head == tail. |
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
#define QUEUE_DEFINE(T)                                                        \
    typedef struct {                                                           \
        T *buf; /*NOLINT(bugprone-macro-parentheses)*/ /**< Heap-allocated     \
                                                          element array. */    \
        size_t capacity; /**< Number of allocated element slots. */            \
        size_t head;     /**< Index of the front element (FIFO dequeue). */    \
        size_t tail; /**< Index one past the last element (FIFO enqueue). */   \
    } Queue##T;                                                                \
    FUNC_UNUSED static inline bool queue##T##IsEmpty(const Queue##T *self) {   \
        return self->head == self->tail;                                       \
    }                                                                          \
    /**                                                                        \
     * @brief Double the capacity of the queue and linearise its contents.     \
     *                                                                         \
     * Takes a snapshot of the current queue, allocates a new buffer of        \
     * @c 2*capacity slots, copies all elements from the old buffer in FIFO    \
     * order (head-to-tail), then frees the old buffer.  If allocation         \
     * fails, the original queue state is rolled back to its pre-Reserve       \
     * state (old buffer pointer restored).                                    \
     *                                                                         \
     * @note Elements are copied via struct assignment (shallow copy).         \
     * @return @c ContainerSucc on success, @c ContainerFail on OOM.           \
     */                                                                        \
    FUNC_UNUSED static inline ContainerRes queue##T##Reserve(Queue##T *self) { \
        Queue##T before = *self;                                               \
        self->buf = malloc(sizeof(T) * self->capacity * 2);                    \
        if (self->buf == NULL) {                                               \
            LOG_ERROR("Failed to allocate queue with type " #T ": %s (%d)",    \
                      strerror(errno), errno);                                 \
            self->buf = before.buf;                                            \
            return ContainerFail;                                              \
        }                                                                      \
        self->capacity *= 2;                                                   \
        self->head = 0;                                                        \
        self->tail = 0;                                                        \
        do {                                                                   \
            self->buf[self->tail] = before.buf[before.head];                   \
            ++self->tail;                                                      \
            before.head = (before.head + 1) % before.capacity;                 \
        } while (before.head != before.tail);                                  \
        free(before.buf);                                                      \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes queue##T##Init(Queue##T *self,      \
                                                          size_t capacity) {   \
        if (capacity == USE_DEFAULT_CAPACITY) {                                \
            capacity = QUEUE_DEFAULT_CAPACITY;                                 \
        }                                                                      \
        self->capacity = capacity;                                             \
        self->buf = malloc(sizeof(T) * self->capacity);                        \
        if (self->buf == NULL) {                                               \
            LOG_ERROR("Failed to allocate queue with type " #T ": %s (%d)",    \
                      strerror(errno), errno);                                 \
            return ContainerFail;                                              \
        }                                                                      \
        self->head = 0;                                                        \
        self->tail = 0;                                                        \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline void queue##T##Deinit(Queue##T *self) {          \
        if (self == NULL) {                                                    \
            return;                                                            \
        }                                                                      \
        free(self->buf);                                                       \
        self->buf = NULL;                                                      \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes queue##T##Front(                    \
        Queue##T *self, T *result) { /*NOLINT(bugprone-macro-parentheses)*/    \
        if (!queue##T##IsEmpty(self)) {                                        \
            *result = self->buf[self->head];                                   \
            return ContainerSucc;                                              \
        }                                                                      \
        return ContainerFail;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes queue##T##Push(Queue##T *self,      \
                                                          T data) {            \
        self->buf[self->tail] = data;                                          \
        self->tail = (self->tail + 1) % self->capacity;                        \
        if (self->tail == self->head) {                                        \
            return queue##T##Reserve(self);                                    \
        }                                                                      \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes queue##T##Pop(Queue##T *self) {     \
        if (queue##T##IsEmpty(self)) {                                         \
            return ContainerFail;                                              \
        }                                                                      \
        self->head = (self->head + 1) % self->capacity;                        \
        return ContainerSucc;                                                  \
    }

/**
 * @brief Define a dynamic array type @c Array##T with its full @c static
 *        @c inline API for element type @c T.
 *
 * This is a single-step macro: include @c container.h and call
 * @c ARRAY_DEFINE(T) — no separate @c .c implementation file is needed.
 *
 * The array stores elements by @b value (shallow copy via struct
 * assignment) in a contiguous heap-allocated buffer.  It grows
 * automatically when full: the internal @c Reserve function doubles
 * the capacity via @c realloc.
 *
 * @param T The element type stored in the array.  Must be copy-assignable.
 *
 * ### Generated type
 *
 * @c struct @c Array##T with the following fields:
 *   - @c T @c *buf — underlying heap-allocated element array.
 *   - @c size_t @c capacity — number of element slots currently allocated.
 *   - @c size_t @c size — number of elements currently stored.
 *
 * ### Generated functions
 *
 * | Function           | Signature                               | Brief |
 * |--------------------|-----------------------------------------|-------|
 * | arrayT##Init     | ContainerRes(ArrayT *, size_t)        | Allocate
 * capacity slots (0 fallback to ARRAY_DEFAULT_CAPACITY). | | arrayT##Deinit   |
 * void(ArrayT *)                        | Free internal buffer (NULL-safe,
 * double-call safe). | | arrayT##Set      | ContainerRes(ArrayT *, size_t, T)
 * | Overwrite element at index (must be < size). | | arrayT##Get      |
 * ContainerRes(ArrayT *, size_t, T *)   | Shallow-copy element at index to
 * *dest; fail if OOB. | | arrayT##PushBack | ContainerRes(ArrayT *, T) | Append
 * an element; auto-resizes if full. | | arrayT##PopBack  | ContainerRes(ArrayT
 * *)                | Remove the last element (does NOT return or free it). |
 * | arrayT##Size     | size_t(const ArrayT *)                | Return current
 * element count. |
 *
 * @note @c Deinit only frees @c self->buf; it does @b not free memory
 *       owned by individual elements.  Callers storing elements that
 *       contain heap-allocated pointers must clean them up manually
 *       before calling @c Deinit.
 *
 * @warning Calling @c Init on an already-initialised array leaks the old
 *          buffer.  Always @c Deinit before re-initialising, or ensure
 *          the struct is zero-filled on first use.
 *
 * @warning @c PopBack does @b not return or free the popped element.  To
 *          retrieve the value first, call @c Get with @c size-1 then
 *          @c PopBack.
 *
 * @warning @c Set and @c Get perform bounds checking against @c size
 *          (not @c capacity).  Indices must satisfy
 *          @c 0 @c <= @c index @c < @c size, otherwise
 *          @c ContainerFail is returned.
 */
#define ARRAY_DEFINE(T)                                                        \
    typedef struct {                                                           \
        T *buf; /*NOLINT(bugprone-macro-parentheses)*/ /**< Heap-allocated     \
                                                           element array. */   \
        size_t capacity; /**< Number of allocated element slots. */            \
        size_t size;     /**< Number of elements currently stored. */          \
    } Array##T;                                                                \
    FUNC_UNUSED static inline ContainerRes array##T##Reserve(Array##T *self) { \
        T *new = /*NOLINT(bugprone-macro-parentheses)*/                        \
            realloc(self->buf, self->capacity * 2 * sizeof(T));                \
        if (new == NULL) {                                                     \
            LOG_ERROR("Failed to allocate array with type " #T ": %s (%d)",    \
                      strerror(errno), errno);                                 \
            return ContainerFail;                                              \
        }                                                                      \
        self->capacity *= 2;                                                   \
        self->buf = new;                                                       \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes array##T##Init(Array##T *self,      \
                                                          size_t capacity) {   \
        if (capacity == USE_DEFAULT_CAPACITY) {                                \
            capacity = ARRAY_DEFAULT_CAPACITY;                                 \
        }                                                                      \
        self->capacity = capacity;                                             \
        self->size = 0;                                                        \
        self->buf = malloc(sizeof(T) * self->capacity);                        \
        if (self->buf == NULL) {                                               \
            LOG_ERROR("Failed to allocate array with type " #T ": %s (%d)",    \
                      strerror(errno), errno);                                 \
            return ContainerFail;                                              \
        }                                                                      \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline void array##T##Deinit(Array##T *self) {          \
        if (self == NULL) {                                                    \
            return;                                                            \
        }                                                                      \
        free(self->buf);                                                       \
        self->buf = NULL;                                                      \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes array##T##Index(                    \
        Array##T *self, size_t index, T **dest) {                              \
        if (index >= self->size) {                                             \
            return ContainerFail;                                              \
        }                                                                      \
        *dest = &self->buf[index];                                             \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes array##T##PushBack(Array##T *self,  \
                                                              T data) {        \
        if (self->size >= self->capacity) {                                    \
            ContainerRes res = array##T##Reserve(self);                        \
            if (res != ContainerSucc) {                                        \
                return res;                                                    \
            }                                                                  \
        }                                                                      \
        self->buf[self->size] = data;                                          \
        ++self->size;                                                          \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes array##T##PopBack(Array##T *self) { \
        if (self->size == 0) {                                                 \
            return ContainerFail;                                              \
        }                                                                      \
        --self->size;                                                          \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes array##T##Set(                      \
        Array##T *self, size_t index, T data) {                                \
        if (index >= self->size) {                                             \
            return ContainerFail;                                              \
        }                                                                      \
        self->buf[index] = data;                                               \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline ContainerRes array##T##Get(                      \
        Array##T *self, size_t index,                                          \
        T *dest) { /*NOLINT(bugprone-macro-parentheses)*/                      \
        if (index >= self->size) {                                             \
            return ContainerFail;                                              \
        }                                                                      \
        *dest = self->buf[index];                                              \
        return ContainerSucc;                                                  \
    }                                                                          \
    FUNC_UNUSED static inline size_t array##T##Size(const Array##T *self) {    \
        return self->size;                                                     \
    }

#endif // CONTAINER_H
