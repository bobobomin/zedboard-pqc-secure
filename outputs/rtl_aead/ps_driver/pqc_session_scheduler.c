#include "pqc_session_scheduler.h"

#include <string.h>

static uint32_t slot_mask(uint8_t slot)
{
    return (uint32_t)1u << (slot & 31u);
}

static uint8_t first_set_bit(uint32_t value)
{
    uint8_t bit = 0u;
    while ((value & 1u) == 0u) {
        value >>= 1;
        ++bit;
    }
    return bit;
}

void pqc_scheduler_init(pqc_session_scheduler_t *scheduler)
{
    if (scheduler == NULL)
        return;
    memset(scheduler, 0, sizeof(*scheduler));
}

int pqc_scheduler_has_pending(const pqc_session_scheduler_t *scheduler,
                              uint8_t slot)
{
    if (scheduler == NULL || slot >= PQC_SCHEDULER_SESSIONS)
        return 0;
    return (scheduler->ready_bitmap[slot >> 5] & slot_mask(slot)) != 0u;
}

int pqc_scheduler_submit(pqc_session_scheduler_t *scheduler, uint8_t slot,
                         const pqc_packet_request_t *request)
{
    if (scheduler == NULL || request == NULL
        || slot >= PQC_SCHEDULER_SESSIONS
        || request->message_length > AEAD_HW_PACKET_BYTES)
        return -1;
    if (pqc_scheduler_has_pending(scheduler, slot))
        return 0;

    scheduler->pending[slot] = *request;
    scheduler->ready_bitmap[slot >> 5] |= slot_mask(slot);
    return 1;
}

int pqc_scheduler_take_next(pqc_session_scheduler_t *scheduler,
                            uint8_t *slot,
                            pqc_packet_request_t *request)
{
    uint8_t start;
    uint8_t start_word;
    uint8_t other_word;
    uint8_t start_bit;
    uint8_t candidate;
    uint32_t candidates;
    uint32_t mask;
    uint32_t word;

    if (scheduler == NULL || slot == NULL || request == NULL)
        return 0;

    start = scheduler->next_slot;
    start_word = start >> 5;
    other_word = start_word ^ 1u;
    start_bit = start & 31u;

    candidates = scheduler->ready_bitmap[start_word]
               & (0xffffffffu << start_bit);
    if (candidates != 0u) {
        candidate = (uint8_t)(32u * start_word + first_set_bit(candidates));
    } else if (scheduler->ready_bitmap[other_word] != 0u) {
        candidate = (uint8_t)(32u * other_word
                              + first_set_bit(scheduler->ready_bitmap[other_word]));
    } else {
        candidates = scheduler->ready_bitmap[start_word]
                   & ~(0xffffffffu << start_bit);
        if (candidates == 0u)
            return 0;
        candidate = (uint8_t)(32u * start_word + first_set_bit(candidates));
    }

    mask = slot_mask(candidate);
    word = candidate >> 5;
    scheduler->ready_bitmap[word] &= ~mask;
    scheduler->next_slot = (uint8_t)((candidate + 1u)
                                     & (PQC_SCHEDULER_SESSIONS - 1u));
    *slot = candidate;
    *request = scheduler->pending[candidate];
    return 1;
}
