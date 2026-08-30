#ifndef PQC_SESSION_SCHEDULER_H
#define PQC_SESSION_SCHEDULER_H

#include <stdint.h>

#include "aead_hw.h"

#define PQC_SCHEDULER_SESSIONS AEAD_HW_MAX_SESSIONS

typedef struct {
    uint8_t decrypt;
    uint8_t message_length;
    uint64_t packet_counter;
    uint8_t data[AEAD_HW_PACKET_BYTES];
    uint8_t tag[AEAD_HW_TAG_BYTES];
} pqc_packet_request_t;

typedef struct {
    uint32_t ready_bitmap[2];
    uint8_t next_slot;
    pqc_packet_request_t pending[PQC_SCHEDULER_SESSIONS];
} pqc_session_scheduler_t;

void pqc_scheduler_init(pqc_session_scheduler_t *scheduler);

/* One pending packet is retained per session. Ethernet RX should apply
 * backpressure or keep additional packets in its own queue. */
int pqc_scheduler_submit(pqc_session_scheduler_t *scheduler, uint8_t slot,
                         const pqc_packet_request_t *request);

/* Event-driven round robin: scans only two 32-bit ready words and returns
 * the next session that actually has work. Returns 1 on success, 0 if idle. */
int pqc_scheduler_take_next(pqc_session_scheduler_t *scheduler,
                            uint8_t *slot,
                            pqc_packet_request_t *request);

int pqc_scheduler_has_pending(const pqc_session_scheduler_t *scheduler,
                              uint8_t slot);

#endif
