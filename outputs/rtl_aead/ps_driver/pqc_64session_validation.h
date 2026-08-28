#ifndef PQC_64SESSION_VALIDATION_H
#define PQC_64SESSION_VALIDATION_H

#include <stdint.h>

int pqc_64session_validation_run(uintptr_t mlkem_base,
                                 uintptr_t aead_base,
                                 uint32_t poll_limit);

#endif
