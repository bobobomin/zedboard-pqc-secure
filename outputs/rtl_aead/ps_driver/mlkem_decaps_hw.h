#ifndef MLKEM_DECAPS_HW_H
#define MLKEM_DECAPS_HW_H
#include <stdint.h>
#include <stddef.h>
#define MLKEM512_SECRET_KEY_BYTES 1632u
#define MLKEM512_CIPHERTEXT_BYTES 768u
typedef struct { uintptr_t base; uint32_t poll_limit; } mlkem_decaps_hw_t;
enum { MLKEM_HW_OK=0, MLKEM_HW_TIMEOUT=-1, MLKEM_HW_ARGUMENT=-2,
       MLKEM_HW_REJECTED=-3 };
void mlkem_decaps_hw_init(mlkem_decaps_hw_t *d,uintptr_t base,uint32_t poll_limit);
int mlkem_decaps_hw_load_secret_key(mlkem_decaps_hw_t *d,const uint8_t sk[1632]);
int mlkem_decaps_hw_start(mlkem_decaps_hw_t *d,const uint8_t ct[768],
                          uint8_t slot,uint32_t session_id);
int mlkem_decaps_hw_wait(mlkem_decaps_hw_t *d);
#endif
