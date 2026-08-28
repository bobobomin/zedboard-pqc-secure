#ifndef UART_SECURE_DEMO_H
#define UART_SECURE_DEMO_H

#include <stdint.h>

int uart_secure_demo_run(uintptr_t mlkem_base, uintptr_t aead_base,
                         uint32_t poll_limit);

#endif
