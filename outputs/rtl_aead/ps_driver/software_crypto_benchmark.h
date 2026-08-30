#ifndef SOFTWARE_CRYPTO_BENCHMARK_H
#define SOFTWARE_CRYPTO_BENCHMARK_H

/* Runs Cortex-A9 portable-C baselines using the same ML-KEM-512 KAT and
 * fixed 64-byte ChaCha20-Poly1305 packet format as the PL design. */
int software_crypto_benchmark_run(void);

#endif
