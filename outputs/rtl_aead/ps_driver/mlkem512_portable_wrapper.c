/* Portable-C ML-KEM-512 baseline for the ARMv7-A Cortex-A9. */
#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_FILE "../mlkem_native_config.h"

#include "../../golden_reference/third_party/mlkem-native/mlkem/mlkem_native.c"
