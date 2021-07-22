#include <stdint.h>
#include <stddef.h>

void int_overflow(const uint8_t *Data, size_t DataSize) {
    int k = 0x7fffffff;
    k += Data[0];
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int_overflow(Data, Size);
    return 0;
}