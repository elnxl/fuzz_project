#include <stdint.h>
#include <stddef.h>

void shift(const uint8_t *Data, size_t DataSize) {
   if (DataSize > 0){
       Data[0] >> DataSize + 1;
   }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    shift(Data, Size);
    return 0;
}