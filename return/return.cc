#include <stdint.h>
#include <stddef.h>
#include <string.h>

int return_(const uint8_t *Data, size_t DataSize) {
   char * res;
   if (DataSize > 0){
       memcpy(res, Data, DataSize);
   }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    return_(Data, Size);
    return 0;
}