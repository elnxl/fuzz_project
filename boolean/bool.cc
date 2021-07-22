#include <stdint.h>
#include <stddef.h>

bool boolean(const uint8_t *Data, size_t DataSize) {
   bool a;
   if (DataSize > 0)
   {
       memset(&a, Data[0]+0x03, sizeof(bool));
    }
    return a;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    boolean(Data, Size);
    return 0;
}