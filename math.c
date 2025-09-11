#include <stdio.h>
#include "math.h"


uint32_t ROTR(uint32_t var, uint8_t pos)
{
    uint8_t idx;
    uint32_t retVal = var;
    for(idx = 0; idx < pos; idx++){
        retVal = (retVal >> 1) | ((retVal & 0x01) << 7);
    }
    return retVal;
}