#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include "rand.h"
#include <sys/time.h>

/* Entropy has to be higher and changed every time random is to be generated 
   This helps avoiding repeated function */
void set_entropy(void)
{

}

int generate_random(uint8_t *buff, uint16_t size)
{
   volatile uint32_t temp;
   uint16_t idx = 0;
   struct timeval tv;
   if(!buff)
      assert(0);
   /* pseudo- random number generator using XorShift */
   /* ref: https://en.wikipedia.org/wiki/Xorshift */
#if 0
   while(idx < size){

      gettimeofday(&tv, NULL);
      temp = tv.tv_usec;
      //temp = time(NULL); /* not working */
      buff[idx] = (uint8_t)(temp | (temp << idx) ^ (temp ^ (!idx)));
      idx++;
   }
#endif
#if 1
for(int i = 0; i < size; i++){
   if(i%2){
      buff[i] = 0xAB;
   }
   else{
      buff[i] = 0xCD;
   }
}
#endif
}