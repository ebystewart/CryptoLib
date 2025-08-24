#ifndef _RAND_H_
#define _RAND_H_

void set_entropy(void);

int generate_random(uint8_t *buff, uint16_t size);

#endif