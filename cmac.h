#ifndef _CMAC_H_
#define _CMAC_H_

#include <stdio.h>
#include <stdint.h>

int cmac_generate_subkey(uint8_t *key, uint8_t *key1, uint8_t *key2);

#endif