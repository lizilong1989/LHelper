//
//  aes.hpp
//
//  Created by zilong.li on 2017/7/6.
//

#ifndef aes_hpp
#define aes_hpp

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void cipher(uint8_t *in, uint8_t *out, uint8_t *w);
void inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w);
uint8_t *getW(uint8_t *key);

#endif /* aes_hpp */
