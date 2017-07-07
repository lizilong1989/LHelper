//
//  des.hpp
//
//  Created by zilong.li on 2017/6/23.
//

#ifndef des_hpp
#define des_hpp

#include <iostream>
#include <fstream>
#include <bitset>
#include <string>

std::bitset<64> decrypt(std::bitset<64>& cipher);
std::bitset<64> encrypt(std::bitset<64>& plain);
std::bitset<64> charToBitset(const char s[8]);
void setSecretkey(std::bitset<64>& aKey);
void generateKeys();

#endif /* des_hpp */
