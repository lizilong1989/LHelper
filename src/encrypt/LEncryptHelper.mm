//
//  LEncryptHelper.h
//
//  Created by zilong.li on 2017/6/23.
//

#import "LEncryptHelper.h"

#include "des.hpp"

static LEncryptHelper *helper = nil;

@interface LEncryptHelper ()
{
}
@end

@implementation LEncryptHelper

+ (instancetype)shareHelper
{
    if (helper == nil) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            helper = [[self alloc] init];
        });
    }
    return helper;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        
    }
    return self;
}

- (NSData *)desEncryptWithData:(NSData*)aData key:(NSString *)aKey
{
    NSMutableData *retData = nil;
    if (aData == nil) {
        return retData;
    }
    
    if (aData == NULL) {
        return retData;
    }
    
    if (aKey.length == 0) {
        return retData;
    }
    
    std::bitset<64> key = charToBitset([aKey cStringUsingEncoding:NSUTF8StringEncoding]);
    setSecretkey(key);
    generateKeys();
    
    retData = [NSMutableData data];
    
    NSInteger length = [aData length];
    char temp[[aData length]];
    int position = 0;
    [aData getBytes:&temp range:NSMakeRange(0, [aData length])];
    for (int i = 0; i < [aData length]; i+=8) {
        char test[8];
        if (i + 8 <= length) {
            for (int j = 0; j < 8; j++) {
                test[j] = temp[i + j];
            }
        } else {
            for (int j = 0; j < 8; j++) {
                if (j + i >= length) {
                    test[j] = 0;
                } else {
                    test[j] = temp[i + j];
                    position++;
                }
            }
        }
        
        std::bitset<64> plain = charToBitset(test);
        std::bitset<64> cipher = encrypt(plain);
        
        for (int i = 0; i < 8; i ++) {
            std::bitset<8> temp;
            for (int j = 0; j < 8; j ++) {
                temp[j] = cipher[i * 8 + j];
            }
            Byte byte = (Byte)(0XFF & temp.to_ulong());
            [retData appendBytes:&byte length:1];
        }
    }
    
    //补位长度
    Byte byte = (Byte)(0XFF & position);
    [retData appendBytes:&byte length:1];
    
    return retData;
}


- (NSData *)desDecodeWithData:(NSData*)aData key:(NSString *)aKey
{
    NSMutableData *retData = nil;
    if (aData == nil) {
        return retData;
    }
    
    if (aData == NULL) {
        return retData;
    }
    
    if (aKey.length == 0) {
        return retData;
    }
    
    std::bitset<64> key = charToBitset([aKey cStringUsingEncoding:NSUTF8StringEncoding]);
    setSecretkey(key);
    generateKeys();
    
    retData = [NSMutableData data];
    NSInteger length = [aData length];
    char temp[[aData length]];
    [aData getBytes:&temp range:NSMakeRange(0, [aData length])];
    
    //获取补位长度
    int position = temp[[aData length]-1];;
    
    for (int i = 0; i < [aData length] - 1; i+=8) {
        char test[8];
        if (i + 8 <= length) {
            for (int j = 0; j < 8; j++) {
                test[j] = temp[i + j];
            }
        }
        
        std::bitset<64> plain = charToBitset(test);
        std::bitset<64> temp_plain = decrypt(plain);
        
        int to = 8;
        if (position != 0) {
            if (i + 8 == [aData length] - 1) {
                to = position;
            }
        }
        for (int i = 0; i < to; i ++) {
            std::bitset<8> temp;
            for (int j = 0; j < 8; j ++) {
                temp[j] = temp_plain[i * 8 + j];
            }
            Byte byte = (Byte)(0XFF & temp.to_ulong());
            [retData appendBytes:&byte length:1];
        }
    }
    
    return retData;
}

- (NSData *)threeDesEncryptWithData:(NSData*)aData
{
    NSData *retData = nil;
    return retData;
}

- (NSData *)threeDesDecodeWithData:(NSData*)aData
{
    NSData *retData = nil;
    return retData;
}

@end
