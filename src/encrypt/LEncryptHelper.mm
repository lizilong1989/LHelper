//
//  LEncryptHelper.h
//
//  Created by zilong.li on 2017/6/23.
//

#import "LEncryptHelper.h"

#import <CommonCrypto/CommonCrypto.h>

#include "des.hpp"
#include "aes.hpp"

uint8_t theKey[] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f};

static LEncryptHelper *helper = nil;

@interface LEncryptHelper ()

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

#pragma mark - DES

- (void)setDesKey:(NSString*)aKey
{
    if (aKey.length == 0) {
        return;
    } else {
        std::bitset<64> key = charToBitset([aKey cStringUsingEncoding:NSUTF8StringEncoding]);
        setSecretkey(key);
        generateKeys();
    }
}

- (NSData *)desEncryptWithData:(NSData*)aData
                           key:(NSString *)aKey

{
    NSMutableData *retData = nil;
    if (![self _validWithData:aData]) {
        return retData;
    }
    
    if (aKey.length != 0) {
        std::bitset<64> key = charToBitset([aKey cStringUsingEncoding:NSUTF8StringEncoding]);
        setSecretkey(key);
        generateKeys();
    }
    
    return [self EMAES256EncryptWithKey:[aKey dataUsingEncoding:NSUTF8StringEncoding] data:aData];

    /*
    retData = [NSMutableData data];
    
    NSInteger length = [aData length];
    char temp[[aData length]];
    int position = 0;
    [aData getBytes:&temp range:NSMakeRange(0, [aData length])];
    for (int i = 0; i < [aData length]; i+=8) {
        char test[8];
        if (i + 8 <= length) {
            [aData getBytes:&test range:NSMakeRange(i, 8)];
        } else {
            //补位
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
            Byte byte = (Byte)(temp.to_ulong());
            [retData appendBytes:&byte length:1];
        }
    }
    
    //补位长度
    Byte byte = (Byte)(position);
    [retData appendBytes:&byte length:1];
    
    return retData;*/
}


- (NSData *)desDecodeWithData:(NSData*)aData
                          key:(NSString *)aKey
{
    NSMutableData *retData = nil;
    if (![self _validWithData:aData]) {
        return retData;
    }
    
    if (aKey.length != 0) {
        std::bitset<64> key = charToBitset([aKey cStringUsingEncoding:NSUTF8StringEncoding]);
        setSecretkey(key);
        generateKeys();
    }
    
    return [self EMAES256DecryptWithKey:[aKey dataUsingEncoding:NSUTF8StringEncoding] data:aData];
/*
    retData = [NSMutableData data];
    NSInteger length = [aData length];
    char temp[[aData length]];
    [aData getBytes:&temp range:NSMakeRange(0, [aData length])];
    
    //获取补位长度
    int position = temp[[aData length]-1];
    
    for (int i = 0; i < [aData length] - 1; i+=8) {
        char test[8];
        if (i + 8 <= length) {
            [aData getBytes:&test range:NSMakeRange(i, 8)];
        }
        
        std::bitset<64> plain = charToBitset(test);
        std::bitset<64> temp_plain = decrypt(plain);
        
        int to = 8;
        if (i + 8 == [aData length] - 1) {
            if (position != 0) {
                to = position;
            }
        }
        for (int i = 0; i < to; i ++) {
            std::bitset<8> temp;
            for (int j = 0; j < 8; j ++) {
                temp[j] = temp_plain[i * 8 + j];
            }
            Byte byte = (Byte)(temp.to_ulong());
            [retData appendBytes:&byte length:1];
        }
    }
    
    return retData;
 */
}

#pragma mark - AES

- (NSData *)aesEncryptWithData:(NSData*)aData
                           key:(NSString *)aKey
                          type:(LEncryptType)aType
{
    NSMutableData *retData = nil;
    if (![self _validWithData:aData]) {
        return retData;
    }
    
    /*
     * Appendix C - Example Vectors
     */
    
    /* 128 bit key */
    /* uint8_t key[] = {
     0x00, 0x01, 0x02, 0x03,
     0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b,
     0x0c, 0x0d, 0x0e, 0x0f}; */
    
    /* 192 bit key */
    /* uint8_t key[] = {
     0x00, 0x01, 0x02, 0x03,
     0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b,
     0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13,
     0x14, 0x15, 0x16, 0x17}; */
    
    /* 256 bit key */
    /* uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f}; */
    
    uint8_t *w = [self _getWWithKey:aKey];
    NSInteger length = [aData length];
    retData = [NSMutableData data];
    switch (aType) {
        case LEncryptECB:
        {
            int baseLength = 16;
            for (int i = 0; i < length; i+=baseLength) {
                Byte temp[baseLength];
                Byte outTemp[baseLength];
                int tempLength = 0;
                if (i + baseLength < length) {
                    tempLength = baseLength;
                    [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                } else {
                    tempLength = (int)length - i;
                    [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                    for (int j = (int)length - i; j < baseLength; j++ ) {
                        temp[j] = 0;
                    }
                }
                cipher(temp, outTemp, w);
                [retData appendBytes:&outTemp length:baseLength];
            }
        }
            break;
        case LEncryptCBC:
        {
            int baseLength = 16;
            Byte last[baseLength];
            BOOL isFirst = YES;
            for (int i = 0; i < length; i+=baseLength) {
                Byte temp[baseLength];
                Byte outTemp[baseLength];
                int tempLength = 0;
                if (i + baseLength < length) {
                    tempLength = baseLength;
                    [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                } else {
                    tempLength = (int)length - i;
                    [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                    for (int j = (int)length - i; j < baseLength; j++ ) {
                        temp[j] = 0;
                    }
                }
                
                if (!isFirst) {
                    for (int j = 0; j < baseLength; j++) {
                        temp[j] = last[j] ^ temp[j];
                    }
                } else {
                    isFirst = NO;
                }
                
                cipher(temp, outTemp, w);
                
                for (int j = 0; j < baseLength; j++) {
                    last[j] = outTemp[j];
                }
                
                [retData appendBytes:&outTemp length:baseLength];
            }
        }
            break;
        case LEncryptCTR:
        {
            int baseLength = 16;
            int counter = 100;
            for (int i = 0; i < length; i+=baseLength) {
                Byte temp[baseLength];
                Byte outTemp[baseLength];
                int tempLength = 0;
                if (i + baseLength < length) {
                    tempLength = baseLength;
                    [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                } else {
                    tempLength = (int)length - i;
                    [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                    for (int j = (int)length - i; j < baseLength; j++ ) {
                        temp[j] = 0;
                    }
                }
                
                NSData *counterData = [[NSString stringWithFormat:@"%d",counter] dataUsingEncoding:NSUTF8StringEncoding];
                Byte counterByte[baseLength];
                [counterData getBytes:&counterByte range:NSMakeRange(0, [counterData length])];
                for (int j = (int)[counterData length]; j < baseLength; j++ ) {
                    counterByte[j] = baseLength - (int)[counterData length];
                }
                cipher(counterByte, outTemp, w);
                for (int j = 0; j < baseLength; j ++) {
                    temp[j] = temp[j] ^ outTemp[j];
                }
                
                counter ++;
                [retData appendBytes:&temp length:baseLength];
            }
        }
            break;
    }
    
    return retData;
}

- (NSData *)aesDecodeWithData:(NSData *)aData
                          key:(NSString *)aKey
                         type:(LEncryptType)aType
{
    NSMutableData *retData = nil;
    if (![self _validWithData:aData]) {
        return retData;
    }
    
    uint8_t *w = [self _getWWithKey:aKey];
    NSInteger length = [aData length];
    retData = [NSMutableData data];
    
    switch (aType) {
        case LEncryptECB:
        {
            int baseLength = 16;
            for (int i = 0; i < length; i+=baseLength) {
                Byte temp[baseLength];
                Byte outTemp[baseLength];
                int tempLength = 0;
                if (i + baseLength < length) {
                    tempLength = baseLength;
                } else {
                    tempLength = (int)length - i;
                }
                [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                inv_cipher(temp, outTemp, w);
                [retData appendBytes:&outTemp length:baseLength];
            }
        }
            break;
        case LEncryptCBC:
        {
            int baseLength = 16;
            Byte last[baseLength];
            BOOL isFirst = YES;
            for (int i = 0; i < length; i+=baseLength) {
                Byte temp[baseLength];
                Byte outTemp[baseLength];
                int tempLength = 0;
                if (i + baseLength < length) {
                    tempLength = baseLength;
                } else {
                    tempLength = (int)length - i;
                }
                [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                
                inv_cipher(temp, outTemp, w);
                
                if (!isFirst) {
                    for (int j = 0; j < baseLength; j++) {
                        outTemp[j] = outTemp[j] ^ last[j];
                    }
                } else {
                    isFirst = NO;
                }
                
                for (int j = 0; j < baseLength; j++) {
                    last[j] = temp[j];
                }
                
                [retData appendBytes:&outTemp length:baseLength];
            }
        }
            break;
        case LEncryptCTR:
        {
            int baseLength = 16;
            int counter = 100;
            for (int i = 0; i < length; i+=baseLength) {
                Byte temp[baseLength];
                Byte outTemp[baseLength];
                int tempLength = 0;
                if (i + baseLength < length) {
                    tempLength = baseLength;
                    [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                } else {
                    tempLength = (int)length - i;
                    [aData getBytes:&temp range:NSMakeRange(i, tempLength)];
                    for (int j = (int)length - i; j < baseLength; j++ ) {
                        temp[j] = 0;
                    }
                }
                
                NSData *counterData = [[NSString stringWithFormat:@"%d",counter] dataUsingEncoding:NSUTF8StringEncoding];
                Byte counterByte[baseLength];
                [counterData getBytes:&counterByte range:NSMakeRange(0, [counterData length])];
                for (int j = (int)[counterData length]; j < baseLength; j++ ) {
                    counterByte[j] = baseLength - (int)[counterData length];
                }
                cipher(counterByte, outTemp, w);
                for (int j = 0; j < baseLength; j ++) {
                    temp[j] = temp[j] ^ outTemp[j];
                }
                
                counter ++;
                [retData appendBytes:&temp length:baseLength];
            }
        }
            break;
    }
    
    return retData;
}

#pragma mark - pirvate

- (uint8_t *)_getWWithKey:(NSString *)aKey
{
    uint8_t *w = nullptr;
    if (aKey.length == 0) {
        //默认使用256 bit key
        w = getW(theKey);
    } else {
        //密码填充，如果超过256 bit位，截取前256 bit，不足256 bit位大于192 bit位，进行补位操作，以此类推
        NSData *keyData = [aKey dataUsingEncoding:NSUTF8StringEncoding];
        if ([keyData length] >= 32) {
            uint8_t key[32];
            [keyData getBytes:key range:NSMakeRange(0, 32)];
            w = getW(key);
        } else {
            int size = 16;
            if ([keyData length] > 32 && [keyData length] >= 24) {
                size = 32;
            } else if ([keyData length] > 24 && [keyData length] >= 16) {
                size = 24;
            }
            uint8_t key[size];
            [keyData getBytes:key range:NSMakeRange(0, [keyData length])];
            for (int i = (int)[keyData length]; i < size; i ++) {
                key[i] = size - (int)[keyData length];
            }
            w = getW(key);
        }
    }
    return w;
}

- (BOOL)_validWithData:(NSData*)aData
{
    if (aData == nil) {
        return NO;
    }
    
    if (aData == NULL) {
        return NO;
    }
    
    if ([aData length] == 0) {
        return NO;
    }
    
    return YES;
}

- (Byte)_getSequenceWithIndex:(NSInteger)aIndex
{
    int baseLength = 16;
    NSData *counterData = [[NSString stringWithFormat:@"%ld",(long)aIndex] dataUsingEncoding:NSUTF8StringEncoding];
    Byte counterByte[baseLength];
    [counterData getBytes:&counterByte range:NSMakeRange(0, [counterData length])];
    for (int j = (int)[counterData length]; j < baseLength; j++ ) {
        counterByte[j] = baseLength - (int)[counterData length];
    }
    
    return counterByte[baseLength];
}

- (NSData *)EMAES256EncryptWithKey:(NSData *)key data:(NSData*)aData{
    const void * keyPtr2;
    if ([key length] < 32) {
        NSMutableData *temp = [NSMutableData dataWithData:key];
        int length = (int)[temp length];
        for (int i = 0; i < 32- length; i++) {
            Byte byte = 32- length;
            [temp appendBytes:&byte length:1];
        }
                keyPtr2 = [temp bytes];
    } else {
        keyPtr2 = [[key subdataWithRange:NSMakeRange(0, 32)] bytes];
    }
    
    NSUInteger dataLength = [aData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr2, kCCKeySizeAES256,
                                          NULL,/* 初始化向量(可选) */
                                          [aData bytes], dataLength,/*输入*/
                                          buffer, bufferSize,/* 输出 */
                                          &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);//释放buffer
    return nil;
}

- (NSData *)EMAES256DecryptWithKey:(NSData *)key data:(NSData*)aData{
    const void * keyPtr2;
    if ([key length] < 32) {
        NSMutableData *temp = [NSMutableData dataWithData:key];
        int length = (int)[temp length];
        for (int i = 0; i < 32- length; i++) {
            Byte byte = 32- length;
            [temp appendBytes:&byte length:1];
        }
        keyPtr2 = [temp bytes];
    } else {
        keyPtr2 = [[key subdataWithRange:NSMakeRange(0, 32)] bytes];
    }
    char (*keyPtr)[32] = (char (*)[32])keyPtr2;
    
    NSUInteger dataLength = [aData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL,/* 初始化向量(可选) */
                                          [aData bytes], dataLength,/* 输入 */
                                          buffer, bufferSize,/* 输出 */
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);
    return nil;
}

@end
