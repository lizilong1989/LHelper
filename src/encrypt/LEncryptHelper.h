//
//  LEncryptHelper.h
//
//  Created by zilong.li on 2017/6/23.
//

#import <Foundation/Foundation.h>

typedef enum {
    EMCrypt_aes128cbc = 0,
    EMCrypt_aes256cbc,
} EMCryptType;

/*!
 *  加密工具
 *
 */
@interface LEncryptHelper : NSObject

+ (NSData *)generalKey:(int)length;

+ (NSData *)encryptWithData:(NSData *)aData
                        key:(const void *)aKey
                         iv:(NSData *)aIv
                       type:(EMCryptType)aType;

+ (NSData *)decryptWithData:(NSData *)aData
                        key:(const void *)aKey
                         iv:(NSData *)aIv
                       type:(EMCryptType)aType;

+ (NSData *)encryptData:(NSData *)aData
              publicKey:(NSData *)aPubKey;

@end
