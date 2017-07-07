//
//  LEncryptHelper.h
//
//  Created by zilong.li on 2017/6/23.
//

#import <Foundation/Foundation.h>

typedef enum{
    LEncryptECB = 0,
    LEncryptCBC,
}LEncryptType;

/*!
 *  加密工具
 *
 */
@interface LEncryptHelper : NSObject

/*!
 *  获取LEncryptHelper实例
 */
+ (instancetype)shareHelper;

/*!
 *  设置des密钥，如果设置，DES加密解密方法无需传入密钥
 *
 *  @param aKey     密钥
 */
- (void)setDesKey:(NSString*)aKey;

/*!
 *  DES加密
 *
 *  @param aData    需要加密的数据
 *  @param aKey     密钥
 *
 *  @result 加密数据
 */
- (NSData *)desEncryptWithData:(NSData*)aData
                           key:(NSString*)aKey;

/*!
 *  DES解密
 *
 *  @param aData    需要解密的数据
 *  @param aKey     密钥
 *
 *  @result 解密数据
 */
- (NSData *)desDecodeWithData:(NSData*)aData
                          key:(NSString*)aKey;

/*!
 *  AES加密
 *
 *  @param aData    需要加密的数据
 *  @param aKey     密钥，如果穿nil，用内部默认256bit位密钥
 *  @param aType    加密模式
 *
 *  @result 加密数据
 */
- (NSData *)aesEncryptWithData:(NSData*)aData
                           key:(NSString*)aKey
                          type:(LEncryptType)aType;


/*!
 *  AES解密
 *
 *  @param aData    需要解密的数据
 *  @param aKey     密钥，如果穿nil，用内部默认256bit位密钥
 *  @param aType    加密模式
 *
 *  @result 加密数据
 */
- (NSData *)aesDecodeWithData:(NSData*)aData
                          key:(NSString*)aKey
                         type:(LEncryptType)aType;

@end
