//
//  LEncryptHelper.h
//
//  Created by zilong.li on 2017/6/23.
//

#import <Foundation/Foundation.h>

@interface LEncryptHelper : NSObject

/*!
 *  获取LEncryptHelper实例
 */
+ (instancetype)shareHelper;

/*!
 *  \~chinese
 *  Des加密
 *
 *  @param aData    需要加密的数据
 *  @param aKey     秘钥
 *
 *  @result 加密数据
 */
- (NSData *)desEncryptWithData:(NSData*)aData
                           key:(NSString*)aKey;

/*!
 *  \~chinese
 *  Des解密
 *
 *  @param aData    需要解密的数据
 *  @param aKey     秘钥
 *
 *  @result 解密数据
 */
- (NSData *)desDecodeWithData:(NSData*)aData key:(NSString*)aKey;

@end
