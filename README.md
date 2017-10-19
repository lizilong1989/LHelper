# LongEncrypt
这是一个简单的加密示例，实现AES加密方式（CCCrypt的简单封装），可以直接对Objective-C中NSData数据进行加密.

## 集成

1.使用 Cocoapods 来集成LHelper, 集成方法如下:

```
pod 'LongEncrypt'
```

2.使用时, 需要引入头文件, 在 pch 预编译文件中, 引入头文件如下:

```
 #import <LongEncrypt/LEncryptHelper.h>
```

## 使用方法


AES加密数据调用示例

```
	//加密数据
    NSData *data = [@"hello world" dataUsingEncoding:NSUTF8StringEncoding];
    
    //随机生成key
    NSData *key = [LEncryptHelper generalKey:16];
    
    //iv偏移量
    unsigned char iv[16] = {'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};
    
    //DES加密
    NSData *encryptData = [LEncryptHelper encryptWithData:data
                                                      key:key.bytes
                                                       iv:[NSData dataWithBytes:iv length:16]
                                                     type:EMCrypt_aes128cbc];
    
    //DES解密
    NSData *decodeData = [LEncryptHelper decryptWithData:encryptData
                                                     key:key.bytes
                                                      iv:[NSData dataWithBytes:iv length:16]
                                                    type:EMCrypt_aes128cbc];

```
