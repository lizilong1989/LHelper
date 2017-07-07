# LHelper
这是一个简单的加密示例，实现了DES，AES等加密方式，可以直接对Objective-C中NSData数据进行加密.

## 集成

1.使用 Cocoapods 来集成LHelper, 集成方法如下:

```
pod 'LHelper'
```

2.使用时, 需要引入头文件, 在 pch 预编译文件中, 引入头文件如下:

```
 #import <LHelper/LEncryptHelper.h>
```

## 使用方法

DES加密数据调用示例

```
//测试数据
NSData *data = [@"Hello world" dataUsingEncoding:NSUTF8StringEncoding];

//设置DES密钥
[[LEncryptHelper shareHelper] setDesKey:@"12345678"];

//DES加密
NSData *encryptData = [[LEncryptHelper shareHelper] desEncryptWithData:data key:nil];

//DES解密
NSData *decodeData = [[LEncryptHelper shareHelper] desDecodeWithData:encryptData key:nil];

```

AES加密数据调用示例

```
//测试数据
NSData *data = [@"Hello world" dataUsingEncoding:NSUTF8StringEncoding];

//AES加密
NSData *encryptData = [[LEncryptHelper shareHelper] aesEncryptWithData:data key:@"1234567890123456"];

//AES解密
NSData *decodeData = [[LEncryptHelper shareHelper] aesDecodeWithData:encryptData key:@"1234567890123456"];

```