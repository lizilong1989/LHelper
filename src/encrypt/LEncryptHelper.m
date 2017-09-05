//
//  LEncryptHelper.h
//
//  Created by zilong.li on 2017/6/23.
//

#import "LEncryptHelper.h"

#import <CommonCrypto/CommonCrypto.h>

@interface LEncryptHelper ()

@end

@implementation LEncryptHelper

+ (NSData *)generalKey:(int)length
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    if (result == 0) {
        return data;
    }
    return nil;
}

+ (NSData *)encryptWithData:(NSData *)aData
                        key:(const void *)aKey
                         iv:(NSData *)aIv
                       type:(EMCryptType)aType
{
    if (aIv.length == 0) {
        return nil;
    }
    
    NSData *keyData = [NSData dataWithBytes:aKey length:[self _getCCKeySize:aType]];
    
    return [LEncryptHelper _cryptWithOperation:kCCEncrypt data:aData key:keyData iv:aIv type:aType];
}

+ (NSData *)decryptWithData:(NSData *)aData
                        key:(const void *)aKey
                         iv:(NSData *)aIv
                       type:(EMCryptType)aType
{
    if (aIv.length == 0) {
        return nil;
    }
    
    NSData *keyData = [NSData dataWithBytes:aKey length:[self _getCCKeySize:aType]];
    
    return [LEncryptHelper _cryptWithOperation:kCCDecrypt data:aData key:keyData iv:aIv type:aType];
}

+ (NSData *)encryptData:(NSData *)aData
              publicKey:(NSData *)aPubKey
{
    if(!aData || !aPubKey){
        return nil;
    }
    SecKeyRef keyRef = [LEncryptHelper _addPublicKey:aPubKey];
    if(!keyRef){
        return nil;
    }
    return [LEncryptHelper _encryptData:aData withKeyRef:keyRef isSign:NO];
}

#pragma mark - private

+ (SecKeyRef)_addPublicKey:(NSData *)aKey
{
    NSString *pubkey = [[NSString alloc] initWithData:aKey encoding:NSUTF8StringEncoding];
    
    NSRange spos = [pubkey rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [pubkey rangeOfString:@"-----END PUBLIC KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        pubkey = [pubkey substringWithRange:range];
    }
    pubkey = [pubkey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pubkey = [pubkey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pubkey = [pubkey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    pubkey = [pubkey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    if (!pubkey) {
        return nil;
    }
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:pubkey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [LEncryptHelper _stripPublicKeyHeader:data];
    if(!data){
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PubKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

+ (NSData *)_stripPublicKeyHeader:(NSData *)d_key{
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx	 = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (NSData *)_encryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef isSign:(BOOL)isSign {
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        
        if (isSign) {
            status = SecKeyRawSign(keyRef,
                                   kSecPaddingPKCS1,
                                   srcbuf + idx,
                                   data_len,
                                   outbuf,
                                   &outlen
                                   );
        } else {
            status = SecKeyEncrypt(keyRef,
                                   kSecPaddingPKCS1,
                                   srcbuf + idx,
                                   data_len,
                                   outbuf,
                                   &outlen
                                   );
        }
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

+ (NSData *)_cryptWithOperation:(CCOperation)aOperation
                           data:(NSData *)aData
                            key:(NSData *)aKey
                             iv:(NSData *)aIv
                           type:(EMCryptType)aType
{
    if ([LEncryptHelper _getCCKeySize:aType] != aKey.length) {
        return nil;
    }
    
    NSUInteger dataLength = [aData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t outLength = 0;
    CCCryptorStatus cryptStatus = CCCrypt(aOperation, [LEncryptHelper _getAlgorithm:aType],
                                          [LEncryptHelper _getCCOptions:aType],
                                          aKey.bytes, aKey.length,
                                          aIv.bytes,
                                          [aData bytes], dataLength,
                                          buffer, bufferSize,
                                          &outLength);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:outLength];
    }
    free(buffer);
    return nil;
}

+ (CCAlgorithm)_getAlgorithm:(EMCryptType)aType {
    switch (aType) {
        case EMCrypt_aes256cbc:
            return kCCAlgorithmAES128;
        case EMCrypt_aes128cbc:
            return kCCAlgorithmAES128;
        default:
            return kCCAlgorithmAES;
    }
}

+ (CCOptions)_getCCOptions:(EMCryptType)aType {
    switch (aType) {
        case EMCrypt_aes256cbc:
            return kCCOptionPKCS7Padding;
        case EMCrypt_aes128cbc:
            return kCCOptionPKCS7Padding;
        default:
            return kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
}

+ (size_t)_getCCKeySize:(EMCryptType)aType {
    switch (aType) {
        case EMCrypt_aes256cbc:
            return kCCKeySizeAES256;
        case EMCrypt_aes128cbc:
            return kCCKeySizeAES128;
        default:
            return kCCKeySizeAES128;
    }
}

@end
