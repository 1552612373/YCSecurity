//
//  YCSafeTools.m
//  YCSecurity
//
//  Created by YC on 2020/8/4.
//  Copyright © 2020 yc. All rights reserved.
//

#import "YCSafeTools.h"
#import "RSA.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>

@implementation YCSafeTools

#pragma mark - RSA
/**************************** RSA ****************************/

/**
 *  RSA加密
 *  @param text    需要加密的字符串
 *  @param publicKey 公钥字符串
 */
+ (NSString *)rsaEncryptWithText:(NSString *)text publicKey:(NSString *)publicKey {
    return [RSA encryptString:text publicKey:publicKey];
}

/**
 *  RSA解密
 *  @param text     需要解密的字符串
 *  @param privateKey 私钥字符串
 */
+ (NSString *)rsaDecryptWithText:(NSString *)text privateKey:(NSString *)privateKey {
    return [RSA decryptString:text privateKey:privateKey];
}

#pragma mark - AES
/**************************** AES ****************************/

/// AES加密
/// @param original 需要加密的字符串
/// @param key aes的key
/// @param iv 初始化向量
+ (NSData *)aesEncryptWithText:(NSString *)original key:(NSString *)key iv:(NSString *)iv {
    NSData *encryptData = [YCSafeTools encryptString:original withKey:key andIv:iv];
    return encryptData;
}

/// AES解密
/// @param data 需要解密的密文
/// @param key aes的key
/// @param iv 初始化向量
+ (NSString *)aesDecryptWithData:(NSData *)data key:(NSString*)key iv:(NSString *)iv {
//    NSData *data = [NSData dataWithBase64EncodedString:string];
//    NSData *data = [base64String dataUsingEncoding:NSUTF8StringEncoding];
    NSString *originString = [YCSafeTools decryptData:data withKey:key andIv:iv];
    return originString;
}

// 加密，直接返回加密数据
+ (nullable NSData *)encryptString:(NSString*)stringToEncrypt withKey:(NSString*)keyString andIv:(NSString *)ivString {
    // 参数检查，固定写死AES128，所以要求key是16位
    if (keyString.length != 16) {
        return nil;
    }
    if (ivString.length != 16 && ivString.length != 0) {
        return nil;
    }
    
    // Key to Data
    NSData *key = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    
    // String to encrypt to Data
    NSData *data = [stringToEncrypt dataUsingEncoding:NSUTF8StringEncoding];
    
    // Init cryptor
    CCCryptorRef cryptor = NULL;
    
    // Alloc Data Out
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
    
    // Empty IV: initialization vector
    NSData *iv =  [ivString dataUsingEncoding:NSUTF8StringEncoding];
    
    // Create Cryptor
    CCCryptorStatus  create = CCCryptorCreateWithMode(kCCEncrypt,
                                                      kCCModeCTR,
                                                      kCCAlgorithmAES,
                                                      ccNoPadding,
                                                      iv.bytes, // can be NULL, because null is full of zeros
                                                      key.bytes,
                                                      key.length,
                                                      NULL,
                                                      0,
                                                      0,
                                                      kCCModeOptionCTR_BE,
                                                      &cryptor);
    
    if (create == kCCSuccess) {
        //alloc number of bytes written to data Out
        size_t outLength;
        
        //Update Cryptor
        CCCryptorStatus  update = CCCryptorUpdate(cryptor,
                                                  data.bytes,
                                                  data.length,
                                                  cipherData.mutableBytes,
                                                  cipherData.length,
                                                  &outLength);
        if (update == kCCSuccess) {
            //Cut Data Out with nedded length
            cipherData.length = outLength;
            
            //Final Cryptor
            CCCryptorStatus final = CCCryptorFinal(cryptor, //CCCryptorRef cryptorRef,
                                                   cipherData.mutableBytes, //void *dataOut,
                                                   cipherData.length, // size_t dataOutAvailable,
                                                   &outLength); // size_t *dataOutMoved)
            if (final == kCCSuccess) {
                //Release Cryptor
                //CCCryptorStatus release =
                CCCryptorRelease(cryptor ); //CCCryptorRef cryptorRef
            }
            return [cipherData copy];
        }
    } else {
        //error
    }
    
    return nil;
}

// 解密，直接解密加密数据
+ (nullable NSString *)decryptData:(NSData*)data withKey:(NSString*)keyString andIv:(NSString *)ivString {
    // 参数检查，固定写死AES128，所以要求key是16位
    if (keyString.length != 16) {
        return nil;
    }
    if (ivString.length != 16 && ivString.length != 0) {
        return nil;
    }
    
    // Key to Data
    NSData *key = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    
    // Init cryptor
    CCCryptorRef cryptor = NULL;
    
    // Empty IV: initialization vector
    // NSMutableData *iv =  [NSMutableData dataWithLength:kCCBlockSizeAES128];
    NSData *iv =  [ivString dataUsingEncoding:NSUTF8StringEncoding];
    
    // Create Cryptor
    CCCryptorStatus createDecrypt = CCCryptorCreateWithMode(kCCDecrypt, // operation
                                                            kCCModeCTR, // mode CTR
                                                            kCCAlgorithmAES, // Algorithm
                                                            ccNoPadding, // padding
                                                            iv.bytes, // can be NULL, because null is full of zeros
                                                            key.bytes, // key
                                                            key.length, // keylength
                                                            NULL, //const void *tweak
                                                            0, //size_t tweakLength,
                                                            0, //int numRounds,
                                                            kCCModeOptionCTR_BE, //CCModeOptions options,
                                                            &cryptor); //CCCryptorRef *cryptorRef
    
    
    if (createDecrypt == kCCSuccess) {
        // Alloc Data Out
        NSMutableData *cipherDataDecrypt = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
        
        //alloc number of bytes written to data Out
        size_t outLengthDecrypt;
        
        //Update Cryptor
        CCCryptorStatus updateDecrypt = CCCryptorUpdate(cryptor,
                                                        data.bytes, //const void *dataIn,
                                                        data.length,  //size_t dataInLength,
                                                        cipherDataDecrypt.mutableBytes, //void *dataOut,
                                                        cipherDataDecrypt.length, // size_t dataOutAvailable,
                                                        &outLengthDecrypt); // size_t *dataOutMoved)
        if (updateDecrypt == kCCSuccess) {
            //Cut Data Out with nedded length
            cipherDataDecrypt.length = outLengthDecrypt;
            // Data to String
            NSString* cipherFinalDecrypt = [[NSString alloc] initWithData:cipherDataDecrypt encoding:NSUTF8StringEncoding];
            //Final Cryptor
            CCCryptorStatus final = CCCryptorFinal(cryptor, //CCCryptorRef cryptorRef,
                                                   cipherDataDecrypt.mutableBytes, //void *dataOut,
                                                   cipherDataDecrypt.length, // size_t dataOutAvailable,
                                                   &outLengthDecrypt); // size_t *dataOutMoved)
            if (final == kCCSuccess) {
                //Release Cryptor
                //CCCryptorStatus release =
                CCCryptorRelease(cryptor); //CCCryptorRef cryptorRef
            }
            return cipherFinalDecrypt;
        }
    } else {
        //error
    }
    return nil;
}


@end
