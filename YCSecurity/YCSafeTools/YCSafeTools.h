//
//  YCSafeTools.h
//  YCSecurity
//
//  Created by YC on 2020/8/4.
//  Copyright © 2020 yc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface YCSafeTools : NSObject

/**************************** RSA ****************************/

/**
 *  RSA加密
 *  @param text    需要加密的字符串
 *  @param publicKey 公钥字符串
 */
+ (NSString *)rsaEncryptWithText:(NSString *)text publicKey:(NSString *)publicKey;

/**
 *  RSA解密
 *  @param text     需要解密的字符串
 *  @param privateKey 私钥字符串
 */
+ (NSString *)rsaDecryptWithText:(NSString *)text privateKey:(NSString *)privateKey;

/**************************** AES ****************************/

/// AES加密
/// @param original 需要加密的字符串
/// @param key aes的key
/// @param iv 初始化向量
+ (NSData *)aesEncryptWithText:(NSString *)original key:(NSString *)key iv:(NSString *)iv;


/// AES解密
/// @param data 需要解密的密文
/// @param key aes的key
/// @param iv 初始化向量
+ (NSString *)aesDecryptWithData:(NSData *)data key:(NSString*)key iv:(NSString *)iv;

@end

NS_ASSUME_NONNULL_END
