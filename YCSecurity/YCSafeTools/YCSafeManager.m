//
//  YCSafeManager.m
//  YCSecurity
//
//  Created by YC on 2020/8/4.
//  Copyright © 2020 yc. All rights reserved.
//

#import "YCSafeManager.h"
#import "YCRandomKey.h"
#import "YCSafeTools.h"
#import "HBRSAHandler.h"
#import <YYCategories/YYCategories.h>

// 公钥
static NSString * const kPublicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxH2sy7gcdumfaIdQ89uxhFbCzfm1qtXuKC3LCjchpPeWt6oyutdwyx0BQTnGZIa3/GTHdZHWbWPY8iUc2fOUgvOPBu7ycPzW9dasWTpBClv/G6ovXFcne4M1dZCl/Za3O5Ed3BqgYYUcOLqPgb1eKjLQTvpXAzDTlMMjm4D9W2QIDAQAB";

// 私钥
static NSString * const kPrivateKey = @"MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALEfazLuBx26Z9oh1Dz27GEVsLN+bWq1e4oLcsKNyGk95a3qjK613DLHQFBOcZkhrf8ZMd1kdZtY9jyJRzZ85SC848G7vJw/Nb11qxZOkEKW/8bqi9cVyd7gzV1kKX9lrc7kR3cGqBhhRw4uo+BvV4qMtBO+lcDMNOUwyObgP1bZAgMBAAECgYEAkEcPg0Tw9v5Iah70S1S3571LWmq5php+r0v0BxaHEXMiDDDqt8XbwGEdukyrrBkLKqjTPYv/YLNuoJESOQgzesKySHVcLgDv3HwusUxEJ3XFe88x80lB3H8OBNmvpGO0jjL4neIlQoVZ96PwGdqiXCAXr8hzXeUbwfWy9e+Cn6ECQQDrna4ZbOfgwNLJxHun3b8crSU2uQWlZVgDuFXIAVkCakLZQV6uLNnhggZhfWxy8i29wAIsoflC2AVEYL5y/1aHAkEAwHJBojZeVVYfhF8AQxRSobyfYNDF4FAW/besJxaM4Q2s7EMM+g27b8n0l12hZS9aQ8CMBqObiAMbw3zbV6/fnwJAYnfCc9PE0HQlY7deqlgM77IY1Fbc2jORZfSavPx7M3wvNdaQ+B+8avdJLWMaeKtnnF5rSjXjEyFuihYYYbz+bwJBAK4WbaMk1Z8Swn4HRoBn4PwoWnDFS0tIiBPKVHQjpRttOJGdch69z2In6hgHfhm/hUMm6kSTOf4G+dWUnAMtuPcCQQCIXYCNCzknbdbDcZbQB8AbrLoaSI2Piyk6x3dmkwGugd7xvUeTDD70Q2S5SnnydKTC20999XuRXDHdKJnd1TKr";


@implementation YCSafeManager

/// 加密
/// @param text 明文
+ (NSString *)encryptWithText:(NSString *)text {

    
    NSMutableArray *tempArray = [NSMutableArray array];
    // 版本号
    [tempArray addObject:@"1.0.0"];
    // key
    NSString *aesKey = [YCRandomKey aesKey16];
    NSString *nonce = [YCRandomKey aesNonce16];
    NSString *hmacKey = [YCRandomKey hmacKey32];
    
    // B1 hmacKey rsa+base64
    NSString *b1Base64 = [YCSafeTools rsaEncryptWithText:hmacKey publicKey:kPublicKey];
    [tempArray addObject:b1Base64];
    // B2 aesKey rsa+base64
    NSString *b2Base64 = [YCSafeTools rsaEncryptWithText:aesKey publicKey:kPublicKey];
    [tempArray addObject:b2Base64];
    // B3 nonce base64
    NSString *b3Base64 = [nonce base64EncodedString];
    [tempArray addObject:b3Base64];
    // B4 aes data
    NSData *b4 = [YCSafeTools aesEncryptWithText:text key:aesKey iv:nonce];
    NSString *b4Base64 = [b4 base64EncodedString];
    [tempArray addObject:b4Base64];
    // B5
    NSData *hmacData = [b4 hmacSHA256DataWithKey:[hmacKey dataValue]];
    NSString *b5Base64 = [hmacData base64EncodedString];
    [tempArray addObject:b5Base64];
    
    return [tempArray componentsJoinedByString:@"$"];
}

/// 解密
/// @param text 密文
+ (NSString *)decryptWithText:(NSString *)text {
    NSArray *myArray = [text componentsSeparatedByString:@"$"];
    if (myArray && myArray.count == 6) {
                
        NSString *hmacKey = [YCSafeTools rsaDecryptWithText:myArray[1] privateKey:kPrivateKey];
        NSString *aesKey = [YCSafeTools rsaDecryptWithText:myArray[2] privateKey:kPrivateKey];
        NSString *nonce = [self base64DecodeStringWithString:myArray[3]];
        
        // b4解析出原文
        NSString *b4 = myArray[4];
        NSData *b4Data = [NSData dataWithBase64EncodedString:b4];
        NSString *base64B4 = [YCSafeTools aesDecryptWithData:b4Data key:aesKey iv:nonce];
        
        // b5验签
        NSData *hmacData = [b4Data hmacSHA256DataWithKey:[hmacKey dataValue]];
        NSString *hmacBase64 = [hmacData base64EncodedString];
        
        if ([hmacBase64 isEqualToString:myArray[5]]) {
            NSLog(@"验签成功");
            return base64B4;
        } else {
            NSLog(@"验签失败");
            return @"验签失败";
        }
    }
    
    return nil;
}

/// 是否验签成功
/// @param sign 签名串，后端返回
/// @param content 明文
+ (BOOL)isMatchWithSign:(NSString *)sign content:(NSString *)content {
    
    HBRSAHandler* handler = [HBRSAHandler new];
    [handler importKeyWithType:KeyTypePublic andkeyString:kPublicKey];
    BOOL isMatch = [handler verifyMD5String:content withSign:sign];
    
    return isMatch;
}

+ (NSString *)base64DecodeStringWithString:(NSString *)string {
    //注意：该字符串是base64编码后的字符串
    //1、转换为二进制数据（完成了解码的过程）
    NSData *data=[[NSData alloc]initWithBase64EncodedString:string options:0];
    //2、把二进制数据转换成字符串
    NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return value;
}

@end
