//
//  YCRandomKey.m
//  YCSecurity
//
//  Created by YC on 2020/7/31.
//  Copyright © 2020 yc. All rights reserved.
//

#import "YCRandomKey.h"

@implementation YCRandomKey

+ (NSString *)aesKey16 {
    return [YCRandomKey randomStringWithLength:16];
}

+ (NSString *)aesNonce16 {
    return [YCRandomKey randomStringWithLength:16];
}

+ (NSString *)hmacKey32 {
    return [YCRandomKey randomStringWithLength:32];
}

// 返回length位大小写字母和数字的随机字符串
+ (NSString *)randomStringWithLength:(NSInteger)length {
    NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *randomString = [NSMutableString stringWithCapacity: length];
    
    for (NSInteger i = 0; i < length; i++) {
        [randomString appendFormat: @"%c", [letters characterAtIndex: arc4random_uniform((uint32_t)[letters length])]];
    }
    return randomString;
}

@end
