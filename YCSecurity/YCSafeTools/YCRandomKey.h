//
//  YCRandomKey.h
//  YCSecurity
//
//  Created by YC on 2020/7/31.
//  Copyright © 2020 yc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface YCRandomKey : NSObject

+ (NSString *)aesKey16;
+ (NSString *)aesNonce16;
+ (NSString *)hmacKey32;

@end

NS_ASSUME_NONNULL_END
