//
//  YCSafeManager.h
//  YCSecurity
//
//  Created by YC on 2020/8/4.
//  Copyright © 2020 yc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface YCSafeManager : NSObject

/// 加密
/// @param text 明文
+ (NSString *)encryptWithText:(NSString *)text;

/// 解密
/// @param text 密文
+ (NSString *)decryptWithText:(NSString *)text;

/// 是否验签成功
/// @param sign 签名串，后端返回
/// @param content 明文
+ (BOOL)isMatchWithSign:(NSString *)sign content:(NSString *)content;

@end

NS_ASSUME_NONNULL_END
