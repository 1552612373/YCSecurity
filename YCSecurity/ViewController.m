//
//  ViewController.m
//  YCSecurity
//
//  Created by YC on 2020/8/4.
//  Copyright © 2020 yc. All rights reserved.
//

#import "ViewController.h"
#import "YCSafeManager.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    NSString *string1 = [YCSafeManager encryptWithText:@"hello world"];
    NSLog(@"加密后：%@",string1);
    NSString *string2 = [YCSafeManager decryptWithText:string1];
    NSLog(@"解密后：%@",string2);

}


@end
