//
//  WXRSAVerifier.h
//  RSATool
//
//  Created by WuXian on 15/7/7.
//  Copyright (c) 2015年 WuXian. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface WXRSAVerifier : NSObject

+ (WXRSAVerifier *)sharedInsect;

- (BOOL)RSA_verify:(NSString *)verifyData sig:(NSString *)sig path:(NSString *)path;


@end
