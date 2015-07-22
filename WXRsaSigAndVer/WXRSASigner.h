//
//  WXRSASigner.h
//  RSATool
//
//  Created by WuXian on 15/7/7.
//  Copyright (c) 2015年 WuXian. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface WXRSASigner : NSObject

+ (WXRSASigner *)sharedInsect;

- (NSString *)signer:(NSString *)planTxt andPath:(NSString *)path;

@end
