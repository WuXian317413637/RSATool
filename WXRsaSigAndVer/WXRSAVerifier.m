//
//  WXRSAVerifier.m
//  RSATool
//
//  Created by WuXian on 15/7/7.
//  Copyright (c) 2015年 WuXian. All rights reserved.
//

#import "WXRSAVerifier.h"
#import <OpenSSL/rsa.h>
#import <OpenSSL/evp.h>
#import <OpenSSL/x509.h>

#define HEXSTRTOCHAR 256

@implementation WXRSAVerifier


+ (WXRSAVerifier *)sharedInsect{
    
    static WXRSAVerifier * _verifier;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
       
        _verifier = [[WXRSAVerifier alloc]init];
        
    });
    return _verifier;
}


- (BOOL)RSA_verify:(NSString *)verifyData sig:(NSString *)sig path:(NSString *)path{
    
    const unsigned char *src = (const unsigned char *)[verifyData UTF8String];
    
    const char * siged = [sig UTF8String];
    
    char hexToChar[HEXSTRTOCHAR];
    
    hexStrToCharStr(siged, (unsigned char *)hexToChar, HEXSTRTOCHAR, 16);
    
    printf("hexToChar is %s",hexToChar);
    
    bool ret = WXrsaVerify((const unsigned char *)[verifyData UTF8String], (int)verifyData.length, (unsigned char *)hexToChar, HEXSTRTOCHAR/2, [path UTF8String]);
    
    if (ret == true) {
        return YES;
    }else{
        return NO;
    }
    
    
}

void hexStrToCharStr(const char* in,unsigned char* out,int size,int base)
{
    unsigned char* pt1 = (unsigned char*)in;
    unsigned char* pt2 = out;
    while (isxdigit(*pt1) && size--)
    {
        *pt2++ = base * ( isdigit(*pt1) ? *pt1++-'0' : tolower(*pt1++)-'a'+10) + ( isdigit(*pt1) ? *pt1++-'0' : tolower(*pt1++)-'a'+10);
        
    }
}


bool WXrsaVerify(const unsigned char *src,int src_len,unsigned char *sig,unsigned int sigl_len,const char *publicKeyPath){
    
    FILE * fp = fopen(publicKeyPath, "rb");
    
    if (!fp) {
        NSLog(@"读取公钥失败");
    }
    
    X509 * cert = NULL;
    EVP_PKEY * key = NULL;
    
    d2i_X509_fp(fp, &cert);
    
    key = X509_get_pubkey(cert);
    
    EVP_MD_CTX * ctx = NULL;
    int size=0;
    if (key) {
        size = EVP_PKEY_size(key);
    }
    ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);
    EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL);
    EVP_VerifyUpdate(ctx, src,src_len);
    int suc = EVP_VerifyFinal(ctx, sig, sigl_len, key);
    EVP_PKEY_free(key);
    EVP_MD_CTX_cleanup(ctx);
    if (suc == 1) {
        return true;
    }
    else
        return false;
    
}


@end
