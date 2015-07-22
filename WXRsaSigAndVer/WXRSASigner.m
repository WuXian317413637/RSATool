//
//  WXRSASigner.m
//  RSATool
//
//  Created by WuXian on 15/7/7.
//  Copyright (c) 2015年 WuXian. All rights reserved.
//

#import "WXRSASigner.h"
#import <OpenSSL/rsa.h>
#import <OpenSSL/bio.h>
#import <OpenSSL/pem.h>

#define SIXTEENARRLENGTH 256

@implementation WXRSASigner

+ (WXRSASigner *)sharedInsect{
    
    static WXRSASigner * signer;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        
        signer = [[WXRSASigner alloc]init];
    });
    return signer;
}

- (NSString *)signer:(NSString *)planTxt andPath:(NSString *)path{
    
    int dst_len;
    unsigned char * signedData = WXRSA_sign([path UTF8String], (const unsigned char*)[planTxt UTF8String], (int)planTxt.length, &dst_len);
    
    char sixTeenArr[SIXTEENARRLENGTH + 1];
    //charToHexChar(signedData, sixTeenArr, SIXTEENARRLENGTH, 16);
    for (int i = 0; i < SIXTEENARRLENGTH / 2; i++) {
        
        sprintf(sixTeenArr+(i * 2), "%02x",signedData[i]);
    }
    //    sixTeenArr[SIXTEENARRLENGTH] = 0;
    
    printf("sixTeenArr is %s\n",sixTeenArr);
    //0x30303030303000
    NSString * Result = [[NSString alloc] initWithCString:sixTeenArr encoding:NSASCIIStringEncoding];
    NSLog(@"result dizhi is %p",&Result);
    return Result;
    
}

void charToHexChar(unsigned char* in,char* out,int size,int base)
{
    unsigned char* pt1 = in;
    char* pt2 = out;
    do
    {
        pt2 += sprintf(pt2,"%02x",(unsigned char)*pt1++);
        size--;
        
        //注意：这里的判断条件加上*pt1 && size则不会崩溃，但是这么转换后判断条件*pt1可能为空，则不会转换为256长度的16进制字符串，后台验签不能成功；去掉*pt1 &&则调用该函数的地方返回Result时会崩溃，崩溃信息为错误：读取内存//0x30303030303000失败
    }while(*pt1 && size);
    out[SIXTEENARRLENGTH] = 0;
    
}


unsigned char *WXRSA_sign(const char * privateKeyPath,const unsigned char *src,int src_len,int *dst_len){
    
    
    BIO *bio_private = NULL;
    RSA *rsa_private = NULL;
    //创建BIO结构体对象,这个结构体主要是处理各种形式的密钥读取
    bio_private = BIO_new(BIO_s_file());
    
    
    BIO_read_filename(bio_private, privateKeyPath);
    
    rsa_private = PEM_read_bio_RSAPrivateKey(bio_private, NULL, NULL, "");
    
    EVP_PKEY *key = EVP_PKEY_new();
    int err = EVP_PKEY_assign_RSA(key,rsa_private);
    int size=0;
    if (err) {
        size = EVP_PKEY_size(key);
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);
    EVP_SignInit_ex(ctx,EVP_sha256() , NULL);
    EVP_SignUpdate(ctx, src,src_len);
    unsigned char *md=(unsigned char *)malloc(size);
    unsigned int len = 0;
    EVP_SignFinal(ctx, md, &len, key);
    *dst_len = len;
    EVP_PKEY_free(key);
    EVP_MD_CTX_cleanup(ctx);
    return md;
}


@end
