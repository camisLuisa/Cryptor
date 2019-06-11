//
//  NSData+CryptorAdditions.m
//  Cryptor
//
//  Created by Joao Paulo Ribeiro on 29/05/2019.
//  Copyright © 2019 Luisa, Camila. All rights reserved.
//

#import "NSData+CryptorAdditions.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation NSData (CryptorAdditions)

- (NSData * _Nullable)encryptedDataUsingKey:(NSString * _Nullable)key
{
    return [self performOperation:kCCEncrypt withkey:key];
}

- (NSData * _Nullable)decrypttedDataUsingKey:(NSString *_Nullable)key
{
    return [self performOperation:kCCDecrypt withkey:key];
}

#pragma mark - Private methods

- (NSData *)performOperation:(CCOperation)operation withkey:(NSString *)AESKey {
    
    NSData *outputData = nil;
    void* inputData = malloc(self.length);
    [self getBytes:inputData length:self.length];
    char aesKey[kCCKeySizeAES128+1];
    bzero(aesKey, sizeof(aesKey));
    NSString *key = AESKey;
    
    [key getCString:aesKey maxLength:key.length+1 encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = self.length;
    size_t bufferSize = dataLength + kCCKeySizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesOperated = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation, kCCAlgorithmAES, kCCOptionPKCS7Padding, aesKey, kCCBlockSizeAES128, NULL, inputData, dataLength, buffer, bufferSize, &numBytesOperated);
    
    if (kCCSuccess == cryptStatus) {
        outputData = [NSData dataWithBytes:buffer length:numBytesOperated];
    }
    
    free(buffer);
    free(inputData);
    
    return outputData;
}

@end
