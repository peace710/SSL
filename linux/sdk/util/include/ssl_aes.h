#ifndef __SSL_AES_H__
#define __SSL_AES_H__

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/nid.h>

#define EVP_aes_128_cbc 0
#define EVP_aes_128_ctr 1
#define EVP_aes_128_ecb 2
#define EVP_aes_128_ofb 3
#define EVP_aes_192_cbc 4
#define EVP_aes_192_ctr 5
#define EVP_aes_192_ecb 6
#define EVP_aes_192_ofb 7
#define EVP_aes_256_cbc 8
#define EVP_aes_256_ctr 9
#define EVP_aes_256_ecb 10
#define EVP_aes_256_ofb 11


int aes_encrypt(const unsigned char *key,int data_len,const unsigned char *in,unsigned char **out,int *out_len,const unsigned char *iv,int mode); 

int aes_decrypt(const unsigned char *key,int data_len,const unsigned char *in,unsigned char **out,int *out_len,const unsigned char *iv,int mode); 

#endif
