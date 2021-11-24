#ifndef __SSL_DES_H__
#define __SSL_DES_H__

#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/nid.h>

#define EVP_des_cbc 0
#define EVP_des_ecb 1
#define EVP_des_ede_cbc 2
#define EVP_des_ede_ecb 3
#define EVP_des_ede3_cbc 4


int des_encrypt(const unsigned char *key,int data_len,const unsigned char *in,unsigned char **out,int *out_len,const unsigned char *iv,int mode); 

int des_decrypt(const unsigned char *key,int data_len,const unsigned char *in,unsigned char **out,int *out_len,const unsigned char *iv,int mode); 

#endif
