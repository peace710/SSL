#ifndef __SSL_RSA_H__
#define __SSL_RSA_H__

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/base64.h>

#define RSA_BITS_1024 1024
#define RSA_BITS_2048 2048

#define PUB_EXPONENT "65537"

#define PKCS1_PADDING 0 
#define NO_PADDING 1

#define ERROR -1

#define HASH_ID_MD5 1
#define HASH_ID_SHA1 2
#define HASH_ID_SHA224 3
#define HASH_ID_SHA256 4
#define HASH_ID_SHA384 5
#define HASH_ID_SHA512 6
#define HASH_ID_MD5_SHA1 7



RSA *rsa_bits(int bits);

RSA *rsa_with_modulus(const char *modulus);

RSA *rsa_with_all(const char *modulus,const char *exponent);

int rsa_pub_encrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding);

int rsa_pri_encrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding);

int rsa_pub_decrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding);

int rsa_pri_decrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding);

int rsa_sign_msg(int type,const unsigned char *in,unsigned int len,unsigned char **sign,unsigned int *sign_len,RSA *rsa);

int rsa_verify_msg(int type,const unsigned char *in,unsigned int len,const unsigned char *verify,unsigned int verify_len,RSA *rsa);

void rsa_get_pub_key(RSA *rsa,char **key);

void rsa_parse_pub_key(RSA **rsa,const uint8_t *pkey);

void free_rsa(RSA *rsa);

#endif
