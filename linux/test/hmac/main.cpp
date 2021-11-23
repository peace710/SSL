#include <stdio.h>
#include <io_util.h>
#include <cstring>
#include <openssl/hmac.h>

void hmac(const EVP_MD *function,uint8_t *out,unsigned int *out_len){
       	char data[] = "hello world";
	char key[] = "1234567890";
	
	HMAC_CTX hmac_ctx;
	HMAC_CTX_init(&hmac_ctx);
	
	if (HMAC_Init_ex(&hmac_ctx,key,strlen(key),function,NULL)){
		HMAC_Update(&hmac_ctx,(const uint8_t*)data,strlen(data));		
		HMAC_Final(&hmac_ctx,out,out_len);
		HMAC_CTX_cleanup(&hmac_ctx);
	}
}

int main(int argc,char* argv[]){

	uint8_t	*out = NULL;
	unsigned int out_len;

       	out = (uint8_t*)malloc(EVP_MAX_MD_SIZE);
	const EVP_MD *const sha1 = EVP_sha1();
	hmac(sha1,out,&out_len);
	printf("HMAC_SHA1:\n");
	printHex((const unsigned char*)out,out_len);

       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const sha224 = EVP_sha224();
	hmac(sha224,out,&out_len);
	printf("HMAC_SHA224:\n");
	printHex((const unsigned char*)out,out_len);
	
       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const sha256 = EVP_sha256();
	hmac(sha256,out,&out_len);
	printf("HMAC_SHA256:\n");
	printHex((const unsigned char*)out,out_len);
	
       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const sha384 = EVP_sha384();
	hmac(sha384,out,&out_len);
	printf("HMAC_SHA384:\n");
	printHex((const unsigned char*)out,out_len);

       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const sha512 = EVP_sha512();
	hmac(sha512,out,&out_len);
	printf("HMAC_SHA512:\n");
	printHex((const unsigned char*)out,out_len);

       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const sha512_256 = EVP_sha512_256();
	hmac(sha512_256,out,&out_len);
	printf("HMAC_SHA512_256:\n");
	printHex((const unsigned char*)out,out_len);

       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const blake2b256 = EVP_blake2b256();
	hmac(blake2b256,out,&out_len);
	printf("HMAC_BLAKE_2B_256:\n");
	printHex((const unsigned char*)out,out_len);

       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const md4 = EVP_md4();
	hmac(md4,out,&out_len);
	printf("HMAC_MD4:\n");
	printHex((const unsigned char*)out,out_len);

       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const md5 = EVP_md5();
	hmac(md5,out,&out_len);
	printf("HMAC_MD5:\n");
	printHex((const unsigned char*)out,out_len);

       	out = (uint8_t*)realloc(out,EVP_MAX_MD_SIZE);
	const EVP_MD *const md5_sha1 = EVP_md5_sha1();
	hmac(md5_sha1,out,&out_len);
	printf("HMAC_MD5_SHA1:\n");
	printHex((const unsigned char*)out,out_len);

	if (out){
		free(out);
		out = NULL;
	}
	return 0;
}
