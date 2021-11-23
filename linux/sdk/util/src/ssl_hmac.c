#include <string.h>
#include <stdlib.h>
#include <ssl_hmac.h>

const EVP_MD *function(int mode){
	switch (mode){
		case HMAC_MD4:
			return EVP_md4();
		case HMAC_MD5:
			return EVP_md5();
		case HMAC_SHA1:
			return EVP_sha1();
		case HMAC_SHA224:
			return EVP_sha224();
		case HMAC_SHA256:
			return EVP_sha256();
		case HMAC_SHA384:
			return EVP_sha384();
		case HMAC_SHA512:
			return EVP_sha512();
		case HMAC_SHA512_256:
			return EVP_sha512_256();
		case HMAC_BLAKE_2B_256:
			return EVP_blake2b256();
		case HMAC_MD5_SHA1:
			return EVP_md5_sha1();
		default:
			return NULL;	
	}
}

int hmac(const uint8_t *data,const void *key,uint8_t **out,unsigned int *out_len,int mode){
	const EVP_MD *md = function(mode);
	
	if (md == NULL){
		return 0;
	}
	
	(*out) = (uint8_t*)malloc(EVP_MAX_MD_SIZE + 1);
	if (*out){
		memset(*out,0x00,EVP_MAX_MD_SIZE + 1);
		int data_len = strlen((const char*)data);
		int key_len = strlen((const char*)key);

		HMAC_CTX hmac_ctx;
		HMAC_CTX_init(&hmac_ctx);

		if (!HMAC_Init_ex(&hmac_ctx,key,key_len,md,NULL)){
			return 0;	
		}
		HMAC_Update(&hmac_ctx,data,data_len);
		if (!HMAC_Final(&hmac_ctx,*out,out_len) || strlen((const char*)out) != *out_len){
			return 0;
		}
		HMAC_CTX_cleanup(&hmac_ctx);
	}
	return 0;

}

