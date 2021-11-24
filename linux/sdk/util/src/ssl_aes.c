#include <string.h>
#include <stdlib.h>
#include <ssl_aes.h>


const EVP_CIPHER *get_cipher(int mode){
	switch (mode){
		case EVP_aes_128_cbc:
			return EVP_get_cipherbynid(NID_aes_128_cbc);
		case EVP_aes_128_ctr:
			return EVP_get_cipherbynid(NID_aes_128_ctr);
		case EVP_aes_128_ecb:
			return EVP_get_cipherbynid(NID_aes_128_ecb);
		case EVP_aes_128_ofb:
			return EVP_get_cipherbynid(NID_aes_128_ofb128);
		case EVP_aes_192_cbc:
			return EVP_get_cipherbynid(NID_aes_192_cbc);
		case EVP_aes_192_ctr:
			return EVP_get_cipherbynid(NID_aes_192_ctr);
		case EVP_aes_192_ecb:
			return EVP_get_cipherbynid(NID_aes_192_ecb);
		case EVP_aes_192_ofb:
			return EVP_get_cipherbynid(NID_aes_192_ofb128);
		case EVP_aes_256_cbc:
			return EVP_get_cipherbynid(NID_aes_256_cbc);
		case EVP_aes_256_ctr:
			return EVP_get_cipherbynid(NID_aes_256_ctr);
		case EVP_aes_256_ecb:
			return EVP_get_cipherbynid(NID_aes_256_ecb);
		case EVP_aes_256_ofb:
			return EVP_get_cipherbynid(NID_aes_256_ofb128);
		default:
			return NULL;
	}
}


int aes_encrypt(const unsigned char *key,int data_len,const unsigned char *in,unsigned char **out,int *out_len,const unsigned char *iv,int mode){
	int update_len = 0;
	int final_len = 0;
	int size = data_len;
	if (size % AES_BLOCK_SIZE != 0){
		size = (size / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE; 
	}
	
	const EVP_CIPHER *cipher = get_cipher(mode);
	if (cipher == NULL){
		return 0;
	}

	*out = (unsigned char*)malloc(size + EVP_MAX_BLOCK_LENGTH + 1);
	if (*out){
		memset(*out,0x00,size + EVP_MAX_BLOCK_LENGTH + 1);
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);

		if (!EVP_EncryptInit_ex(&ctx,cipher,NULL,key,iv) || !EVP_EncryptUpdate(&ctx,*out,&update_len,in,data_len) || !EVP_EncryptFinal_ex(&ctx,*out+update_len,&final_len)){
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		EVP_CIPHER_CTX_cleanup(&ctx);
		int len = update_len + final_len;
		*out_len = len;
		return 1;
	}
	return 0;
}


int aes_decrypt(const unsigned char *key,int data_len,const unsigned char *in,unsigned char **out,int *out_len,const unsigned char *iv,int mode){

	int update_len = 0;
	int final_len = 0;
	
        const EVP_CIPHER *cipher = get_cipher(mode);
	if (cipher == NULL){
		return 0;
	}

	*out = (unsigned char*)malloc(data_len + EVP_MAX_BLOCK_LENGTH + 1);
	if (*out){
		memset(*out,0x00,data_len + EVP_MAX_BLOCK_LENGTH + 1);
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);

		if (!EVP_DecryptInit_ex(&ctx,cipher,NULL,key,iv) || !EVP_DecryptUpdate(&ctx,*out,&update_len,in,data_len) || !EVP_DecryptFinal_ex(&ctx,*out+update_len,&final_len)){
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		EVP_CIPHER_CTX_cleanup(&ctx);
		int len = update_len + final_len;
		*out_len = len;
		return 1;
	}
	return 0;
}  



