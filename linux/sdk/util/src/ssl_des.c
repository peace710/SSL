#include <string.h>
#include <stdlib.h>
#include <ssl_des.h>


const EVP_CIPHER *get_des_cipher(int mode){
	switch (mode){
		case EVP_des_cbc:
			return EVP_get_cipherbynid(NID_des_cbc);
		case EVP_des_ecb:
			return EVP_get_cipherbynid(NID_des_ecb);
		case EVP_des_ede_cbc:
			return EVP_get_cipherbynid(NID_des_ede_cbc);
		case EVP_des_ede_ecb:
			return EVP_get_cipherbynid(NID_des_ede_ecb);
		case EVP_des_ede3_cbc:
			return EVP_get_cipherbynid(NID_des_ede3_cbc);
		default:
			return NULL;
	}
}


int des_encrypt(const unsigned char *key,int data_len,const unsigned char *in,unsigned char **out,int *out_len,const unsigned char *iv,int mode){
	int update_len = 0;
	int final_len = 0;
	int size = data_len;
	if (size % DES_KEY_SZ != 0){
		size = (size / DES_KEY_SZ + 1) * DES_KEY_SZ; 
	}
	
	const EVP_CIPHER *cipher = get_des_cipher(mode);
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


int des_decrypt(const unsigned char *key,int data_len,const unsigned char *in,unsigned char **out,int *out_len,const unsigned char *iv,int mode){

	int update_len = 0;
	int final_len = 0;
	
        const EVP_CIPHER *cipher = get_des_cipher(mode);
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



