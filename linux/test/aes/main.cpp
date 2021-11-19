#include <stdio.h>
#include <openssl/aes.h>
#include <cstring>
#include <io_util.h>


int aes_encrypt(const char *key,const uint8_t *data,uint8_t *out){
	int length = strlen(key);
	
	AES_KEY aeskey;
	int ret = AES_set_encrypt_key((const uint8_t*)key,length  * 8,&aeskey);
	if (ret == 0){
		AES_encrypt(data,out,&aeskey);
		return 0;
	}
	return -1;
}

int aes_decrypt(const char *key,const uint8_t *enc_data,uint8_t *out){
	int length = strlen(key);
	
	AES_KEY aeskey;
	int ret = AES_set_decrypt_key((const uint8_t*)key,length  * 8,&aeskey);
	if (ret == 0){
		AES_decrypt((const uint8_t*)enc_data,out,&aeskey);
		return 0;
	}
	return -1;
}

int aes_test(const char *key,const char *data){
	int length = strlen(key);
	int len = strlen(data);
	uint8_t *enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);
	aes_encrypt(key,(const uint8_t*)data,enc_data);
	
	printf("aes_encrypt data(%d bytes)\n",length);
	printHex((const unsigned char*)enc_data,strlen((const char*)enc_data));
        
	int size = strlen((const char*)enc_data);
	uint8_t *dec_data = new uint8_t[size];
	memset(dec_data,0x00,size);
	aes_decrypt(key,(const uint8_t*)enc_data,dec_data);
	
	printf("aes_decrypt data(%d bytes)\n",length);
	printChar((const unsigned char*)dec_data,strlen((const char*)dec_data));

	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;
}

int aes_ctr_encrypt(const char *key,const char *data,uint8_t *out,uint8_t *ivec,unsigned int *num){
	int length = strlen(key);
	
	AES_KEY aeskey;
	int ret = AES_set_encrypt_key((const uint8_t*)key,length  * 8,&aeskey);

	if (ret == 0){
		uint8_t *ecount_buf = new uint8_t[AES_BLOCK_SIZE];
		memset(ecount_buf,0x00,AES_BLOCK_SIZE);
	   	AES_ctr128_encrypt((const uint8_t*)data,out,strlen(data),&aeskey,ivec,ecount_buf,num);

		delete ecount_buf;
		ecount_buf = NULL;

		return 0;
	}
	return -1;

}

int aes_ctr_test(const char *key,const char *data,uint8_t *ivec_enc,uint8_t *ivec_dec){
	unsigned int enc_num = 0;
	int len = strlen(data);
	uint8_t *enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);
	aes_ctr_encrypt(key,data,enc_data,ivec_enc,&enc_num);

	printf("aes_ctr128_encrypt data(ctr)\n");
	printHex((const unsigned char*)enc_data,strlen((const char*)enc_data));
	
	unsigned int dec_num = 0;
	int size = strlen((const char*)enc_data);
	uint8_t *dec_data = new uint8_t[size];
	memset(dec_data,0x00,size);
	aes_ctr_encrypt(key,(const char*)enc_data,dec_data,ivec_dec,&dec_num);

	printf("aes_ctr128_decrypt data(ctr)\n");
	printChar((const unsigned char*)dec_data,strlen((const char*)dec_data));
	
	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;
	
	return 0;
}

int aes_encrypt_ecb(const char *key,const uint8_t *data,uint8_t *out){
	int length = strlen(key);

	AES_KEY aeskey;
	int ret = AES_set_encrypt_key((const uint8_t*)key,length  * 8,&aeskey);
	if (ret == 0){
		AES_ecb_encrypt(data,out,&aeskey,AES_ENCRYPT);
		return 0;
	}
	return -1;
}

int aes_decrypt_ecb(const char *key,const uint8_t *data,uint8_t *out){
	int length = strlen(key);

	AES_KEY aeskey;
	int ret = AES_set_decrypt_key((const uint8_t*)key,length  * 8,&aeskey);
	if (ret == 0){
		AES_ecb_encrypt(data,out,&aeskey,AES_DECRYPT);
		return 0;
	}
	return -1;
}

int aes_ecb_test(const char *key,const uint8_t *data){
	int length = strlen(key);
     
       	int len = strlen((const char*)data);	
	uint8_t *enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);
	aes_encrypt_ecb(key,data,enc_data);

	printf("aes_ecb_encrypt data(%d bytes)\n",length);
	printHex((const unsigned char*)enc_data,strlen((const char*)enc_data));
	
	int size = strlen((const char*)enc_data);
	uint8_t *dec_data = new uint8_t[size];
	memset(dec_data,0x00,size);
	aes_decrypt_ecb(key,(const uint8_t*)enc_data,dec_data);

	printf("aes_ecb_decrypt data(%d bytes)\n",length);
	printChar((const unsigned char*)dec_data,strlen((const char*)dec_data));
	
	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;
	
	return 0;
}

int aes_encrypt_cbc(const char *key,const uint8_t *data,uint8_t *out,uint8_t *ivec){
	int length = strlen(key);

	AES_KEY aeskey;
	int ret = AES_set_encrypt_key((const uint8_t*)key,length  * 8,&aeskey);
	if (ret == 0){
		AES_cbc_encrypt(data,out,strlen((const char*)data),&aeskey,ivec,AES_ENCRYPT);
		return 0;
	}
	return -1;
}

int aes_decrypt_cbc(const char *key,const uint8_t *data,uint8_t *out,uint8_t *ivec){
	int length = strlen(key);

	AES_KEY aeskey;
	int ret = AES_set_decrypt_key((const uint8_t*)key,length  * 8,&aeskey);
	if (ret == 0){
		AES_cbc_encrypt(data,out,strlen((const char*)data),&aeskey,ivec,AES_DECRYPT);
		return 0;
	}
	return -1;
}

int aes_cbc_test(const char *key,const uint8_t *data,uint8_t *ivec_enc,uint8_t *ivec_dec){
	int length = strlen(key);

	int len = strlen((const char*)data);
	uint8_t *enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);
	aes_encrypt_cbc(key,data,enc_data,ivec_enc);

	printf("aes_cbc_encrypt data(%d bytes)\n",length);
	printHex((const unsigned char*)enc_data,strlen((const char*)enc_data));
	
	int size = strlen((const char*)enc_data);
	uint8_t *dec_data = new uint8_t[size];
	memset(dec_data,0x00,size);
	aes_decrypt_cbc(key,(const uint8_t*)enc_data,dec_data,ivec_dec);

	printf("aes_cbc_decrypt data(%d bytes)\n",length);
	printChar((const unsigned char*)dec_data,strlen((const char*)dec_data));
	
	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;
	
	return 0;
}

int aes_ofb_encrypt(const char *key,const uint8_t *data,uint8_t *out,uint8_t *ivec,int *num){
	int length = strlen(key);
	
	AES_KEY aeskey;
	int ret = AES_set_encrypt_key((const uint8_t*)key,length  * 8,&aeskey);

	if (ret == 0){
	   	AES_ofb128_encrypt(data,out,strlen((const char*)data),&aeskey,ivec,num);
		return 0;
	}
	return -1;

}

int aes_ofb_test(const char *key,const uint8_t *data,uint8_t *ivec_enc,uint8_t *ivec_dec){
	int enc_num = 0;
	int len = strlen((const char*)data);
	uint8_t *enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);
	aes_ofb_encrypt(key,data,enc_data,ivec_enc,&enc_num);

	printf("aes_ofb128_encrypt data\n");
	printHex((const unsigned char*)enc_data,strlen((const char*)enc_data));
	

	int dec_num = 0;
	int size = strlen((const char*)enc_data);
	uint8_t *dec_data = new uint8_t[size];
	memset(dec_data,0x00,size);
	aes_ofb_encrypt(key,(const uint8_t*)enc_data,dec_data,ivec_dec,&dec_num);

	printf("aes_ofb128_decrypt data\n");
	printChar((const unsigned char*)dec_data,strlen((const char*)dec_data));
	
	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;
	
	return 0;
}


int aes_encrypt_cfb(const char *key,const uint8_t *data,uint8_t *out,uint8_t *ivec,int *num){
	int length = strlen(key);

	AES_KEY aeskey;
	int ret = AES_set_encrypt_key((const uint8_t*)key,length  * 8,&aeskey);
	if (ret == 0){
		AES_cfb128_encrypt(data,out,strlen((const char*)data),&aeskey,ivec,num,AES_ENCRYPT);
		return 0;
	}
	return -1;
}

int aes_decrypt_cfb(const char *key,const uint8_t *data,uint8_t *out,uint8_t *ivec,int *num){
	int length = strlen(key);

	AES_KEY aeskey;
	int ret = AES_set_encrypt_key((const uint8_t*)key,length  * 8,&aeskey);
	if (ret == 0){
		AES_cfb128_encrypt(data,out,strlen((const char*)data),&aeskey,ivec,num,AES_DECRYPT);
		return 0;
	}
	return -1;
}

int aes_cfb_test(const char *key,const uint8_t *data,uint8_t *ivec_enc,uint8_t *ivec_dec){
	
	int len = strlen((const char*)data);
      	int enc_num = 0;
	uint8_t *enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);
	aes_encrypt_cfb(key,data,enc_data,ivec_enc,&enc_num);

	printf("aes_cfb128_encrypt data\n");
	printHex((const unsigned char*)enc_data,strlen((const char*)enc_data));
	
	int size = strlen((const char*)enc_data);
	int dec_num = 0;
	uint8_t *dec_data = new uint8_t[size];
	memset(dec_data,0x00,size);
	aes_decrypt_cfb(key,(const uint8_t*)enc_data,dec_data,ivec_dec,&dec_num);

	printf("aes_cfb128_decrypt data\n");
	printChar((const unsigned char*)dec_data,strlen((const char*)dec_data));
	
	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;
	
	return 0;
}

int main(int argc,char *argv[]){
	char key1[] = "1234567812345678";
	char key2[] = "123456781234567812345678";
	char key3[] = "12345678123456781234567812345678";
	
//	char data[] = "Hello World";
	char data[] = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXX";
	
	char ivec_enc[]="1111222233334444";
	char ivec_dec[]="1111222233334444";

	char ivec_enc_ctr[]="1111222233334444";
	char ivec_dec_ctr[]="1111222233334444";

	char ivec_enc_ofb[]="1111222233334444";
	char ivec_dec_ofb[]="1111222233334444";

	char ivec_enc_cfb[]="1111222233334444";
	char ivec_dec_cfb[]="1111222233334444";

	aes_test((const char*)key1,(const char*)data);
	aes_test((const char*)key2,(const char*)data);
	aes_test((const char*)key3,(const char*)data);

	
	aes_ctr_test((const char*)key1,(const char*)data,(uint8_t*)ivec_enc_ctr,(uint8_t*)ivec_dec_ctr);

	aes_ecb_test((const char*)key1,(const uint8_t*)data);
	aes_ecb_test((const char*)key2,(const uint8_t*)data);
	aes_ecb_test((const char*)key3,(const uint8_t*)data);
	
	aes_cbc_test((const char*)key1,(const uint8_t*)data,(uint8_t*)ivec_enc,(uint8_t*)ivec_dec);
	aes_cbc_test((const char*)key2,(const uint8_t*)data,(uint8_t*)ivec_enc,(uint8_t*)ivec_dec);
	aes_cbc_test((const char*)key3,(const uint8_t*)data,(uint8_t*)ivec_enc,(uint8_t*)ivec_dec);

	aes_ofb_test((const char*)key1,(const uint8_t*)data,(uint8_t*)ivec_enc_ofb,(uint8_t*)ivec_dec_ofb);

	aes_cfb_test((const char*)key1,(const uint8_t*)data,(uint8_t*)ivec_enc_cfb,(uint8_t*)ivec_dec_cfb);

}
