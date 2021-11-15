#include <stdio.h>
#include <openssl/aes.h>
#include <cstring>
#include <io_util.h>

int aes_encrypt(const char* key,const uint8_t* data,uint8_t* out){
	int length = strlen(key);
	
	AES_KEY aeskey;
	int ret = AES_set_encrypt_key((const uint8_t*)key,length * 8,&aeskey);
	if (ret == 0){
		AES_encrypt(data,out,&aeskey);
		return 0;
	}
	return -1;
}

int aes_decrypt(const char* key,const uint8_t* enc_data,uint8_t* out){
	int length = strlen(key);
	
	AES_KEY aeskey;
	int ret = AES_set_decrypt_key((const uint8_t*)key,length * 8,&aeskey);
	if (ret == 0){
		AES_decrypt((const uint8_t*)enc_data,out,&aeskey);
		return 0;
	}
	return -1;
}

int aes_test(const char* key,const char* data){
	int length = strlen(key);
	uint8_t* enc_data = new uint8_t;
	
	aes_encrypt(key,(const uint8_t*)data,enc_data);
	printf("encrypt data(%d bytes)\n",length);
	printHex((const unsigned char*)enc_data,strlen((const char*)enc_data));
        
	uint8_t* dec_data = new uint8_t;
	aes_decrypt(key,(const uint8_t*)enc_data,dec_data);
	
	printf("decrypt data(%d bytes)\n",length);
	printChar((const unsigned char*)dec_data,strlen((const char*)dec_data));

	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;
}

int main(int argc,char* argv[]){
	char key1[] = "1234567812345678";
	char key2[] = "123456781234567812345678";
	char key3[] = "12345678123456781234567812345678";
	
	char data[] = "Hello World";
	
	aes_test((const char*)key1,(const char*)data);
	aes_test((const char*)key2,(const char*)data);
	aes_test((const char*)key3,(const char*)data);
	
}
