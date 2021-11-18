#include <stdio.h>
#include <openssl/des.h>
#include <cstring>
#include <io_util.h>

void des_encrypt_ecb(const char *des_key,const char *data,DES_cblock *out){
	DES_cblock key;
	memcpy(&key,des_key,DES_KEY_SZ);

	DES_key_schedule schedule;
	DES_set_key(&key,&schedule);

	DES_cblock in;
	memcpy(&in,data,DES_KEY_SZ);

	DES_ecb_encrypt((const DES_cblock*)&in,out,&schedule,DES_ENCRYPT);
}

void des_decrypt_ecb(const char *des_key,const char *data,DES_cblock *out){
	DES_cblock key;
	memcpy(&key,des_key,DES_KEY_SZ);

	DES_key_schedule schedule;
	DES_set_key(&key,&schedule);

	DES_cblock in;
	memcpy(&in,data,DES_KEY_SZ);

	DES_ecb_encrypt((const DES_cblock*)&in,out,&schedule,DES_DECRYPT);
}

void des_ecb_test(const char *key,const char *data){
	DES_cblock enc_data;
	des_encrypt_ecb(key,data,&enc_data);
	printf("DES_ecb_encrypt data:\n");
	printHex((unsigned char*)&enc_data,strlen((const char *)enc_data.bytes));


	DES_cblock dec_data;
	des_decrypt_ecb(key,(const char*)&enc_data,&dec_data);
	printf("DES_ecb_decrypt data:\n");
	printChar((unsigned char*)&dec_data,DES_KEY_SZ);

}



int main(int argc,char* argv[]){
	char des_key[] = "12345678";
	char data[] = "OrangePC";

	des_ecb_test((const char*)des_key,(const char*)data);


	return 0;
}
