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
	printHex((unsigned char*)&enc_data,DES_KEY_SZ);


	DES_cblock dec_data;
	des_decrypt_ecb(key,(const char*)&enc_data,&dec_data);
	printf("DES_ecb_decrypt data:\n");
	printChar((unsigned char*)&dec_data,DES_KEY_SZ);

}


void des_encrypt_ncbc(const char *des_key,const uint8_t *in,uint8_t *out,DES_cblock *ivec){
	DES_cblock key;
	memcpy(&key,des_key,DES_KEY_SZ);

	DES_key_schedule schedule;
	DES_set_key(&key,&schedule);
	
	DES_ncbc_encrypt(in,out,strlen((const char*)in),&schedule,ivec,DES_ENCRYPT);
}

void des_decrypt_ncbc(const char *des_key,const uint8_t *in,uint8_t *out,DES_cblock *ivec){
	DES_cblock key;
	memcpy(&key,des_key,DES_KEY_SZ);

	DES_key_schedule schedule;
	DES_set_key(&key,&schedule);

	DES_ncbc_encrypt(in,out,strlen((const char*)in),&schedule,ivec,DES_DECRYPT);
}

void des_ncbc_test(const char *key,const uint8_t *data,DES_cblock *enc_ivec,DES_cblock *dec_ivec){
	int len = strlen((const char*)data)+1;	
	uint8_t* enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);

	des_encrypt_ncbc(key,data,enc_data,enc_ivec);
	printf("DES_ncbc_encrypt data:\n");
	printHex((unsigned char*)enc_data, strlen((const char*)enc_data));

	int size = strlen((const char*)enc_data);
	uint8_t* dec_data= new uint8_t[size];
	memset(dec_data,0x00,size);

	des_decrypt_ncbc(key,(const uint8_t*)enc_data,dec_data,dec_ivec);
	printf("DES_ncbc_decrypt data:\n");
	printChar((unsigned char*)dec_data,strlen((const char*)dec_data));

	
	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;

}

void des_generate(const char *des_key,DES_key_schedule *ks){
	DES_cblock key;
	memcpy(&key,des_key,DES_KEY_SZ);
	DES_set_key(&key,ks);
}

void des_encrypt_ecb3(const DES_cblock *input,DES_cblock *output,const DES_key_schedule *ks1,const DES_key_schedule *ks2,const DES_key_schedule *ks3){
	DES_ecb3_encrypt(input,output,ks1,ks2,ks3,DES_ENCRYPT);		
}


void des_decrypt_ecb3(const DES_cblock *input,DES_cblock *output,const DES_key_schedule *ks1,const DES_key_schedule *ks2,const DES_key_schedule *ks3){
	DES_ecb3_encrypt(input,output,ks1,ks2,ks3,DES_DECRYPT);		
}

void des_ecb3_test(const char *data,const char *key1,const char *key2,const char *key3){
	DES_key_schedule ks1;
	des_generate(key1,&ks1);
	DES_key_schedule ks2;
	des_generate(key2,&ks2);
	DES_key_schedule ks3;
	des_generate(key3,&ks3);

	
	DES_cblock in;
	memcpy(&in,data,DES_KEY_SZ);


	DES_cblock enc_data;
	des_encrypt_ecb3(&in,&enc_data,(const DES_key_schedule*)&ks1,(const DES_key_schedule*)&ks2,(const DES_key_schedule*)&ks3);
	printf("DES_ecb3_encrypt data:\n");
	printHex((unsigned char*)&enc_data,DES_KEY_SZ);


	DES_cblock dec_data;
	des_decrypt_ecb3(&enc_data,&dec_data,(const DES_key_schedule*)&ks1,(const DES_key_schedule*)&ks2,(const DES_key_schedule*)&ks3);
	printf("DES_ecb3_decrypt data:\n");
	printChar((unsigned char*)&dec_data,DES_KEY_SZ);
}


void des_ede3_cbc_test(const char *data,const char *key1,const char *key2,const char *key3,DES_cblock *enc_ivec,DES_cblock *dec_ivec){
	DES_key_schedule ks1;
	des_generate(key1,&ks1);
	DES_key_schedule ks2;
	des_generate(key2,&ks2);
	DES_key_schedule ks3;
	des_generate(key3,&ks3);


	int len = strlen(data);
	uint8_t *enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);
	DES_ede3_cbc_encrypt((const uint8_t*)data,enc_data,len,(const DES_key_schedule*)&ks1,(const DES_key_schedule*)&ks2,(const DES_key_schedule*)&ks3,enc_ivec,DES_ENCRYPT);


	int size = strlen((const char*)enc_data);
	printf("DES_ede3_cbc_encrypt data:\n");
	printHex((unsigned char*)enc_data,size);

	uint8_t *dec_data = new uint8_t[size];
	memset(dec_data,0x00,size);
	DES_ede3_cbc_encrypt((const uint8_t*)enc_data,dec_data,size,(const DES_key_schedule*)&ks1,(const DES_key_schedule*)&ks2,(const DES_key_schedule*)&ks3,dec_ivec,DES_DECRYPT);
	printf("DES_ede3_cbc_decrypt data:\n");
	printChar((unsigned char*)dec_data,strlen((const char*)dec_data));

	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;

}

void des_ede2_cbc_test(const char *data,const char *key1,const char *key2,DES_cblock *enc_ivec,DES_cblock *dec_ivec){
	DES_key_schedule ks1;
	des_generate(key1,&ks1);
	DES_key_schedule ks2;
	des_generate(key2,&ks2);

	int len = strlen(data);
	uint8_t *enc_data = new uint8_t[len];
	memset(enc_data,0x00,len);
	DES_ede2_cbc_encrypt((const uint8_t*)data,enc_data,len,(const DES_key_schedule*)&ks1,(const DES_key_schedule*)&ks2,enc_ivec,DES_ENCRYPT);


	int size = strlen((const char*)enc_data);
	printf("DES_ede2_cbc_encrypt data:\n");
	printHex((unsigned char*)enc_data,size);

	uint8_t *dec_data = new uint8_t[size];
	memset(dec_data,0x00,size);
	DES_ede2_cbc_encrypt((const uint8_t*)enc_data,dec_data,size,(const DES_key_schedule*)&ks1,(const DES_key_schedule*)&ks2,dec_ivec,DES_DECRYPT);
	printf("DES_ede2_cbc_decrypt data:\n");
	printChar((unsigned char*)dec_data,strlen((const char*)dec_data));

	delete enc_data;
	enc_data = NULL;

	delete dec_data;
	dec_data = NULL;

}



void get_ivec(DES_cblock *ivec,const char *src_ivec){
	memcpy(ivec,src_ivec,DES_KEY_SZ);
}

int main(int argc,char* argv[]){
	char des_key[] = "12345678";
	char key1[] = "12345678";
	char key2[] = "87654321";
	char key3[] = "88888888";

	char data[] = "OrangePC";
	const char data_des[] = "Hello Github World Square FaceBook";


	char ivec[] = "11223344";

	DES_cblock enc_ivec;
	get_ivec(&enc_ivec,(const char*)ivec);
	
	DES_cblock dec_ivec;
	get_ivec(&dec_ivec,(const char*)ivec);


	DES_cblock enc_ivec_ede3;
	get_ivec(&enc_ivec_ede3,(const char*)ivec);
	
	DES_cblock dec_ivec_ede3;
	get_ivec(&dec_ivec_ede3,(const char*)ivec);


	DES_cblock enc_ivec_ede2;
	get_ivec(&enc_ivec_ede2,(const char*)ivec);
	
	DES_cblock dec_ivec_ede2;
	get_ivec(&dec_ivec_ede2,(const char*)ivec);

	des_ecb_test((const char*)des_key,(const char*)data);
	

	des_ncbc_test((const char*)des_key,(const uint8_t*)data_des,&enc_ivec,&dec_ivec);

	des_ecb3_test((const char*)data,(const char*)key1,(const char*)key2,(const char*)key3);
	
	
	des_ede3_cbc_test((const char*)data_des,(const char*)key1,(const char*)key2,(const char*)key3,&enc_ivec_ede3,&dec_ivec_ede3);


	des_ede2_cbc_test((const char*)data_des,(const char*)key1,(const char*)key2,&enc_ivec_ede2,&dec_ivec_ede2);

	return 0;
}
