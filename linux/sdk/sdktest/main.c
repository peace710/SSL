#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hex.h>
#include <ssl_sha.h>
#include <ssl_md.h>
#include <ssl_hmac.h>
#include <ssl_aes.h>
#include <ssl_des.h>
#include <ssl_rsa.h>
#include <openssl/err.h>

void printHex(const unsigned char *data,int len){
	for (int i = 0 ;i < len; i++){
		printf("%02X",data[i]);
	}
	printf("\n");
}

void printChar(const char *data,int len){
	for (int i = 0;i < len;i++){
		printf("%c",data[i]);
	}
	printf("\n");
}

void cleanup(void *ptr){
	if (ptr != NULL){
		free(ptr);
		ptr = NULL;	
	}
}

void test_hex(){
	char p[] = "Desktop of War -> Call of Duty";

	int len = strlen((const char*)p);
	
	char *hex_out = NULL;
	int hex_len = hex_encode((const unsigned char*)p,len,&hex_out);

	char *out = NULL;
	int out_len = hex_decode((const unsigned char*)hex_out,(const int)hex_len,(unsigned char**)&out);


	printChar((const char*)out,out_len);

	cleanup(hex_out);
	cleanup(out);

}

void test_sha(){
	char data[] = "hello world";
	int len = 0;
	unsigned char *out = NULL;

	len = sha((const char*)data,&out,SHA_1);
	printf("SHA1:");
	printHex((const unsigned char*)out,len);
	cleanup(out);
	
	len = sha((const char*)data,&out,SHA_224);
	printf("SHA224:");
	printHex((const unsigned char*)out,len);
	cleanup(out);
	
	len = sha((const char*)data,&out,SHA_256);
	printf("SHA256:");
	printHex((const unsigned char*)out,len);
	cleanup(out);
	
	len = sha((const char*)data,&out,SHA_384);
	printf("SHA384:");
	printHex((const unsigned char*)out,len);
	cleanup(out);
	
	len = sha((const char*)data,&out,SHA_512);
	printf("SHA512:");
	printHex((const unsigned char*)out,len);
	cleanup(out);
	
	len = sha((const char*)data,&out,SHA_512_256);
	printf("SHA512_256:");
	printHex((const unsigned char*)out,len);
	cleanup(out);
}

void test_md(){
	char data[] = "hello world";
	int len = 0;
	unsigned char *out = NULL;

	len = md((const char*)data,&out,MD_4);
	printf("MD4:");
	printHex((const unsigned char*)out,len);
	cleanup(out);
	
	len = md((const char*)data,&out,MD_5);
	printf("MD5:");
	printHex((const unsigned char*)out,len);
	cleanup(out);
}

void test_hmac(){
	char data[] = "hello world";
	char key[] = "1234567890";

	uint8_t *out = NULL;
	unsigned int out_len;

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_MD4);
	printf("HMAC_MD4:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_MD5);
	printf("HMAC_MD5:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);
		
	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_SHA1);
	printf("HMAC_SHA1:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_SHA224);
	printf("HMAC_SHA224:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_SHA256);
	printf("HMAC_SHA256:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_SHA384);
	printf("HMAC_SHA384:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_SHA512);
	printf("HMAC_SHA512:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_SHA512_256);
	printf("HMAC_SHA512_256:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_BLAKE_2B_256);
	printf("HMAC_SHA_BLAKE_2B_256:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);

	hmac((const uint8_t*)data,key,&out,&out_len,HMAC_MD5_SHA1);
	printf("HMAC_MD5_SHA1:\n");
	printHex((const unsigned char*)out,out_len);
	cleanup(out);
}

void test_aes_128(){
	char key128[] = "0123456789ABCDEF";

	char data[] = "Hello World OpenSSL Linux 支持中文吗，你好世界";
	int data_len = strlen(data);
	
	unsigned char *enc = NULL;
	int enc_len = 0;

	unsigned char *dec = NULL;
	int dec_len = 0;

	aes_encrypt((const unsigned char*)key128,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_128_cbc);
	printf("aes_128_cbc:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key128,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_128_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;
	

	aes_encrypt((const unsigned char*)key128,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_128_ctr);
	printf("aes_128_ctr:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key128,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_128_ctr);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	aes_encrypt((const unsigned char*)key128,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_128_ecb);
	printf("aes_128_ecb:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key128,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_128_ecb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	aes_encrypt((const unsigned char*)key128,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_128_ofb);
	printf("aes_128_ofb:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key128,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_128_ofb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

}

void test_aes_192(){
	char key192[] = "ABCDEFGHIJKLMNOPQRSTUVWX";

	char data[] = "Hello World OpenSSL Linux 支持中文吗，你好世界";
	int data_len = strlen(data);
	
	unsigned char *enc = NULL;
	int enc_len = 0;

	unsigned char *dec = NULL;
	int dec_len = 0;

	aes_encrypt((const unsigned char*)key192,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_192_cbc);
	printf("aes_192_cbc:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key192,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_192_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;
	

	aes_encrypt((const unsigned char*)key192,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_192_ctr);
	printf("aes_192_ctr:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key192,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_192_ctr);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	aes_encrypt((const unsigned char*)key192,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_192_ecb);
	printf("aes_192_ecb:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key192,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_192_ecb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	aes_encrypt((const unsigned char*)key192,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_192_ofb);
	printf("aes_192_ofb:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key192,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_192_ofb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

}

void test_aes_256(){
	char key256[] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";

	char data[] = "AES最常见的有3种方案，分别是AES-128、AES-192和AES-256，它们的区别在于密钥长度不同，AES-128的密钥长度为16bytes（128bit / 8），后两者分别为24bytes和32bytes。密钥越长，安全强度越高，但伴随运算轮数的增加，带来的运算开销就会更大，所以用户应根据不同应用场合进行合理选择";
	int data_len = strlen(data);
	
	unsigned char *enc = NULL;
	int enc_len = 0;

	unsigned char *dec = NULL;
	int dec_len = 0;

	aes_encrypt((const unsigned char*)key256,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_256_cbc);
	printf("aes_256_cbc:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key256,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_256_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;
	

	aes_encrypt((const unsigned char*)key256,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_256_ctr);
	printf("aes_256_ctr:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key256,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_256_ctr);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	aes_encrypt((const unsigned char*)key256,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_256_ecb);
	printf("aes_256_ecb:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key256,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_256_ecb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	aes_encrypt((const unsigned char*)key256,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_aes_256_ofb);
	printf("aes_256_ofb:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key256,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_aes_256_ofb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

}

void test_aes_128_iv(){
	char key128[] = "0123456789ABCDEF";

	char data[] = "Hello World OpenSSL Linux 支持中文吗，你好世界";
	int data_len = strlen(data);
	
	unsigned char *enc = NULL;
	int enc_len = 0;

	unsigned char *dec = NULL;
	int dec_len = 0;

	char cbc_enc_iv[] = "1111222233334444";
	char cbc_dec_iv[] = "1111222233334444";
	aes_encrypt((const unsigned char*)key128,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)cbc_enc_iv,EVP_aes_128_cbc);
	printf("aes_128_cbc_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key128,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)cbc_dec_iv,EVP_aes_128_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;
	
	char ctr_enc_iv[] = "1111222233334444";
	char ctr_dec_iv[] = "1111222233334444";
	aes_encrypt((const unsigned char*)key128,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)ctr_enc_iv,EVP_aes_128_ctr);
	printf("aes_128_ctr_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key128,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)ctr_dec_iv,EVP_aes_128_ctr);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	char ofb_enc_iv[] = "1111222233334444";
	char ofb_dec_iv[] = "1111222233334444";
	aes_encrypt((const unsigned char*)key128,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)ofb_enc_iv,EVP_aes_128_ofb);
	printf("aes_128_ofb_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key128,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)ofb_dec_iv,EVP_aes_128_ofb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

}

void test_aes_192_iv(){
	char key192[] = "0123456789ABCDEF";

	char data[] = "Hello World OpenSSL Linux 支持中文吗，你好世界";
	int data_len = strlen(data);
	
	unsigned char *enc = NULL;
	int enc_len = 0;

	unsigned char *dec = NULL;
	int dec_len = 0;

	char cbc_enc_iv[] = "111122223333444455556666";
	char cbc_dec_iv[] = "111122223333444455556666";
	aes_encrypt((const unsigned char*)key192,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)cbc_enc_iv,EVP_aes_192_cbc);
	printf("aes_192_cbc_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key192,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)cbc_dec_iv,EVP_aes_192_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;
	
	char ctr_enc_iv[] = "111122223333444455556666";
	char ctr_dec_iv[] = "111122223333444455556666";
	aes_encrypt((const unsigned char*)key192,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)ctr_enc_iv,EVP_aes_192_ctr);
	printf("aes_192_ctr_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key192,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)ctr_dec_iv,EVP_aes_192_ctr);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	char ofb_enc_iv[] = "111122223333444455556666";
	char ofb_dec_iv[] = "111122223333444455556666";
	aes_encrypt((const unsigned char*)key192,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)ofb_enc_iv,EVP_aes_192_ofb);
	printf("aes_192_ofb_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key192,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)ofb_dec_iv,EVP_aes_192_ofb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

}

void test_aes_256_iv(){
	char key256[] = "0123456789ABCDEF";

	char data[] = "AES最常见的有3种方案，分别是AES-128、AES-192和AES-256，它们的区别在于密钥长度不同，AES-128的密钥长度为16bytes（128bit / 8），后两者分别为24bytes和32bytes。密钥越长，安全强度越高，但伴随运算轮数的增加，带来的运算开销就会更大，所以用户应根据不同应用场合进行合理选择";
	int data_len = strlen(data);
	
	unsigned char *enc = NULL;
	int enc_len = 0;

	unsigned char *dec = NULL;
	int dec_len = 0;

	char cbc_enc_iv[] = "11112222333344445555666677778888";
	char cbc_dec_iv[] = "11112222333344445555666677778888";
	aes_encrypt((const unsigned char*)key256,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)cbc_enc_iv,EVP_aes_256_cbc);
	printf("aes_256_cbc_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key256,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)cbc_dec_iv,EVP_aes_256_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;
	
	char ctr_enc_iv[] = "11112222333344445555666677778888";
	char ctr_dec_iv[] = "11112222333344445555666677778888";
	aes_encrypt((const unsigned char*)key256,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)ctr_enc_iv,EVP_aes_256_ctr);
	printf("aes_256_ctr_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key256,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)ctr_dec_iv,EVP_aes_256_ctr);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

	char ofb_enc_iv[] = "11112222333344445555666677778888";
	char ofb_dec_iv[] = "11112222333344445555666677778888";
	aes_encrypt((const unsigned char*)key256,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)ofb_enc_iv,EVP_aes_256_ofb);
	printf("aes_256_ofb_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	aes_decrypt((const unsigned char*)key256,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)ofb_dec_iv,EVP_aes_256_ofb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

}

void test_des(){
	char key[] = "ABCDEFGH";
	char key16[] = "ABCDEFGH69696969";
	char key24[] = "12345678ABCDEFGH99996666";

	char data[] = "AES最常见的有3种方案，分别是AES-128、AES-192和AES-256，它们的区别在于密钥长度不同，AES-128的密钥长度为16bytes（128bit / 8），后两者分别为24bytes和32bytes。密钥越长，安全强度越高，但伴随运算轮数的增加，带来的运算开销就会更大，所以用户应根据不同应用场合进行合理选择";
	int data_len = strlen(data);

	unsigned char *enc = NULL;
	int enc_len = 0;

	unsigned char *dec = NULL;
	int dec_len = 0;

	des_encrypt((const unsigned char*)key,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_des_cbc);
	printf("des_cbc:\n");
	printHex((const unsigned char*)enc,enc_len);
	des_decrypt((const unsigned char*)key,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_des_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	des_encrypt((const unsigned char*)key,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_des_ecb);
	printf("des_ecb:\n");
	printHex((const unsigned char*)enc,enc_len);
	des_decrypt((const unsigned char*)key,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_des_ecb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	des_encrypt((const unsigned char*)key16,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_des_ede_cbc);
	printf("des_ede_cbc:\n");
	printHex((const unsigned char*)enc,enc_len);
	des_decrypt((const unsigned char*)key16,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_des_ede_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	des_encrypt((const unsigned char*)key16,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_des_ede_ecb);
	printf("des_ede_ecb:\n");
	printHex((const unsigned char*)enc,enc_len);
	des_decrypt((const unsigned char*)key16,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_des_ede_ecb);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	des_encrypt((const unsigned char*)key24,data_len,(const unsigned char*)data,&enc,&enc_len,NULL,EVP_des_ede3_cbc);
	printf("des_ede3_cbc:\n");
	printHex((const unsigned char*)enc,enc_len);
	des_decrypt((const unsigned char*)key24,enc_len,(const unsigned char*)enc,&dec,&dec_len,NULL,EVP_des_ede3_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

}

void test_des_iv(){
	char key[] = "ABCDEFGH";
	char key16[] = "ABCDEFGH69696969";
	char key24[] = "12345678ABCDEFGH99996666";

	char data[] = "AES最常见的有3种方案，分别是AES-128、AES-192和AES-256，它们的区别在于密钥长度不同，AES-128的密钥长度为16bytes（128bit / 8），后两者分别为24bytes和32bytes。密钥越长，安全强度越高，但伴随运算轮数的增加，带来的运算开销就会更大，所以用户应根据不同应用场合进行合理选择";
	int data_len = strlen(data);
	
	unsigned char *enc = NULL;
	int enc_len = 0;

	unsigned char *dec = NULL;
	int dec_len = 0;

	char cbc_enc_iv[] = "12345678";
	char cbc_dec_iv[] = "12345678";
	des_encrypt((const unsigned char*)key,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)cbc_enc_iv,EVP_des_cbc);
	printf("des_cbc_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	des_decrypt((const unsigned char*)key,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)cbc_dec_iv,EVP_des_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;


	char ede_cbc_enc_iv[] = "12345678";
	char ede_cbc_dec_iv[] = "12345678";
	des_encrypt((const unsigned char*)key16,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)ede_cbc_enc_iv,EVP_des_ede_cbc);
	printf("des_ede_cbc_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	des_decrypt((const unsigned char*)key16,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)ede_cbc_dec_iv,EVP_des_ede_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

	char ede3_cbc_enc_iv[] = "12345678";
	char ede3_cbc_dec_iv[] = "12345678";
	des_encrypt((const unsigned char*)key24,data_len,(const unsigned char*)data,&enc,&enc_len,(const unsigned char *)ede3_cbc_enc_iv,EVP_des_ede3_cbc);
	printf("des_ede3_cbc_iv:\n");
	printHex((const unsigned char*)enc,enc_len);
	des_decrypt((const unsigned char*)key24,enc_len,(const unsigned char*)enc,&dec,&dec_len,(const unsigned char *)ede3_cbc_dec_iv,EVP_des_ede3_cbc);
	printChar((const unsigned char*)dec,dec_len);
	cleanup(enc);
	enc_len = 0;
	cleanup(dec);
	dec_len = 0;

}

void test_rsa_gen(){
	RSA *rsa = NULL;
	rsa = rsa_bits(RSA_BITS_1024);
	printf("---------------------------------------------\n");
	printf("public modulus(n) %s\n", BN_bn2hex(rsa->n));
	printf("public modulus(10n) %s\n", BN_bn2dec(rsa->n));
	printf("public exponent(e) %s\n", BN_bn2hex(rsa->e));
	printf("private exponent(d) %s\n", BN_bn2hex(rsa->d));
	printf("private exponent(10d) %s\n", BN_bn2dec(rsa->d));
	printf("secret prime factor(p) %s\n", BN_bn2hex(rsa->p));
	printf("secret prime factor(q) %s\n", BN_bn2hex(rsa->q));
	printf("---------------------------------------------\n");
	free_rsa(rsa);

	rsa = rsa_bits(RSA_BITS_2048);
	printf("---------------------------------------------\n");
	printf("public modulus(n) %s\n", BN_bn2hex(rsa->n));
	printf("public modulus(10n) %s\n", BN_bn2dec(rsa->n));
	printf("public exponent(e) %s\n", BN_bn2hex(rsa->e));
	printf("private exponent(d) %s\n", BN_bn2hex(rsa->d));
	printf("private exponent(10d) %s\n", BN_bn2dec(rsa->d));
	printf("secret prime factor(p) %s\n", BN_bn2hex(rsa->p));
	printf("secret prime factor(q) %s\n", BN_bn2hex(rsa->q));
	printf("---------------------------------------------\n");
	free_rsa(rsa);
}

void test_rsa_enc_dec_no_pad(){
	char modulus[] = "132786637117497282676450771703683839940848023258985053537474526562964302308143738562590162081795058288941050336872025009605124585724155203413046028979140768272461971411122547197547149397643757558197863704787830128185088608335626908277058094504636145797120939853198167649787677435802763602720937946003723737873";
	
	char exponent[] = "5033672606142824841681910767220646960542049648046767358624338571034140081889537215487967620152884598571614842465575737876889869732493829187776160462716523318447612072800356798660314149045185529963162765145055278227733741831346389826463414287512166355553618982432952098063518138168165264203994145982416737473";
	
	char data[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

	int data_len = strlen(data);
	
	RSA *rsa = NULL;
	rsa = rsa_with_all((const char*)modulus,(const char*)exponent);
	
	unsigned char *pub_enc = NULL;
	int pub_enc_len = rsa_pub_encrypt(rsa,(unsigned char*)data,data_len,&pub_enc,NO_PADDING);
	printf("rsa_pub_enc/pri_dec(NO_PADDING):\n");
	printHex((const unsigned char*)pub_enc,pub_enc_len);
	unsigned char *pri_dec = NULL;
	int pri_dec_len = rsa_pri_decrypt(rsa,(unsigned char*)pub_enc,pub_enc_len,&pri_dec,NO_PADDING);
	printChar((const unsigned char*)pri_dec,pri_dec_len);
	cleanup(pub_enc);
	cleanup(pri_dec);
	
	unsigned char *pri_enc = NULL;
	int pri_enc_len = rsa_pri_encrypt(rsa,(unsigned char*)data,data_len,&pri_enc,NO_PADDING);
	printf("rsa_pri_enc/pub_dec(NO_PADDING):\n");
	printHex((const unsigned char*)pri_enc,pri_enc_len);
	unsigned char *pub_dec = NULL;
	int pub_dec_len = rsa_pub_decrypt(rsa,(unsigned char*)pri_enc,pri_enc_len,&pub_dec,NO_PADDING);
	printChar((const unsigned char*)pub_dec,pub_dec_len);
	cleanup(pri_enc);
	cleanup(pub_dec);
	
	free_rsa(rsa);
	
}

void test_rsa_enc_dec_pkcs1(){

//	char data[] = "ACCCCCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCC";

	char data[] = "当你在客户端选择RSA_NO_PADDING填充模式";

//	char data[] = "Hello World";
	
	int data_len = strlen(data);
	
	RSA *rsa = rsa_bits(RSA_BITS_1024);
	
	unsigned char *pub_enc = NULL;
	int pub_enc_len = rsa_pub_encrypt(rsa,(unsigned char*)data,data_len,&pub_enc,PKCS1_PADDING);
	printf("rsa_pub_enc/pri_dec(PKCS1_PADDING):\n");
	printHex((const unsigned char*)pub_enc,pub_enc_len);
	unsigned char *pri_dec = NULL;
	int pri_dec_len = rsa_pri_decrypt(rsa,(unsigned char*)pub_enc,pub_enc_len,&pri_dec,PKCS1_PADDING);
	printChar((const unsigned char*)pri_dec,pri_dec_len);
	cleanup(pub_enc);
	cleanup(pri_dec);
	
	unsigned char *pri_enc = NULL;
	int pri_enc_len = rsa_pri_encrypt(rsa,(unsigned char*)data,data_len,&pri_enc,PKCS1_PADDING);
	printf("rsa_pri_enc/pub_dec(PKCS1_PADDING):\n");
	printHex((const unsigned char*)pri_enc,pri_enc_len);
	unsigned char *pub_dec = NULL;
	int pub_dec_len = rsa_pub_decrypt(rsa,(unsigned char*)pri_enc,pri_enc_len,&pub_dec,PKCS1_PADDING);
	printChar((const unsigned char*)pub_dec,pub_dec_len);
	cleanup(pri_enc);
	cleanup(pub_dec);
	
	free_rsa(rsa);
	
}

void test_rsa_sign_verify(){
	
	unsigned int len = 0;
	
	RSA *rsa = rsa_bits(RSA_BITS_1024);
	
	unsigned char *sign = NULL;
	unsigned int sign_len = 0;
	int success = 0;
	
	
	char data_md5[] = "ABCDEFGHABCDEFGH";
	len = strlen(data_md5);
	rsa_sign_msg(HASH_ID_MD5,(const unsigned char*)data_md5,len,&sign,&sign_len,rsa);
	printf("rsa_sign_msg(HASH_ID_MD5)%d,%s:\n",sign_len,ERR_error_string(ERR_get_error(), NULL));
	printHex((const unsigned char*)sign,sign_len);
	success = rsa_verify_msg(HASH_ID_MD5,(const unsigned char*)data_md5,len,(const unsigned char*)sign,sign_len,rsa);
	printf("rsa_verify_msg(HASH_ID_MD5) is success:%d\n",success);
	cleanup(sign);
	sign = 0;
	success = 0;
	
	char data_sha1[] = "0123456789ABCDEF1234";
	len = strlen(data_sha1);
	rsa_sign_msg(HASH_ID_SHA1,(const unsigned char*)data_sha1,len,&sign,&sign_len,rsa);
	printf("rsa_sign_msg(HASH_ID_SHA1)%d,%s:\n",sign_len,ERR_error_string(ERR_get_error(), NULL));
	printHex((const unsigned char*)sign,sign_len);
	success = rsa_verify_msg(HASH_ID_SHA1,(const unsigned char*)data_sha1,len,(const unsigned char*)sign,sign_len,rsa);
	printf("rsa_verify_msg(HASH_ID_SHA1) is success:%d\n",success);
	cleanup(sign);
	sign = 0;
	success = 0;

	
	char data_sha224[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZOK";
	len = strlen(data_sha224);
	rsa_sign_msg(HASH_ID_SHA224,(const unsigned char*)data_sha224,len,&sign,&sign_len,rsa);
	printf("rsa_sign_msg(HASH_ID_SHA224)%d,%s:\n",sign_len,ERR_error_string(ERR_get_error(), NULL));
	printHex((const unsigned char*)sign,sign_len);
	success = rsa_verify_msg(HASH_ID_SHA224,(const unsigned char*)data_sha224,len,(const unsigned char*)sign,sign_len,rsa);
	printf("rsa_verify_msg(HASH_ID_SHA224) is success:%d\n",success);
	cleanup(sign);
	sign = 0;
	success = 0;	
	
	char data_sha256[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZOrange";
	len = strlen(data_sha256);
	rsa_sign_msg(HASH_ID_SHA256,(const unsigned char*)data_sha256,len,&sign,&sign_len,rsa);
	printf("rsa_sign_msg(HASH_ID_SHA256)%d,%s:\n",sign_len,ERR_error_string(ERR_get_error(), NULL));
	printHex((const unsigned char*)sign,sign_len);
	success = rsa_verify_msg(HASH_ID_SHA256,(const unsigned char*)data_sha256,len,(const unsigned char*)sign,sign_len,rsa);
	printf("rsa_verify_msg(HASH_ID_SHA256) is success:%d\n",success);
	cleanup(sign);
	sign = 0;
	success = 0;
	
	char data_sha384[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUV";
	len = strlen(data_sha384);
	rsa_sign_msg(HASH_ID_SHA384,(const unsigned char*)data_sha384,len,&sign,&sign_len,rsa);
	printf("rsa_sign_msg(HASH_ID_SHA384)%d,%s:\n",sign_len,ERR_error_string(ERR_get_error(), NULL));
	printHex((const unsigned char*)sign,sign_len);
	success = rsa_verify_msg(HASH_ID_SHA384,(const unsigned char*)data_sha384,len,(const unsigned char*)sign,sign_len,rsa);
	printf("rsa_verify_msg(HASH_ID_SHA384) is success:%d\n",success);
	cleanup(sign);
	sign = 0;
	success = 0;
	
	
	char data_sha512[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKL";
	len = strlen(data_sha512);
	rsa_sign_msg(HASH_ID_SHA512,(const unsigned char*)data_sha512,len,&sign,&sign_len,rsa);
	printf("rsa_sign_msg(HASH_ID_SHA512)%d,%s:\n",sign_len,ERR_error_string(ERR_get_error(), NULL));
	printHex((const unsigned char*)sign,sign_len);
	success = rsa_verify_msg(HASH_ID_SHA512,(const unsigned char*)data_sha512,len,(const unsigned char*)sign,sign_len,rsa);
	printf("rsa_verify_msg(HASH_ID_SHA512) is success:%d\n",success);
	cleanup(sign);
	sign = 0;
	success = 0;
	

	
	char data_md5_sha1[] = "ABCDEFGHABCDEFGH0123456789ABCDEF1234";
	len = strlen(data_md5_sha1);
	rsa_sign_msg(HASH_ID_MD5_SHA1,(const unsigned char*)data_md5_sha1,len,&sign,&sign_len,rsa);
	printf("rsa_sign_msg(HASH_ID_MD5_SHA1)%d,%s:\n",sign_len,ERR_error_string(ERR_get_error(), NULL));
	printHex((const unsigned char*)sign,sign_len);
	success = rsa_verify_msg(HASH_ID_MD5_SHA1,(const unsigned char*)data_md5_sha1,len,(const unsigned char*)sign,sign_len,rsa);
	printf("rsa_verify_msg(HASH_ID_MD5_SHA1) is success:%d\n",success);
	cleanup(sign);
	sign = 0;
	success = 0;
	
	
	free_rsa(rsa);
	
}


int main(int argc,char *argv[]){
//	test_hex();	
//	test_sha();
//	test_md();
//	test_hmac();
//	test_aes_128();
//	test_aes_128_iv();
	
//	test_aes_192();
//	test_aes_192_iv();
	
//	test_aes_256();
//	test_aes_256_iv();
	
//	test_des();
//	test_des_iv();
	
//	test_rsa_gen();
//	test_rsa_enc_dec_no_pad();
//	test_rsa_enc_dec_pkcs1();
	test_rsa_sign_verify();
	return 0;

}
