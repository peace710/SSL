#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hex.h>
#include <ssl_sha.h>
#include <ssl_md.h>

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

int main(int argc,char *argv[]){
	test_hex();	
	test_sha();
	test_md();
	return 0;	

}
