#include <stdio.h>
#include <io_util.h>
#include <cstring>
#include <openssl/sha.h>

int ssl_sha1(const char* data,const int length,const int out_size){
    	uint8_t out[out_size];
    	
	SHA_CTX sha;
    	SHA1_Init(&sha);
    	SHA1_Update(&sha,data,length);
    	SHA1_Final(out,&sha);
    	
	printf("hello world sha1:\n");
    	printHex((const unsigned char*)out,out_size);

    	uint8_t easyout[out_size];
    	
	SHA1((const uint8_t*)data,length,easyout);
    	
	printf("hello world sha1(easy):\n");
    	printHex((const unsigned char*)easyout,out_size);

    	return 0;
}
 
int ssl_sha224(const char* data,const int length,const int out_size){
    	uint8_t out[out_size];
    	
	SHA256_CTX sha;
    	SHA224_Init(&sha);
    	SHA224_Update(&sha,data,length);
    	SHA224_Final(out,&sha);
    	
	printf("hello world sha224:\n");
    	printHex((const unsigned char*)out,out_size);

    	uint8_t easyout[out_size];
    	
	SHA224((const uint8_t*)data,length,easyout);
    	
	printf("hello world sha224(easy):\n");
    	printHex((const unsigned char*)easyout,out_size);

    	return 0;
}

int ssl_sha256(const char* data,const int length,const int out_size){
    	uint8_t out[out_size];
    	
	SHA256_CTX sha;
    	SHA256_Init(&sha);
    	SHA256_Update(&sha,data,length);
    	SHA256_Final(out,&sha);
    	
	printf("hello world sha256:\n");
    	printHex((const unsigned char*)out,out_size);

    	uint8_t easyout[out_size];
    	
	SHA256((const uint8_t*)data,length,easyout);
    	
	printf("hello world sha256(easy):\n");
    	printHex((const unsigned char*)easyout,out_size);

    	return 0;
}


int ssl_sha384(const char* data,const int length,const int out_size){
    	uint8_t out[out_size];
    	
	SHA512_CTX sha;
    	SHA384_Init(&sha);
    	SHA384_Update(&sha,data,length);
    	SHA384_Final(out,&sha);
    	
	printf("hello world sha384:\n");
    	printHex((const unsigned char*)out,out_size);

    	uint8_t easyout[out_size];
    	
	SHA384((const uint8_t*)data,length,easyout);
    	
	printf("hello world sha384(easy):\n");
    	printHex((const unsigned char*)easyout,out_size);

    	return 0;
}


int ssl_sha512(const char* data,const int length,const int out_size){
    	uint8_t out[out_size];
    	
	SHA512_CTX sha;
    	SHA512_Init(&sha);
    	SHA512_Update(&sha,data,length);
    	SHA512_Final(out,&sha);
    	
	printf("hello world sha512:\n");
    	printHex((const unsigned char*)out,out_size);

    	uint8_t easyout[out_size];
    	
	SHA512((const uint8_t*)data,length,easyout);
    	
	printf("hello world sha512(easy):\n");
    	printHex((const unsigned char*)easyout,out_size);

    	return 0;
}


int ssl_sha512_256(const char* data,const int length,const int out_size){
    	uint8_t out[out_size];
    	
	SHA512_CTX sha;
    	SHA512_256_Init(&sha);
    	SHA512_256_Update(&sha,data,length);
    	SHA512_256_Final(out,&sha);
    	
	printf("hello world sha512_256:\n");
    	printHex((const unsigned char*)out,out_size);

    	uint8_t easyout[out_size];
    	
	SHA512_256((const uint8_t*)data,length,easyout);
    	
	printf("hello world sha512_256(easy):\n");
    	printHex((const unsigned char*)easyout,out_size);

    	return 0;
}

int main(int argc,char* argv[]){
       	char data[] = "hello world";
        int length = strlen(data);
	ssl_sha1((const char*)data,length,SHA_DIGEST_LENGTH);
	ssl_sha224((const char*)data,length,SHA224_DIGEST_LENGTH);
	ssl_sha256((const char*)data,length,SHA256_DIGEST_LENGTH);
	ssl_sha384((const char*)data,length,SHA384_DIGEST_LENGTH);
	ssl_sha512((const char*)data,length,SHA512_DIGEST_LENGTH);
	ssl_sha512_256((const char*)data,length,SHA512_256_DIGEST_LENGTH);
	return 0;
}
