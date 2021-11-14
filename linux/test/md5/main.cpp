#include <stdio.h>
#include <openssl/md5.h>
#include <cstring>
#include <io_util.h>

int main(int argc,char* argv[]){
	char data[]="hello world";
   	uint8_t out[MD5_DIGEST_LENGTH];
    
    	MD5_CTX md5;
    	MD5_Init(&md5);
    	MD5_Update(&md5,data,strlen(data));
    	MD5_Final(out,&md5);  
    	printf("hello world md5:\n");
    	printHex((const unsigned char*)out,MD5_DIGEST_LENGTH);
    
    	uint8_t easyout[MD5_DIGEST_LENGTH];
    	MD5((const uint8_t*)data,strlen(data),easyout);
    	printf("hello world md5(easy):\n");
    	printHex((const unsigned char*)easyout,MD5_DIGEST_LENGTH);

    	return 0;
}
