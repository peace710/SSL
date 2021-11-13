#include <stdio.h>
#include <openssl/md4.h>
#include <cstring>
#include <io_util.h>

int main(int argc,char* argv[]){
	char data[]="hello world";
   	uint8_t out[MD4_DIGEST_LENGTH];
    
    	MD4_CTX md4;
    	MD4_Init(&md4);
    	MD4_Update(&md4,data,strlen(data));
    	MD4_Final(out,&md4);  
    	printf("hello world md4:\n");
    	printHex((unsigned const char*)out,MD4_DIGEST_LENGTH);
    
    	uint8_t easyout[MD4_DIGEST_LENGTH];
    	MD4((const uint8_t*)data,strlen(data),easyout);
    	printf("hello world md4(easy):\n");
    	printHex((unsigned const char*)easyout,MD4_DIGEST_LENGTH);

    	return 0;
}
