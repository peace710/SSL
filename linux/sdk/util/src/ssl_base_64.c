#include <string.h>
#include <stdlib.h>
#include <ssl_base_64.h>

int base64_encode(const char *in,unsigned char **out){
	int ret = 0;
	if (in){
		int len = strlen(in);
		size_t size = 0;
		if (EVP_EncodedLength(&size,len)){
			*out = (unsigned char*)malloc(size + 1);
			if (*out){
				memset(*out,0x00,size + 1);
				ret = EVP_EncodeBlock(*out,(const unsigned char*)in,len);
			}		
		}
	}
	return ret;
}

int base64_decode(const char *in,unsigned char **out){
	int ret = 0;
	if (in){
		int len = strlen(in);
		size_t size = 0;
		if (EVP_DecodedLength(&size,len)){
			*out = (unsigned char*)malloc(size + 1);
			if (*out){
				memset(*out,0x00,size + 1);
				ret = EVP_DecodeBlock(*out,in,len);
			}
		}
	}
	return ret;	
}

