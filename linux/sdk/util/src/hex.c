#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hex.h>

int hex_encode(const unsigned char *in ,int len ,char **out){
	int size = len * 2 + 1;
	*out = (char*)malloc(size);
	int i = 0;
	if (*out){
		memset(*out,0x00,size);
		char *temp = *out;
		for (i = 0 ; i < len;i++){
			sprintf(temp,"%02X",in[i]);
			temp += 2;	
		}			
	}
	return i * 2;
}

int hex_decode(const unsigned char *in ,const int len, unsigned char **out){
	int size = len / 2;
	*out = (char*)malloc(size + 1);
	int i = 0;
	if (*out){
		memset(*out,0x00,size + 1);
		for (i = 0 ; i < size;i++){
			unsigned int n;
			sscanf((in + i * 2),"%2X",&n);
			(*out)[i] = (unsigned char)n;
		}		
	}
	return i;
}
