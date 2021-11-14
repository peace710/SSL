#include <stdio.h>
#include "io_util.h"

int printHex(const unsigned char* data,int len){
	for (int i = 0 ; i < len ;i++){
		printf("%X",data[i]);
   	}
   	printf("\n");
   	return 0;
}


int printChar(const unsigned char* data,int len){
	for (int i = 0 ; i < len ;i++){
		printf("%c",data[i]);
   	}
   	printf("\n");
   	return 0;
}
