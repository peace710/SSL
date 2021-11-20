#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hex.h>

int main(int argc,char *argv[]){
	char p[] = "Desktop of War -> Call of Duty";

	int len = strlen((const char*)p);
	
	char *hex_out = NULL;
	int hex_len = hex_encode((const unsigned char*)p,len,&hex_out);

	char *out = NULL;
	int out_len = hex_decode((const unsigned char*)hex_out,(const int)hex_len,(unsigned char**)&out);


	for (int i = 0 ; i < out_len ;i++){
		printf("%c",out[i]);
	}

	printf("\n");

	if (hex_out != NULL){
		free(hex_out);
		hex_out = NULL;
	}
	
	if (out != NULL){
		free(out);
		out = NULL;
	}
	return 0;	

}
