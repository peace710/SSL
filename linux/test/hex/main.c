#include <stdio.h>
#include <stdlib.h>
#include <io_util.h>
#include <string.h>

int hex_encode(const char *data,const int len,char **out){
	int size = len * 2 + 1;
	*out = (char*)malloc(size);
	int i = 0;
	if (*out){
		memset(*out,0x00,size);
		char* temp = *out;
		for (i = 0 ; i < len ;i++){
			sprintf(temp,"%02X",data[i]);
			temp += 2;
		}
	}
	return 2 * i;
}

int hex_decode(const char *data,const int len,char **out){
	int size = len / 2;
	*out = (char*)malloc(size + 1);
	int i = 0;
	if (*out){
		memset(*out,0x00,size + 1);
		for (i = 0 ; i < size ;i++){
			unsigned int n;
			sscanf((data + i * 2),"%2X",&n);
			(*out)[i] = (unsigned char)n;
		}
	}
	return i;
}


int main(int argc,char *argv[]){

//	char data[] = "Linux Ubuntu Android Windows 11 MacOS Kotlin C# F# shell";
	char data[] = "Visual Studio Code Notepad++ Android Studio Chrome Thunder";
	
	int data_len = strlen((const char*)data);
	printf("hex_encode %d\n",data_len);
	char *hex = NULL;
	int hex_len = hex_encode((const char*)data,data_len,&hex);
	printChar((unsigned char*)hex,hex_len);

	printf("hex_decode %d\n",hex_len);
	char *out = NULL;
	int out_len = hex_decode((const char*)hex,hex_len,&out);
	printChar((unsigned char*)out,out_len);


	if (hex != NULL){
		free(hex);
		hex = NULL;
	}

	if (out != NULL){
		free(out);
		out = NULL;
	}


	return 0;
}
