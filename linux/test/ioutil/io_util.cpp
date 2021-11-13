#include <stdio.h>
#include "io_util.h"

int printHex(unsigned const char* data,int len){
   for (int i = 0 ; i < len ;i++){
   	printf("%X",data[i]);
   }
   printf("\n");
   return 0;
}
