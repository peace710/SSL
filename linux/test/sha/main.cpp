#include <stdio.h>
#include <io_util.h>
#include <cstring>
#include <openssl/sha.h>

int main(int argc,char* argv[]){
    char data[] = "hello world";
    uint8_t out[SHA_DIGEST_LENGTH];

    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1,data,strlen(data));
    SHA1_Final(out,&sha1);
    printf("hello world sha1:\n");
    printHex((unsigned const char*)out,SHA_DIGEST_LENGTH);

    uint8_t easyout[SHA_DIGEST_LENGTH];
    SHA1((const uint8_t*)data,strlen(data),easyout);
    printf("hello world sha1(easy):\n");
    printHex((unsigned const char*)easyout,SHA_DIGEST_LENGTH);

    return 0;
}
