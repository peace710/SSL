#include <string.h>
#include <ssl_md.h>

int md4(const char *in,unsigned char **out){
	int ret = 0;
	*out = (char*)malloc(MD4_DIGEST_LENGTH + 1);
	if (*out){
		memset(*out,0x00,MD4_DIGEST_LENGTH + 1);
		MD4_CTX c;
		if (MD4_Init(&c)){
			MD4_Update(&c,in,strlen(in));
			MD4_Final(*out,&c);
			OPENSSL_cleanse(&c,sizeof(c));
			ret = MD4_DIGEST_LENGTH;
		}
	}
	return ret;
}

int md5(const char *in,unsigned char **out){
	int ret = 0;
	*out = (char*)malloc(MD5_DIGEST_LENGTH + 1);
	if (*out){
		memset(*out,0x00,MD5_DIGEST_LENGTH + 1);
		MD5_CTX c;
		if (MD5_Init(&c)){
			MD5_Update(&c,in,strlen(in));
			MD5_Final(*out,&c);
			OPENSSL_cleanse(&c,sizeof(c));
			ret = MD5_DIGEST_LENGTH;
		}
	}
	return ret;
}

int md(const char *in,unsigned char **out,int mode){
	switch (mode){
		case MD_4:
			return md4(in,out);
		case MD_5:
			return md5(in,out);
	}
	return 0;
}
