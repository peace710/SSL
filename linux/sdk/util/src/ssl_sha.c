#include <string.h>
#include <ssl_sha.h>

int sha1(const char *in,unsigned char **out){
	int ret = 0;
	*out = (char*)malloc(SHA_DIGEST_LENGTH + 1);
	if (*out){
		memset(*out,0x00,SHA_DIGEST_LENGTH + 1);
		SHA_CTX c;
		if (SHA1_Init(&c)){
			SHA1_Update(&c,in,strlen(in));
			SHA1_Final(*out,&c);
			OPENSSL_cleanse(&c,sizeof(c));
			ret = SHA_DIGEST_LENGTH;
		}
	}
	return ret;
}

int sha224(const char *in,unsigned char **out){
	int ret = 0;
	*out = (char*)malloc(SHA224_DIGEST_LENGTH + 1);
	if (*out){
		memset(*out,0x00,SHA224_DIGEST_LENGTH + 1);
		SHA256_CTX c;
		if (SHA224_Init(&c)){
			SHA224_Update(&c,in,strlen(in));
			SHA224_Final(*out,&c);
			OPENSSL_cleanse(&c,sizeof(c));
			ret = SHA224_DIGEST_LENGTH;
		}
	}
	return ret;
}

int sha256(const char *in,unsigned char **out){
	int ret = 0;
	*out = (char*)malloc(SHA256_DIGEST_LENGTH + 1);
	if (*out){
		memset(*out,0x00,SHA256_DIGEST_LENGTH + 1);
		SHA256_CTX c;
		if (SHA256_Init(&c)){
			SHA256_Update(&c,in,strlen(in));
			SHA256_Final(*out,&c);
			OPENSSL_cleanse(&c,sizeof(c));
			ret = SHA256_DIGEST_LENGTH;
		}
	}
	return ret;
}

int sha384(const char *in,unsigned char **out){
	int ret = 0;
	*out = (char*)malloc(SHA384_DIGEST_LENGTH + 1);
	if (*out){
		memset(*out,0x00,SHA384_DIGEST_LENGTH + 1);
		SHA512_CTX c;
		if (SHA384_Init(&c)){
			SHA384_Update(&c,in,strlen(in));
			SHA384_Final(*out,&c);
			OPENSSL_cleanse(&c,sizeof(c));
			ret = SHA384_DIGEST_LENGTH;
		}
	}
	return ret;
}

int sha512(const char *in,unsigned char **out){
	int ret = 0;
	*out = (char*)malloc(SHA512_DIGEST_LENGTH + 1);
	if (*out){
		memset(*out,0x00,SHA512_DIGEST_LENGTH + 1);
		SHA512_CTX c;
		if (SHA512_Init(&c)){
			SHA512_Update(&c,in,strlen(in));
			SHA512_Final(*out,&c);
			OPENSSL_cleanse(&c,sizeof(c));
			ret = SHA512_DIGEST_LENGTH;
		}
	}
	return ret;
}

int sha512_256(const char *in,unsigned char **out){
	int ret = 0;
	*out = (char*)malloc(SHA512_256_DIGEST_LENGTH + 1);
	if (*out){
		memset(*out,0x00,SHA512_256_DIGEST_LENGTH + 1);
		SHA512_CTX c;
		if (SHA512_256_Init(&c)){
			SHA512_256_Update(&c,in,strlen(in));
			SHA512_256_Final(*out,&c);
			OPENSSL_cleanse(&c,sizeof(c));
			ret = SHA512_256_DIGEST_LENGTH;
		}
	}
	return ret;
}

int sha(const char *in,unsigned char **out,int mode){
	switch (mode){
		case SHA_1:
			return sha1(in,out);
		case SHA_224:
			return sha224(in,out);
		case SHA_256:
			return sha256(in,out);
		case SHA_384:
			return sha384(in,out);
		case SHA_512:
			return sha512(in,out);
		case SHA_512_256:
			return sha512_256(in,out);
	}
	return 0;
}
