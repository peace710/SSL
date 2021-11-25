#include <string.h>
#include <stdlib.h>
#include <ssl_rsa.h>

RSA *rsa_bits(int bits){
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();

	if (rsa == NULL || e == NULL || !BN_set_word(e,RSA_F4) || !RSA_generate_key_ex(rsa,bits,e,NULL)){
		goto err;
	}
	BN_free(e);
	return rsa;

err:
	BN_free(e);
	RSA_free(rsa);
	return NULL;
}

RSA *rsa_with_modulus(const char *modulus){
	RSA *rsa = RSA_new();
	if (rsa == NULL || !BN_dec2bn(&rsa->n,modulus) || !BN_dec2bn(&rsa->e,PUB_EXPONENT)){
		goto err;
	}
	return rsa;
err:
	RSA_free(rsa);
	return NULL;
}

int get_rsa_padding(int padding){
	switch(padding){
		case PKCS1_PADDING:
			return RSA_PKCS1_PADDING;
		case NO_PADDING:
			return RSA_NO_PADDING;
		default:
			return ERROR;
	}
}

RSA *rsa_with_all(const char *modulus,const char *exponent){
	RSA *rsa = RSA_new();
	if (rsa == NULL || !BN_dec2bn(&rsa->n,modulus) || !BN_dec2bn(&rsa->e,PUB_EXPONENT) || !BN_dec2bn(&rsa->d,exponent)){
		goto err;
	}
	return rsa;
err:
	RSA_free(rsa);
	return NULL;
}

int rsa_pub_encrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding){
	int ret = 0;
	int pad = get_rsa_padding(padding);
	if (pad == ERROR){
		return ret;
	}
	if (rsa){
		int size = RSA_size(rsa);
		*out = (unsigned char*)malloc(size + 1);
		if (*out){
			memset(*out,0x00,size + 1);
			ret = RSA_public_encrypt(data_len,in,*out,rsa,pad);
		}
	}
	return ret;
}

int rsa_pri_encrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding){
	int ret = 0;
	int pad = get_rsa_padding(padding);
	if (pad == ERROR){
		return ret;
	}
	if (rsa){
		int size = RSA_size(rsa);
		*out = (unsigned char*)malloc(size + 1);
		if (*out){
			memset(*out,0x00,size + 1);
			ret = RSA_private_encrypt(data_len,in,*out,rsa,pad);
		}
	}
	return ret;
}

int rsa_pub_decrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding){
	int ret = 0;
	int pad = get_rsa_padding(padding);
	if (pad == ERROR){
		return ret;
	}
	if (rsa){
		int size = RSA_size(rsa);
		*out = (unsigned char*)malloc(size + 1);
		if (*out){
			memset(*out,0x00,size + 1);
			ret = RSA_public_decrypt(data_len,in,*out,rsa,pad);
		}
	}
	return ret;
}

int rsa_pri_decrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding){
	int ret = 0;
	int pad = get_rsa_padding(padding);
	if (pad == ERROR){
		return ret;
	}
	if (rsa){
		int size = RSA_size(rsa);
		*out = (unsigned char*)malloc(size + 1);
		if (*out){
			memset(*out,0x00,size + 1);
			ret = RSA_private_decrypt(data_len,in,*out,rsa,pad);
		}
	}
	return ret;
}

void free_rsa(RSA *rsa){
	if (rsa){
		RSA_free(rsa);
		rsa = NULL;
	}
}



