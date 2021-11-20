#ifndef __HEX_H__
#define __HEX_H__

#ifndef NULL
#define NULL 0
#endif

int hex_encode(const unsigned char *in,int len,char **out);

int hex_decode(const unsigned char *in,int len,unsigned char **out);

#endif
