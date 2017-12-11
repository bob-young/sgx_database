#ifndef IPP_AES_H_
#define IPP_AES_H_


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ippcp.h"

#define errlist_len 15


	IppStatus init(unsigned char* pwd,int pwdlen,unsigned char* piv,int pivlen);
	IppStatus encrypt(unsigned char* src,unsigned char* dest,int length);
	IppStatus decrypt(unsigned char* src,unsigned char* dest,int length);
	IppStatus reset();

#endif
