#ifndef IPP_AES_H_
#define IPP_AES_H_


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ippcp.h"

#define errlist_len 15


	IppStatus ipp_init(const unsigned char* pwd,int pwdlen,unsigned char* piv,int pivlen);
	IppStatus ipp_encrypt(const unsigned char* src,unsigned char* dest,int length);
	IppStatus ipp_decrypt(const unsigned char* src,unsigned char* dest,int length);
	IppStatus ipp_reset();
	void ipp_free();
	
#endif
