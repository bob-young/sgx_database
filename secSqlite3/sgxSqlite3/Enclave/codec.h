/*
///////////////////////////////////////////////////////////////////////////////
// Name:        codec.h
// Purpose:     
// Author:      Ulrich Telle
// Modified by:
// Created:     2006-12-06
// Copyright:   (c) Ulrich Telle
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

/// \file codec.h Interface of the codec class
*/
#include <time.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include "hashmap/hashmap.h"

#ifndef _CODEC_H_
#define _CODEC_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__BORLANDC__)
#define __STDC__ 1
#endif

#if defined(__BORLANDC__)
#undef __STDC__
#endif

/*
// ATTENTION: Macro similar to that in pager.c
// TODO: Check in case of new version of SQLite
*/
#define WX_PAGER_MJ_PGNO(x) ((PENDING_BYTE/(x))+1)

#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif

//#include "rijndael.h"
#define KEYLENGTH 16
#define GCM_IV_LEN 12

#define _MAX_KEY_COLUMNS (256/32)
#define _MAX_ROUNDS      14
#define MAX_IV_SIZE      16
  

/* We assume that unsigned int is 32 bits long....  */
typedef unsigned char  UINT8;
typedef unsigned int   UINT32;
typedef unsigned short UINT16;
#define sgx_Encrypt 0
#define sgx_Decrypt 1

/*typedef struct{
    time_t tv_sec;
    syscall_slong_t tv_nsec;
}timespec;*/

unsigned char iv[MAX_IV_SIZE]; //16?

typedef struct _Codec
{
  int           m_isEncrypted;
  int           m_hasReadKey;
  unsigned char m_readKey[KEYLENGTH];
  int           m_hasWriteKey;
  unsigned char m_writeKey[KEYLENGTH];
  unsigned char m_tag[16];

  //Rijndael*     m_aes;

  Btree*        m_bt; /* Pointer to B-tree used by DB */
  unsigned char m_page[SQLITE_MAX_PAGE_SIZE+24];
} Codec;


void CodecInit(Codec* codec);
void CodecTerm(Codec* codec);

void CodecCopy(Codec* codec, Codec* other);

void CodecGenerateReadKey(Codec* codec, char* userPassword, int passwordLength);

void CodecGenerateWriteKey(Codec* codec, char* userPassword, int passwordLength);

#if CODEC_TYPE == CODEC_TYPE_GCM128
void CodecEncrypt(Codec* codec, int page, unsigned char* data, int len, int useWriteKey, hashmap *tag);
#else
void CodecEncrypt(Codec* codec, int page, unsigned char* data, int len, int useWriteKey);
#endif
#if CODEC_TYPE == CODEC_TYPE_GCM128
void CodecDecrypt(Codec* codec, int page, unsigned char* data, int len, hashmap *tag);
#else
void CodecDecrypt(Codec* codec, int page, unsigned char* data, int len);
#endif

void CodecCopyKey(Codec* codec, int read2write);

void CodecSetIsEncrypted(Codec* codec, int isEncrypted);
void CodecSetHasReadKey(Codec* codec, int hasReadKey);
void CodecSetHasWriteKey(Codec* codec, int hasWriteKey);
void CodecSetBtree(Codec* codec, Btree* bt);

int CodecIsEncrypted(Codec* codec);
int CodecHasReadKey(Codec* codec);
int CodecHasWriteKey(Codec* codec);
Btree* CodecGetBtree(Codec* codec);
unsigned char* CodecGetPageBuffer(Codec* codec);

void CodecGenerateEncryptionKey(Codec* codec, char* userPassword, int passwordLength, 
                                unsigned char encryptionKey[KEYLENGTH]);

void CodecPadPassword(Codec* codec, char* password, int pswdlen, unsigned char pswd[32]);

void CodecRC4(Codec* codec, unsigned char* key, int keylen,
              unsigned char* textin, int textlen,
         unsigned char* textout);

void CodecGetMD5Binary(Codec* codec, unsigned char* data, int length, unsigned char* digest);
void CodecWriteTag(Codec*  codec, unsigned char * inTag, int nTaglen);
void CodecGetTag(Codec*  codec, unsigned char * outTag, int nTaglen);
  
void CodecGenerateInitialVector(Codec* codec, int seed, unsigned char iv[16]);

void CodecAES(Codec* codec, int page, int encrypt_type, int encrypt, const unsigned char encryptionKey[KEYLENGTH],
              unsigned char* datain, int datalen, unsigned char* dataout, unsigned char* p_mac);

#endif
