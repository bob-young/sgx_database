/*
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Name:        codec.cpp
// Purpose:     
// Author:      Ulrich Telle
// Modified by:
// Created:     2006-12-06
// RCS-ID:      $$
// Copyright:   (c) Ulrich Telle
// Licence:     wxWindows licence + RSA Data Security license
///////////////////////////////////////////////////////////////////////////////

/// \file codec.cpp Implementation of MD5, RC4 and AES algorithms
*/
/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

#include "codec.h"
#include "user_types.h"

#if CODEC_TYPE == CODEC_TYPE_GCM128
hashmap *tag;
//int counter;
#endif

/*#if CODEC_TYPE == CODEC_TYPE_AES256
#include "sha2.h"
#include "sha2.c"
#endif*/

/*
// ----------------
// MD5 by RSA
// ----------------

// C headers for MD5
*/
//#include <sys/types.h>
#include <string.h>
//#include <stdio.h>
//#include <stdlib.h>
#include "vfslib/stdio.h"
#include "vfslib/stdlib.h"

#ifndef SQLITE_FILE_HEADER /* 123456789 123456 */
#  define SQLITE_FILE_HEADER "SQLite format 3"
#endif
/*
/// Structure representing an MD5 context while ecrypting. (For internal use only)
*/
 
 void
CodecAES(Codec* codec, int page, int encrypt_type, int encrypt, const unsigned char encryptionKey[KEYLENGTH],
         unsigned char* datain, int datalen, unsigned char* dataout, unsigned char* p_mac)
{
  uint8_t ctr_initial[MAX_IV_SIZE];
  uint8_t gcm_initial[GCM_IV_LEN];
  memset(ctr_initial,0,MAX_IV_SIZE);
  memset(gcm_initial,0,GCM_IV_LEN);
  const uint8_t *p_src = (const uint8_t *)datain;
  const uint32_t src_len = datalen;
  uint8_t *p_dsts = (uint8_t *)dataout;
  const uint32_t ctr_inc_bits = 128;
  int keyLength = KEYLENGTH;

  uint8_t *sgx_keys = (uint8_t *)malloc(KEYLENGTH);
  memcpy(sgx_keys,encryptionKey,16);

  sgx_aes_gcm_128bit_tag_t *p_out_mac = (sgx_aes_gcm_128bit_tag_t *)malloc(sizeof(sgx_aes_gcm_128bit_tag_t));
  memset(p_out_mac,0,sizeof(sgx_aes_gcm_128bit_tag_t));
  sgx_aes_gcm_128bit_tag_t *p_in_mac = (sgx_aes_gcm_128bit_tag_t *)malloc(sizeof(sgx_aes_gcm_128bit_tag_t));
  memset(p_in_mac,0,sizeof(sgx_aes_gcm_128bit_tag_t));

  sgx_status_t rc;
  char *zErrMsg = 0;
  
  if (encrypt_type==1){
    if (encrypt)
    {     
        rc =sgx_aes_ctr_encrypt((const sgx_aes_ctr_128bit_key_t *)sgx_keys, p_src, src_len, ctr_initial, ctr_inc_bits, p_dsts);    
        if( rc!=SGX_SUCCESS ){
          fprintf(stderr,"ctr_enc error: %d\n", rc);
        }
    }
    else
    {
        rc = sgx_aes_ctr_decrypt((const sgx_aes_gcm_128bit_key_t *)sgx_keys, p_src, src_len, ctr_initial, ctr_inc_bits, p_dsts);
        if( rc!=SGX_SUCCESS ){
          fprintf(stderr,"ctr_dec error: %d\n", rc);
        }
    }
  }
  else{
    if (encrypt)
    {
      rc = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *)sgx_keys,p_src,src_len,p_dsts,gcm_initial, GCM_IV_LEN, NULL, 0, p_out_mac);
      memcpy(p_mac, (unsigned char *)p_out_mac, sizeof(sgx_aes_gcm_128bit_tag_t));
      if( rc!=SGX_SUCCESS ){
        fprintf(stderr,"gcm_enc error: %d\n", rc);;
      }
    }
    else
    {
      memcpy(p_in_mac, (const sgx_aes_gcm_128bit_tag_t *)p_mac, sizeof(sgx_aes_gcm_128bit_tag_t));
      rc = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *)sgx_keys, p_src,src_len,p_dsts,gcm_initial, GCM_IV_LEN, NULL, 0, (const sgx_aes_gcm_128bit_tag_t *) p_in_mac);
      if( rc!=SGX_SUCCESS ){
      fprintf(stderr,"gcm_dec error: %d\n", rc);
      }
    }
  }
  free(sgx_keys);
  free(p_out_mac);
  free(p_in_mac);
  /* It is a good idea to check the error code */
  //if (len < 0)
  //{
    /* AES: Error on encrypting. */
  //}
}
void
CodecInit(Codec* codec)
{
  codec->m_isEncrypted = 0;
  codec->m_hasReadKey  = 0;
  codec->m_hasWriteKey = 0;
}

void
CodecSetIsEncrypted(Codec* codec, int isEncrypted)
{
  codec->m_isEncrypted = isEncrypted;
}

void
CodecSetHasReadKey(Codec* codec, int hasReadKey)
{
  codec->m_hasReadKey = hasReadKey;
}

void
CodecSetHasWriteKey(Codec* codec, int hasWriteKey)
{
  codec->m_hasWriteKey = hasWriteKey;
}

void
CodecSetBtree(Codec* codec, Btree* bt)
{
  codec->m_bt = bt;
}

int
CodecIsEncrypted(Codec* codec)
{
  return codec->m_isEncrypted;
}

int
CodecHasReadKey(Codec* codec)
{
  return codec->m_hasReadKey;
}

int
CodecHasWriteKey(Codec* codec)
{
  return codec->m_hasWriteKey;
}

Btree*
CodecGetBtree(Codec* codec)
{
  return codec->m_bt;
}

void
CodecWriteTag(Codec*  codec, unsigned char * inTag, int nTaglen){
  memcpy(codec->m_tag, inTag, nTaglen);
}
void
CodecGetTag(Codec*  codec, unsigned char * outTag, int nTaglen){
  memcpy(outTag, codec->m_tag, nTaglen);
}

unsigned char*
CodecGetPageBuffer(Codec* codec)
{
  return &codec->m_page[4];
}

void
CodecCopy(Codec* codec, Codec* other)
{
  int j;
  codec->m_isEncrypted = other->m_isEncrypted;
  codec->m_hasReadKey  = other->m_hasReadKey;
  codec->m_hasWriteKey = other->m_hasWriteKey;
  for (j = 0; j < KEYLENGTH; j++)
  {
    codec->m_readKey[j]  = other->m_readKey[j];
    codec->m_writeKey[j] = other->m_writeKey[j];
  }
  for (j = 0; j < 16; j++)
  {
    codec->m_tag[j]  = other->m_tag[j];
  }
  codec->m_bt = other->m_bt;
  //RijndaelInvalidate(codec->m_aes);
}

void
CodecCopyKey(Codec* codec, int read2write)
{
  int j;
  if (read2write)
  {
    for (j = 0; j < KEYLENGTH; j++)
    {
      codec->m_writeKey[j] = codec->m_readKey[j];
    }
  }
  else
  {
    for (j = 0; j < KEYLENGTH; j++)
    {
      codec->m_readKey[j] = codec->m_writeKey[j];
    }
  }
}


void
CodecGenerateReadKey(Codec* codec, char* userPassword, int passwordLength)
{
  CodecGenerateEncryptionKey(codec, userPassword, passwordLength, codec->m_readKey);
}

void
CodecGenerateWriteKey(Codec* codec, char* userPassword, int passwordLength)
{
  CodecGenerateEncryptionKey(codec, userPassword, passwordLength, codec->m_writeKey);
}

void
CodecGenerateEncryptionKey(Codec* codec, char* userPassword, int passwordLength, 
                           unsigned char encryptionKey[KEYLENGTH])
{
  memcpy(encryptionKey, userPassword, KEYLENGTH); 
}
#if CODEC_TYPE == CODEC_TYPE_GCM128
void CodecEncrypt(Codec* codec, int page, unsigned char* data, int len, int useWriteKey, hashmap *tag)
{
  unsigned char dbHeader[8];
  int offset = 0;
  unsigned char* key = (useWriteKey) ? codec->m_writeKey : codec->m_readKey;
  int i;
  unsigned char p_mac[16];
  memset(p_mac, 0, 16);
  unsigned char p_in_hash[32];
  memset(p_in_hash, 0, 32);
  unsigned char p_hash[32];
  memset(p_hash, 0, 32);
  if (page == 1)
  {
    memcpy(dbHeader, data+16, 8);
    offset = 16;
    CodecAES(codec,page, CODEC_TYPE, 1, key, data, 16, data, p_mac);

    int pageHeader = page-1; 
    hm_set(tag, &pageHeader, p_mac);
  }
  CodecAES(codec, page, CODEC_TYPE, 1, key, data+offset, len-offset, data+offset, p_mac);

  hm_set(tag, &page, p_mac);
  if (page == 1)
  {
    memcpy(data+8,  data+16,  8);
    memcpy(data+16, dbHeader, 8);
  }
}
#else
void CodecEncrypt(Codec* codec, int page, unsigned char* data, int len, int useWriteKey)
{
  unsigned char dbHeader[8];
  int offset = 0;
  unsigned char* key = (useWriteKey) ? codec->m_writeKey : codec->m_readKey;
  int i;
  unsigned char p_mac[16];
  memset(p_mac, 0, 16);
  unsigned char p_in_hash[32];
  memset(p_in_hash, 0, 32);
  unsigned char p_hash[32];
  memset(p_hash, 0, 32);
  if (page == 1)
  {
    memcpy(dbHeader, data+16, 8);
    offset = 16;
    CodecAES(codec,page, CODEC_TYPE, 1, key, data, 16, data, p_mac);
  }
  CodecAES(codec, page, CODEC_TYPE, 1, key, data+offset, len-offset, data+offset, p_mac);
  if (page == 1)
  {
    memcpy(data+8,  data+16,  8);
    memcpy(data+16, dbHeader, 8);
  }
}
#endif

#if CODEC_TYPE == CODEC_TYPE_GCM128
void CodecDecrypt(Codec* codec, int page, unsigned char* data, int len, hashmap *tag)
{
  unsigned char dbHeader[8];
  int dbPageSize;
  unsigned char p_in_mac[16];
  memset(p_in_mac, 0, 16);
  int offset = 0;
  int i=0;
  int j=0;

  if (page == 1)
  {
    memcpy(dbHeader, data+16, 8);
    dbPageSize = (dbHeader[0] << 8) | (dbHeader[1] << 16);
    if ((dbPageSize >= 512)   && (dbPageSize <= SQLITE_MAX_PAGE_SIZE) && (((dbPageSize-1) & dbPageSize) == 0) &&
        (dbHeader[5] == 0x40) && (dbHeader[6] == 0x20) && (dbHeader[7] == 0x20))
    {
      memcpy(data+16, data+8, 8);
      offset = 16;
    }
  }
  unsigned char *tmp;
  tmp = (unsigned char *)hm_get(tag, &page);
  if( tmp == NULL){
    fprintf(stdout, "page %d not match!\n ", page);
  }
  else{
    memcpy(p_in_mac, tmp, 16);
  }

  CodecAES(codec,page, CODEC_TYPE, 0, codec->m_readKey, data+offset, len-offset, data+offset, p_in_mac);
  if (page == 1 && offset != 0)
  {
    if (memcmp(dbHeader, data+16, 8) == 0)
    {
      memcpy(data, SQLITE_FILE_HEADER, 16);
    }
  }

}
#else
void CodecDecrypt(Codec* codec, int page, unsigned char* data, int len)
{
  unsigned char dbHeader[8];
  int dbPageSize;
  unsigned char p_in_mac[16];
  memset(p_in_mac, 0, 16);
  int offset = 0;
  int i=0;
  int j=0;

  if (page == 1)
  {
    memcpy(dbHeader, data+16, 8);
    dbPageSize = (dbHeader[0] << 8) | (dbHeader[1] << 16);
    if ((dbPageSize >= 512)   && (dbPageSize <= SQLITE_MAX_PAGE_SIZE) && (((dbPageSize-1) & dbPageSize) == 0) &&
        (dbHeader[5] == 0x40) && (dbHeader[6] == 0x20) && (dbHeader[7] == 0x20))
    {
      memcpy(data+16, data+8, 8);
      offset = 16;
    }
  }
  CodecAES(codec,page, CODEC_TYPE, 0, codec->m_readKey, data+offset, len-offset, data+offset, p_in_mac);
  if (page == 1 && offset != 0)
  {
    if (memcmp(dbHeader, data+16, 8) == 0)
    {
      memcpy(data, SQLITE_FILE_HEADER, 16);
    }
  }

}
#endif

