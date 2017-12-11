/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


/* User defined types */


#ifndef __SGX_USER_TYPES_H
#define __SGX_USER_TYPES_H
//#define SGX_ENC_DEC_TIME_TEST//dec and enc time test. No of pages read or written
struct tDB{
    void * pDB;
};
#pragma pack(1)
typedef struct
{
    void* p;    //8
    int len;    //4
    int rlen;   //4
}OMem;          //size = 16

#pragma pack()

#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include "../Enclave/hashmap/hashmap.h"
/*##################Before Coding... (VERY IMPORTANT)###################
-----This is just a TRADEOFF to solve the proble of using some definitions only in Enclave environment facing EDL file.
-----In file /opt/intel/sgxsdk/include/tlibc/sys/types.h 
-----after
#ifndef _SYS_TYPES_H_
#define _SYS_TYPES_H_
-----add a newline
#define __VIVI_SGX_IN_ENCLAVE__
##################Before Coding... (VERY IMPORTANT)###################*/
#ifdef __VIVI_SGX_IN_ENCLAVE__
//Very Important:  Here, we use those definitions below only in Enclave environment. Please Refer to info.txt.
struct timeval{
	long tv_sec;
	long tv_usec;
};
 struct timezone
 {
 	int tz_minuteswest;
 	int tz_dsttime;
 };

//for fcntl.h
struct flock{
	short	l_type;
	short	l_whence;
	long	l_start;
	long	l_len;
	int		l_pid;
	//__ARCH_FLOCK_PAD
};
//for stat.h

typedef unsigned int mode_t;

typedef unsigned int uid_t;
typedef unsigned int gid_t;

typedef unsigned long dev_t;
typedef unsigned long ino_t;
typedef unsigned long nlink_t;

typedef long blksize_t;
typedef long blkcnt_t;
typedef long long syscall_slong_t ;
//typedef long long __syscall_slong_t ;

struct timespec {
    time_t tv_sec;
    syscall_slong_t tv_nsec;
};

#ifdef SGX_ENC_DEC_TIME_TEST
#define CLOCK_PROCESS_CPUTIME_ID 2
struct calltime{
    int no_pages;
    double exec_time;
};
extern struct calltime enc_call_time;
extern struct calltime dec_call_time;
#endif

struct stat {
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;
    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    int __pad0;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    syscall_slong_t __glibc_reserved[3];
};

struct ctr_state 
{ 
    unsigned char ivec[16];  
    unsigned int num; 
    unsigned char ecount[16]; 
}; 

typedef int pid_t;

//for Enclave.cpp

// typedef struct {
//   char **azResult;   /* Accumulated output */
//   char *zErrMsg;     /* Error message text, if an error occurs */
//   int nAlloc;        /* Slots allocated for azResult[] */
//   int nRow;           //Number of rows in the result 
//   int nColumn;       /* Number of columns in the result */
//   int nData;         /* Slots used in azResult[].  (nRow+1)*nColumn */
//   int rc;            /* Return code from sqlite3_exec() */
// }TabResult;
#define CODEC_TYPE_CTR128 1
#define CODEC_TYPE_GCM128 2
#ifndef CODEC_TYPE
#define CODEC_TYPE CODEC_TYPE_GCM128
#endif

extern hashmap *tag;

#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#endif /*  _SGX_EDGER8R_H_  */

#endif

