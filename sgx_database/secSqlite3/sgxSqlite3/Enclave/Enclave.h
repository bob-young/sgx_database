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


#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include "user_types.h"


#if defined(__cplusplus)
extern "C" {
#endif

//typedef struct sqlite3 sqlite3;

//int ecall_sqlite3_exec_once(const char *dbname, const char *sql);

// struct sqlite3 {
//   sqlite3_vfs *pVfs;            /* OS Interface */
//   struct Vdbe *pVdbe;           /* List of active virtual machines */
//   CollSeq *pDfltColl;           /* The default collating sequence (BINARY) */
//   sqlite3_mutex *mutex;         /* Connection mutex */
//   Db *aDb;                      /* All backends */
//   int nDb;                      /* Number of backends currently in use */
//   int flags;                    /* Miscellaneous flags. See below */
//   i64 lastRowid;                /* ROWID of most recent insert (see above) */
//   i64 szMmap;                   /* Default mmap_size setting */
//   unsigned int openFlags;       /* Flags passed to sqlite3_vfs.xOpen() */
//   int errCode;                  /* Most recent error code (SQLITE_*) */
//   int errMask;                  /* & result codes with this before returning */
//   u16 dbOptFlags;               /* Flags to enable/disable optimizations */
//   u8 autoCommit;                /* The auto-commit flag. */
//   u8 temp_store;                /* 1: file 2: memory 0: default */
//   u8 mallocFailed;              /* True if we have seen a malloc failure */
//   u8 dfltLockMode;              /* Default locking-mode for attached dbs */
//   signed char nextAutovac;      /* Autovac setting after VACUUM if >=0 */
//   u8 suppressErr;               /* Do not issue error messages if true */
//   u8 vtabOnConflict;            /* Value to return for s3_vtab_on_conflict() */
//   u8 isTransactionSavepoint;    /* True if the outermost savepoint is a TS */
//   int nextPagesize;             /* Pagesize after VACUUM if >0 */
//   u32 magic;                    /* Magic number for detect library misuse */
//   int nChange;                  /* Value returned by sqlite3_changes() */
//   int nTotalChange;             /* Value returned by sqlite3_total_changes() */
//   int aLimit[SQLITE_N_LIMIT];   /* Limits */

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
