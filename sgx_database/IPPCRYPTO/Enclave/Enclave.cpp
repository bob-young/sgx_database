#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#include "Enclave_t.h"
#include "Enclave.h"
#include "vfslib/stdio.h"
#include "vfslib/stat.h"
#include "vfslib/fcntl.h"
#include "vfslib/unistd.h"
#include "vfslib/stdlib.h"
#include "vfslib/time.h"
#include "vfslib/mman.h"
#include "sqlite3.h"
//#include <sgx_tcrypto.h>
#include "interface_crypto.h"
//#define VFS_SGX_TEST

#ifdef VFS_SGX_TEST
#include "vfs_sgx_test.cpp"
#endif  /* VFS_SGX_TEST */
#define MEM_BLOCK_SIZE 1024*8

unsigned const char enc_key[17] = "1234567812345678";

int callback(void *NotUsed, int argc, char **argv, char **azColName){
    int i;
    for(i=0; i<argc; i++){
      fprintf(stdout, "%s = %s\t", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    fprintf(stdout, "\n");

    return 0;
 }


// int callback_enc(OMem *pOM, int argc, char **argv, char **azColName){
int callback_enc(char *str, int argc, char **argv, char **azColName){

    int i,fp;

    int s_len=MEM_BLOCK_SIZE-strlen(str);
   	// fprintf(stdout, "str: %s\n", str);
    fp = 0;
    for(i=0; i<argc; i++){
     	// fprintf(stdout, "%s = %s\t", azColName[i], argv[i] ? argv[i] : "NULL");
     	fp = fp + strlen(azColName[i]) + strlen(argv[i]) + 2;
     	// fprintf(stdout,"fp = %d\n",fp);
     	// if (fp < (pOM->rlen)){
     	if (fp < (s_len)){
	    	strcat(str,(char*)(azColName[i]));
	    	strcat(str," = ");
	    	strcat(str,(char*)(argv[i] ? argv[i] : "NULL"));
    		strcat(str,"\t");
		}
		else{
			fprintf(stdout,"out of memory");
		}
    }
    fp += 1;
    strcat(str,"\n");

    return 0;
}

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{        
    state->num = 0;
    memset(state->ecount, 0, 16); 
    memcpy(state->ivec, iv, 16); 
}

int transfer_cipher(
	const unsigned char *key, 
	const unsigned char *cipher,
	unsigned char *decrypted,
	int length,
    unsigned char *ecount    
){
	const uint32_t ctr_inc_bits = 128;
	// fprintf(stdout, "recive cipher:%.*s\n", cipher);
	//int t_len = strlen((const char*)cipher);

	uint8_t p_dsts[length];
	// fprintf(stdout,"%d\n",length);
	//enclave_encrypt(key,unsigned char* src,unsigned char* dest,int length);
	enclave_decrypt(key,cipher,p_dsts,length);
	//sgx_aes_ctr_decrypt((sgx_aes_gcm_128bit_key_t *)key,cipher, length, ecount, ctr_inc_bits, p_dsts);
	p_dsts[length] = '\0';
    // fprintf(stdout, "SGX ecount (hex mode): ");
    // for(int i=0; i<16; i++){
    //     fprintf(stdout, "%02x ", ecount[i]);
    // }
    // fprintf(stdout, "\n");
    for(int i=0;i<length;i++){
    	decrypted[i] = p_dsts[i];
    }
    return 0;
}

int transfer_plaintext(
	const unsigned char *key, 
	const unsigned char *plaintext,
	unsigned char *encrypted,
	int length,
    unsigned char *ecount
){
	char *zErrMsg = 0;
	int rc;		
	uint8_t p_ctr[16]= {0};

	const uint32_t ctr_inc_bits = 128;
	uint8_t p_dsts[length];

//	rc = sgx_aes_ctr_encrypt((sgx_aes_ctr_128bit_key_t *)key,plaintext, length, ecount, ctr_inc_bits, p_dsts);

	rc = enclave_encrypt(key,plaintext,p_dsts,length);

	p_dsts[length] = '\0';

	if( rc!=SGX_SUCCESS ){
	  fprintf(stderr,"SQL error: %s\n", zErrMsg);
	  sqlite3_free(zErrMsg);
	}
    for(int i=0;i<length;i++){
    	encrypted[i] = p_dsts[i];
    }
    return 0;
}

 
int ecall_vfs_sgx_test(){
#ifdef VFS_SGX_TEST
	return vfs_sgx_test();
#else
	fprintf(stdout, "vfs_sgx_test() if not supported! \n");
	return 0;
#endif  /* VFS_SGX_TEST */
}

int ecall_sqlite3_open(const char *filename,struct tDB *pdb){
	sqlite3 **ppdb = (sqlite3 **)&(pdb->pDB);
	return sqlite3_open(filename, ppdb);
}

int ecall_sqlite3_open_enc(const unsigned char *filenameEn, int len, unsigned char *ivec, struct tDB *pdb){
	sqlite3 **ppdb = (sqlite3 **)&(pdb->pDB);
	const char *filename;
	unsigned char decrypted[len]; 
	decrypted[len] = '\0';

	if(transfer_cipher(enc_key, filenameEn, decrypted, len, ivec)==0){
		filename = (const char *)decrypted ;
	}

    fprintf(stdout, "SGX decrypted dbname text: %s\n", filename);
	return sqlite3_open(filename, ppdb);
}

int ecall_sqlite3_prepare(
	struct tDB *pdb,              
  	const char *zSql,         /* UTF-8 encoded SQL statement. */
  	int nBytes	              /* Length of zSql in bytes. */
){
	sqlite3_stmt **ppStmt;    /* OUT: A pointer to the prepared statement */
  	const char **pzTail;       /* OUT: End of parsed string */
	sqlite3 **ppdb = (sqlite3 **)&(pdb->pDB);
	return sqlite3_prepare(*ppdb, zSql, nBytes, ppStmt, pzTail);
}

int ecall_sqlite3_prepare_v2(
	struct tDB *pdb,              
  	const char *zSql,         /* UTF-8 encoded SQL statement. */
  	int nBytes	              /* Length of zSql in bytes. */
){
	sqlite3_stmt **ppStmt;    /* OUT: A pointer to the prepared statement */
  	const char **pzTail;       /* OUT: End of parsed string */
	sqlite3 **ppdb = (sqlite3 **)&(pdb->pDB);
	return sqlite3_prepare_v2(*ppdb, zSql, nBytes, ppStmt, pzTail);
}

int ecall_sqlite3_step(){
	sqlite3_stmt *pStmt;
	return sqlite3_step(pStmt);
}


// const void *ecall_sqlite3_column_blob(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_blob(pStmt, iCol);
// }

// int ecall_sqlite3_column_bytes(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_bytes(pStmt, iCol);
// }
// int ecall_sqlite3_column_bytes16(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_bytes16(pStmt, iCol);
// }
// double ecall_sqlite3_column_double(sint iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_double(pStmt, iCol);
// }
// int ecall_sqlite3_column_int(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_int(pStmt, iCol);
// }
// sqlite3_int64 ecall_sqlite3_column_int64(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_int64(pStmt, iCol);
// }
// const unsigned char *ecall_sqlite3_column_text(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_text(pStmt, iCol);
// }
// const void *ecall_sqlite3_column_text16(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_text16(pStmt, iCol);
// }
// int ecall_sqlite3_column_type(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_type(pStmt, iCol);
// }
// sqlite3_value *ecall_sqlite3_column_value(int iCol){
// 	sqlite3_stmt *pStmt;
// 	return sqlite3_column_value(pStmt, iCol);
// }



int ecall_sqlite3_finalize(){
	sqlite3_stmt *pStmt;
	return sqlite3_step(pStmt);	
}

int ecall_sqlite3_exec(
	struct tDB *pdb,                                  /* An open database */
	const char *sql,                           /* SQL to be evaluated */
	//int (*callback)(void*,int,char**,char**),  /* Callback function */
	//void *,                                    /* 1st argument to callback */
	char *errmsg,                             /* Error msg written here */
    size_t count
){
	char *zErrMsg = 0;
	sqlite3 **ppdb = (sqlite3 **)&(pdb->pDB);

	int ret = sqlite3_exec(*ppdb, sql, callback, 0, count >0 ? &zErrMsg : NULL);
	if (count > 0 && zErrMsg != NULL) {
		strncpy(errmsg, zErrMsg, count);
		sqlite3_free(zErrMsg);
	}
    #ifdef SGX_ENC_DEC_TIME_TEST
    int pFile = open("test/enc_dec_time.log",O_RDWR | O_APPEND | O_CREAT, 0777);
	fprintf(pFile,"dec_time:%lfs\n", dec_call_time.exec_time);
    fprintf(pFile,"dec_pages:%d\n", dec_call_time.no_pages);
    fprintf(pFile,"enc_time:%lfs\n", enc_call_time.exec_time);
    fprintf(pFile,"enc_pages:%d\n", enc_call_time.no_pages);
    close(pFile);
    #endif
	return ret;
}

int ecall_sqlite3_exec_enc(	
	struct tDB *pdb,                                  /* An open database */
	const unsigned char *cipher,                           /* SQL to be evaluated */
	int len,
	unsigned char *ivec, 
	char *errmsg,                             /* Error msg written here */
    size_t count,
    unsigned char *pm,
    int m_rlen
    // char* strout,
    // size_t count2
){
	char *zErrMsg = 0;
	sqlite3 **ppdb = (sqlite3 **)&(pdb->pDB);
	const char *sql_dec;
	unsigned char decrypted[len]; 
	decrypted[len]='\0';
	if(transfer_cipher(enc_key, cipher, decrypted, len, ivec)==0){
		sql_dec = (const char *)decrypted;
	}
	// for(int i=0; i<len; i++){
 //        fprintf(stdout,"%02x ", cipher[i]);
 //    }	
	// fprintf(stdout, "SGX encrypted sql text: %s\n", cipher);
	//fprintf(stdout, "SGX len in: %d\n", len);
	//fprintf(stdout, "SGX decrypted sql text: %s\n", decrypted);
    fprintf(stdout, "SGX decrypted sql text: %s\n", sql_dec);

    OMem om;
    om.len = MEM_BLOCK_SIZE;	//1K
    om.rlen = om.len;

    // fprintf(stdout, "ocall_malloc\n");
    // ocall_malloc(&om);

    // void *pp = &(om.p);
    // void* fpp=(void*)(*(uint64_t*)pp);
    // fprintf(stdout, "fpp = %p\n", fpp);
    // memcpy(pm,pp,sizeof(unsigned char)*8);
    // void* fpm=(void*)(*(uint64_t*)pm);
    // fprintf(stdout, "fpm = %p\n", fpm);

    char str[MEM_BLOCK_SIZE]="\n";

	int ret = sqlite3_exec_enc(*ppdb, sql_dec, callback_enc, str, count >0 ? &zErrMsg : NULL);
	if (count > 0 && zErrMsg != NULL) {
		strncpy(errmsg, zErrMsg, count);
		sqlite3_free(zErrMsg);
	}
	// memcpy(strout,str,strlen(str));	
	int s_len = strlen(str);
	m_rlen = s_len;
	// fprintf(stdout, "str:%s\n",str);
	unsigned char encrypted[s_len]; 
	decrypted[s_len]='\0';
	uint8_t ecount[16]= {0};

	transfer_plaintext(enc_key, (const unsigned char *)str, encrypted, s_len, ecount);
	// fprintf(stdout, "iv in:  %d\n",ecount );
	ocall_reslutcp(&ret, &om, encrypted, s_len, ecount);
	void *pp = &(om.p);
    memcpy(pm,pp,sizeof(unsigned char)*8);
    void* fpm=(void*)(*(uint64_t*)pm);
    fprintf(stdout, "exec_enc fpm = %p\n", fpm);
	return ret;
}




typedef struct TabResult {
  char **azResult;   /* Accumulated output */
  char *zErrMsg;     /* Error message text, if an error occurs */
  int nAlloc;        /* Slots allocated for azResult[] */
  int nRow;          /* Number of rows in the result */
  int nColumn;       /* Number of columns in the result */
  int nData;         /* Slots used in azResult[].  (nRow+1)*nColumn */
  int rc;            /* Return code from sqlite3_exec() */
} TabResult;




int ecall_sqlite3_close(struct tDB *pdb){
	sqlite3 **ppdb = (sqlite3 **)&(pdb->pDB);
	return sqlite3_close(*ppdb);
}

void ecall_sqlite3_errmsg(struct tDB *pdb, char *errmsg, size_t count){
	sqlite3 **ppdb = (sqlite3 **)&(pdb->pDB);
	const char * msg = sqlite3_errmsg(*ppdb);
	strncpy(errmsg, msg, count);
}

int ecall_sqlite3_exec_once(const char *dbname, const char *sql){
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	fprintf(stdout,"\n---SQL Query Start----\n");
	rc = sqlite3_open(dbname, &db);

	if( rc ){
	  fprintf(stdout, "Can't open database: %s\n", sqlite3_errmsg(db));
	  sqlite3_close(db);
	  return(1);
	}
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	if( rc!=SQLITE_OK ){
	  fprintf(stderr,"SQL error: %s\n", zErrMsg);
	  sqlite3_free(zErrMsg);
	}
	sqlite3_close(db);
	fprintf(stdout,"---SQL Query End----\n\n");

	return 0;
}

//0
int ecall_sqlite3_ctr_encrypt(const char *sql, const char *sgx_ctr_key, uint8_t *p_dst, size_t count){
	int rc = -1;
	char *zErrMsg = 0;

	int src_len = strlen(sql);
	unsigned char *p_src = (unsigned char*)malloc(src_len); 
	memcpy(p_src,sql,src_len);	

	unsigned char *sgx_keys = (unsigned char *)malloc(Enclave_Key_Size*sizeof(char));
	memcpy(sgx_keys,sgx_ctr_key,Enclave_Key_Size);

	unsigned char *p_dsts = (unsigned char *)malloc(src_len*sizeof(char));

	rc = enclave_encrypt(sgx_keys,p_src,p_dsts,src_len);

	if(rc != 0){
	  fprintf(stderr,"SQL error: %s\n", zErrMsg);
	  sqlite3_free(zErrMsg);
	}

	fprintf(stdout, "sgx cipher: ");
	for(int i=0; i<src_len; i++){
		p_dst[i] = p_dsts[i];
        fprintf(stdout, "%02x ", p_dsts[i]);
    }
    fprintf(stdout, "\n");
    free(p_src);
    free(sgx_keys);
	return 0;
}


int ecall_sqlite3_ctr_decrypt(unsigned char *cipher, const char *sgx_ctr_key, uint8_t *p_dst,size_t count){
	int rc = -1;
	char *zErrMsg = 0;

	int src_len = strlen((char*)cipher);
	unsigned char *p_src = (unsigned char*)malloc(src_len); 
	memcpy(p_src,cipher,src_len);

	unsigned char *sgx_keys = (unsigned char *)malloc(Enclave_Key_Size*sizeof(char));
	memcpy(sgx_keys,sgx_ctr_key,Enclave_Key_Size);

	unsigned char *p_dsts = (unsigned char *)malloc(count*sizeof(char));

	rc = enclave_encrypt(sgx_keys,p_src,p_dsts,count);

	fprintf(stdout, "sgx p_dsts: ");
	for(int i=0; i<count; i++){
		p_dst[i] = p_dsts[i];
        fprintf(stdout, "%c", p_dsts[i]);
    }
    fprintf(stdout, "\n");
	if( rc!=SGX_SUCCESS ){
	  fprintf(stderr,"SQL error: %s\n", zErrMsg);
	  sqlite3_free(zErrMsg);
	}
    free(p_src);
    free(sgx_keys);
	return 0;
}

int ecall_sqlite3_ctr_decrypt_2(unsigned char *ecount,unsigned char *cipher, const unsigned char *sgx_ctr_key, uint8_t *p_dst,size_t count){
	
	char *zErrMsg = 0;
	int rc;


	uint8_t *sgx_ctr_keys = (uint8_t *)malloc(16*sizeof(char));
	memcpy(sgx_ctr_keys,sgx_ctr_key,16);
	const uint8_t *p_src = (const uint8_t *)cipher;
	uint8_t p_ctr[16]= {0};

	const uint32_t ctr_inecall_sqlite3_openc_bits = 128;
	const uint32_t ctr_inc_bits = 128;//////////////////
	uint8_t *p_dsts = (uint8_t *)malloc(count*sizeof(char));

	fprintf(stdout, "sgx ecount: ");
	for(int i=0; i<16; i++){
        fprintf(stdout, "%02x ", ecount[i]);
    }
    fprintf(stdout, "\n");

	//rc = sgx_aes_ctr_decrypt((sgx_aes_gcm_128bit_key_t *)sgx_ctr_keys, p_src, count, ecount, ctr_inc_bits, p_dsts);
	rc = enclave_encrypt(sgx_ctr_keys,p_src,p_dsts,count);

	fprintf(stdout, "sgx cipher: ");
	for(int i=0; i<count; i++){
        fprintf(stdout, "%02x ", cipher[i]);
    }
    fprintf(stdout, "\n");

	fprintf(stdout, "sgx decrypted: ");
    for(int i=0; i<count; i++){
    	p_dst[i] = p_dsts[i];
        fprintf(stdout, "%c", p_dsts[i]);
    }
    fprintf(stdout, "\n");


	if( rc!=SGX_SUCCESS ){
	  fprintf(stderr,"SQL error: %s\n", zErrMsg);
	  sqlite3_free(zErrMsg);
	}

	return 0;
}


void ecall_transfer_cipher(const unsigned char *key, 
	const unsigned char *cipher, 
    unsigned char *ecount,
    size_t length){
	const uint32_t ctr_inc_bits = 128;
	// fprintf(stdout, "recive cipher:%.*s\n", cipher);
	//int t_len = strlen((const char*)cipher);

	uint8_t p_dsts[length];
	fprintf(stdout,"%d\n",length);

	//sgx_aes_ctr_decrypt((sgx_aes_ctr_128bit_key_t *)key, cipher, length, ecount, ctr_inc_bits, p_dsts);
	enclave_decrypt(key,cipher,p_dsts,length);
	p_dsts[length] = '\0';
    fprintf(stdout, "SGX ecount (hex mode): ");
    for(int i=0; i<16; i++){
        fprintf(stdout, "%02x ", ecount[i]);
    }
    fprintf(stdout, "\n");

    fprintf(stdout, "SGX Plain text (hex mode): ");
    for(int i=0; i<length; i++){
        fprintf(stdout, "%02x ", p_dsts[i]);
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "SGX Plain text: %s\n", p_dsts);
}
