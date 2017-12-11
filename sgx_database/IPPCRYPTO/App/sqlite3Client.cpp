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


#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
//#define FilePath "test.log"
#include "sgx_urts.h"
#include "sqlite3Client.h"
#include "Enclave_u.h"
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdlib.h>
#include <math.h>


// #define XDSGX_BLOCK_SIZE  AES_BLOCK_SIZE
#define XDSGX_BLOCK_SIZE  65535
#define AES_KEY_SIZE 16
#define MEM_BLOCK_SIZE 1024*8   //1k
// unsigned const char enc_key[AES_KEY_SIZE+1] = "1234567812345678";
// #define OPENSSL_CTR_TEST
// #define SGX_CTR_TEST
//#define SGX_GET_TABLE_TEST
//#include "md5.c"
//#include "md5.h"
//#define SGX_SQLITE_TIME_TEST

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

unsigned char * TextDecrypt(const unsigned char* enc_key, unsigned char* cypherText,int bytes_read,uint8_t* ecount);

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];
    printf("error ret: %d\n", ret);

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        //printf("%d\n", ret);
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}


int ocall_rtreslut(char *title, size_t count, char *r, size_t size){
    //decrypt
    //print
    printf("ok");
    printf("%s = %s\t", title, r ? r : "NULL");

}

int ocall_reslutcp(OMem* mem,unsigned char* str,int s_len,uint8_t* ecount){
    char *p = (char*)malloc(mem->len);
    memcpy(p,str,s_len);
    int i;
    // fprintf(stdout, "sgx cipher encrypt in ocall_reslutcp: ");
    // for(i=0; i<s_len; i++){
    //     fprintf(stdout, "%02x ", str[i]);
    // }
    // fprintf(stdout, "\n");

    unsigned const char enc_key[AES_KEY_SIZE+1] = "1234567812345678";
    uint8_t ivec[16]= {0};

    str = TextDecrypt(enc_key, str, s_len, ivec);
    printf("-------reslut:----------\n ");
    for(int i=0; i<s_len; i++){
        printf("%c", str[i]);
    }
    printf("\n");
    // printf("--------------------------------pout:----------------------------------\n");
    // for(i=0;i<s_len;i++){
    //     printf("%c",p[i]);
    // }
    // printf("\n");
    mem->p = p;
    return 0;
}

void ocall_malloc(OMem* mem){
    void *p = malloc(mem->len);
    //unsigned char **mpath = (unsigned char **)&p;
    printf("malloc the mem: %p\n",(void*)p);
    // printf("malloc the mem: \n");

    mem->p = p;
}



int aes_encrypt(char *key_string,const char *sql,unsigned char *out1){
    AES_KEY  aes;
    int sql_len = strlen(sql);
    printf("sql_len = %d\n", sql_len);
    int n=sql_len/16;
    if (AES_set_encrypt_key((unsigned char*)key_string, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        return 0;
    }
    unsigned char* tmpe=(unsigned char*)malloc(sizeof(unsigned char)*16*(n+1));
    memcpy(tmpe,sql,sql_len);
    for(int m=sql_len;m<(n+1)*16;m++){
        tmpe[m]='\0';
    }
    for(int m=0;m<=n;m++){
        AES_encrypt(tmpe+16*m,out1+16*m,&aes);
    }
    return 1;
}


int aes_decrypt(char *key_string, unsigned char *out1, unsigned char *out2){
    AES_KEY  aes;
    int sql_len = strlen((char *)out1);
    printf("sql_len = %d\n", sql_len);
    int n = sql_len/16;
    if (AES_set_decrypt_key((unsigned char*)key_string, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        return 0;
    }
    for(int m=0;m<=n;m++){
        AES_decrypt(out1+16*m,out2+16*m,&aes);
    }
    return 1;
}


struct ctr_state 
{ 
    unsigned char ivec[AES_BLOCK_SIZE];  
    unsigned int num; 
    unsigned char ecount[AES_BLOCK_SIZE]; 
}; 
AES_KEY key, dec_key; 

int bytes_read, bytes_written;   
unsigned char indata[XDSGX_BLOCK_SIZE]; 
unsigned char outdata[XDSGX_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE]; //16?
struct ctr_state state;



int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{        
    /*O aes_ctr128_encrypt exige um 'num' e um 'ecount' definidos a zero na primeira chamada. */
    state->num = 0;
    //memset(state->ecount, 0, XDSGX_BLOCK_SIZE); //16?

    /* Inicilaização do contador no 'ivec' a 0 */
    memset(state->ecount, 0, 16); //16?
    // memset(state->ivec + 8, 0, 8);
    /* Copia o IV para o 'ivec' */
    memcpy(state->ivec, iv, 16); //16?
}

unsigned char * TextEncrypt(const unsigned char* enc_key, const unsigned char * text, int bytes_read)
{ 
    //Cria vector com valores aleatórios
    if(!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
        printf("Erro\n");
        exit(1);    
    }

    //printf("enc_key = %s\n",enc_key);
    //Inicializa a chave de encriptação
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Unable to set encryption key in AES");
        exit(1);
    }
/*    if (AES_set_decrypt_key(enc_key, 128, &dec_key) < 0)
    {
        fprintf(stderr, "Unable to set encryption key in AES");
        exit(1);
    }*/

    init_ctr(&state, iv); //Chamada do contador

    // printf("state.ivec: ");
    // for(int i=0; i<AES_BLOCK_SIZE; i++){
    //     printf("%02x ", state.ivec[i]);
    // }
    // printf("\n");
    // printf("state.ecount: ");
    // for(int i=0; i<AES_BLOCK_SIZE; i++){
    //     printf("%02x ", state.ecount[i]);
    // }
    // printf("\n");
    // printf("state.num:%d\n",state.num);

    // //AES_set_encrypt_key(enc_key, 128, &key);    
    // printf("state.num:%d\n",state.num);
    //Encripta em blocos de 16 bytes e guarda o texto cifrado numa string -> outdata
    AES_ctr128_encrypt(text, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
    printf("soutdata: ");
    for(int i=0; i<bytes_read; i++){
        printf("%02x ", outdata[i]);
    }
    printf("\n");
    memcpy(state.ivec, iv, 16);

    fflush(stdin);
    return outdata;
}

unsigned char * TextDecrypt(const unsigned char* enc_key, unsigned char* cypherText,int bytes_read, uint8_t* ivec)
{       

    //Inicialização da Chave de encriptação 
    // if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    // {
    //     fprintf(stderr, "Unable to set decryption key in AES.");
    //     exit(1);
    // }

    init_ctr(&state, ivec);//Chamada do contador
    // printf("TextDecrypt state.num=%d,ivec=%d,ecount=%d\n",state.num,state.ivec,state.ecount);
    //memcpy(state.ivec, iv, 16);
    //Encripta em blocos de 16 bytes e escreve o ficheiro output.txt cifrado         
    //bytes_read = strlen(cypherText);    
    if (AES_set_decrypt_key(enc_key, 128, &dec_key) < 0)
    {
        fprintf(stderr, "Unable to set encryption key in AES");
        exit(1);
    }
    // state.ivec = ecount;
    //memcpy(state.ivec, ecount, 16);
    AES_ctr128_encrypt(cypherText, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
    // printf("decrypt data in TextDecrypt: ");
    // for(int i=0; i<bytes_read; i++){
    //     printf("%c", outdata[i]);
    // }
    // printf("\n");
    fflush(stdin);
    return outdata;
}

int sqlite3_exec_encrypt(const char *dbname, const char *sql, const unsigned char *enc_key){

    int retval;
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    char errmsg[50] = {'\0'};

    /* Utilize trusted sqlite3 */
    int rc;
    struct tDB tdb;

    fprintf(stdout,"\n---ENCRPT SQL Query Start----\n");
    const unsigned char * cipherdb;
    int len = strlen(dbname);
    cipherdb = TextEncrypt(enc_key, (const unsigned char *)dbname,len);
    if ( (rc = ecall_sqlite3_open_enc(global_eid, &rc, cipherdb, len, state.ivec, &tdb)) 
            != SGX_SUCCESS ) {
        abort();
    }

    if( rc ){
        if ( (ret = ecall_sqlite3_errmsg(global_eid, &tdb, errmsg, sizeof(errmsg))) 
                != SGX_SUCCESS ) {
            abort();
        }
        fprintf(stdout, "Can't open database: %s\n", errmsg);
        //sqlite3_close(db);
        if ( (ret = ecall_sqlite3_close(global_eid, &rc, &tdb))
                != SGX_SUCCESS ) {
            abort();
        }
        return(1);
    }

    //sql1 encrypt
    fprintf(stdout, "run with SGX encrypt exec:\n"); 
    //sql2 encrypt
    unsigned char pm[8];
    int m_len;
    const unsigned char * ciphersql;
    len = strlen(sql);

    ciphersql = TextEncrypt(enc_key, (const unsigned char *)sql,len);
    // char strout[MEM_BLOCK_SIZE];
    // size_t count2 = MEM_BLOCK_SIZE;
    // ret = ecall_sqlite3_exec_enc(
    //     global_eid, &rc, &tdb, ciphersql2, len, state.ivec, errmsg, sizeof(errmsg),pm, m_len, strout, count2);
    ret = ecall_sqlite3_exec_enc(
        global_eid, &rc, &tdb, ciphersql, len, state.ivec, errmsg, sizeof(errmsg),pm, m_len);    
    if ( ret != SGX_SUCCESS) {
        // global_eit命令查看backtraced, &rc, &tdb, sql, errmsg, sizeof(errmsg)
        abort();    
    }
    if( rc!=0 ){
      fprintf(stderr,"SQL error: %s\n", errmsg);
    }
    int i;
    // printf("strout");
    // len = strlen(strout);
    // for(i=0;i<len;i++){
    //     printf("%c",strout[i]);
    // }
    // printf("\n");
    printf("outd====%p\n",(void*)(*(uint64_t*)pm));
    //print the encrypt reslut in the malloc memory
/*    printf("pmout:");
    char* upm=(char*)*(uint64_t*)pm;
    for(i=0;i<m_len;i++){
        printf("%c", upm[i]);
    }
    printf("\n");*/

    // printf("pm free\n");
    // free(pm);
    fprintf(stdout,"---ENCRPT SQL Query END----\n");
    return 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    //printf("use \"-crypt_ctr\" in the end to crypt the sql\n");

    printf("argc: %u\n", argc);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    const char *dbname = argv[1];
    const char *sql = argv[2];
    char ctr_rand_key[AES_KEY_SIZE]={0};
    const unsigned char key[17] = "1234567812345678";

    const char *encryp = NULL;
    char errmsg[50] = {'\0'};
#ifdef SGX_SQLITE_TIME_TEST 
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
    if (argc < 3){
        char *sqlPath;
        printf("Usage: ./sqlite3Client sqlPath\n");
        printf("SGX_SQLITE_TIME_TEST Mode!!!!\n");
        if (argc == 2 ) {
            sqlPath = argv[1]; 
        }
        fprintf(stdout,"---SGX_SQLITE_TIME_TEST start!----\n");
    
        //int test_flag = oss_test (FilePath,sqlPath);
        int test_flag = oss_test (sqlPath);
        if (test_flag != 0)
        {
            fprintf(stdout,"fopen error!\n");
        }
        fprintf(stdout,"---SGX_SQLITE_TIME_TEST end!----\n");

        //printf("Usage: ./sqlite3Client db sql [-crypt_ctr]\n");
        goto sgx_destroy;
        return 0;
    }
#endif //SGX_SQLITE_TIME_TEST
    printf("use \"-crypt_ctr\" in the end to crypt the sql\n");
    if (argc<3){
        printf("Usage: ./sqlite3Client db sql [-crypt_ctr]\n");
        return 0;
    }
    if (argc == 4 ) {
       encryp = argv[3]; 
    }

    printf("dbname = %s \n", dbname);
    printf("sql = %s \n", sql);
    if(encryp && strcmp(encryp, "-crypt_ctr") == 0){
        printf("crypt or not: YES\n");
        int number[AES_KEY_SIZE] = {0};
        int i;
        srand((unsigned)time(NULL));
        // printf("rand_sgx_ctr_key:");
        for(i = 0; i < AES_KEY_SIZE; i++){
            number[i] = (rand() % 255);
            ctr_rand_key[i] = (char)number[i];
            // printf("%d:%c",i,ctr_rand_key[i]);
        }
        if ( sqlite3_exec_encrypt(dbname, sql, key)!=0) {
            abort();
        }
/*        if ( sqlite3_exec_encrypt(dbname, sql2, key)!=0) {
            abort();
        }*/
        // int fd = -1;
        // int size;
        // unsigned long filesize = -1;
        // char fname[60] = {'\0'};
        // char buffer[100];
        // strncpy(fname, "./test_m/", 7);
        // strncat(fname, "test.txt", 8);

        // fprintf(stdout, "app open file %s\n",fname);
        // fd = open(fname, O_RDONLY);
        // size = read(fd,buffer,sizeof(buffer));
        // close(fd);
        //printf("%s",buffer);
        return 0;
    }else{
        printf("crypt or not: NO");
    }

     //Initialize the enclave 
    int retval;
   if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    /* Utilize trusted sqlite3 */
    int rc;
    struct tDB tdb;

    //ret = ecall_sqlite3_exec_once(global_eid, &rc, dbname, sql, &tdb);

    fprintf(stdout,"\n---SQL Query Start----\n");
    //rc = sqlite3_open(dbname, &db);
    //encrypt dbname
    // unsigned char * cipherdb, * decrypted;
    // cipherdb = TextEncrypt(enc_key, (const unsigned char *)text,len);
    if ( (ret = ecall_sqlite3_open(global_eid, &rc, dbname, &tdb)) 
            != SGX_SUCCESS ) {
        abort();
    }

    if( rc ){
        if ( (ret = ecall_sqlite3_errmsg(global_eid, &tdb, errmsg, sizeof(errmsg))) 
                != SGX_SUCCESS ) {
            abort();
        }
        fprintf(stdout, "Can't open database: %s\n", errmsg);
        //sqlite3_close(db);
        if ( (ret = ecall_sqlite3_close(global_eid, &rc, &tdb))
                != SGX_SUCCESS ) {
            abort();
        }
        return(1);
    }
    fprintf(stdout, "DATABASE OPENED!\n");

    //sql encrypt

    //Two ways to sexecute the sql statements

    //exec();
    /*    char *zFirstCmd = 0;
    for(int i=2; i<argc; i++){
        zFirstCmd = argv[i];
        if( zFirstCmd[i]=='.' ){
            rc = do_meta_command(zFirstCmd, &data);
            if( rc==2 ) rc = 0;
        }
        else{
            fprintf(stdout, "run with exec:\n");
            if ( (ret = ecall_sqlite3_exec(global_eid, &rc, &tdb, zFirstCmd[i], errmsg, sizeof(errmsg)))!= SGX_SUCCESS) {
                 abort();
            }
            if( rc!=0 ){
                fprintf(stderr,"SQL error: %s\n", errmsg);
            }
        }
    }*/
    fprintf(stdout, "run with exec:\n");
    if ( (ret = ecall_sqlite3_exec(global_eid, &rc, &tdb, sql, errmsg, sizeof(errmsg)))
                != SGX_SUCCESS) {
        abort();
    }
    if( rc!=0 ){
      fprintf(stderr,"SQL error: %s\n", errmsg);
    }






#ifdef MD5_test
    printf("--------------test md5---------------:\n");
    const char *key = "admin";

    int i = 0;
    //The key of the AES
    unsigned char keyResult[16];
    MD5_CTX md5;  
    MD5Init(&md5);                
    MD5Update(&md5,(unsigned char *)key,strlen(key)); 



    MD5Final(&md5,keyResult);


    printf("md5前:%s\nmd5后:",key); 
     for(i=0;i<16;i++)  
    {  
        printf("%02x",keyResult[i]);  
    }  
    printf("\n---------------test aes--------------\n");
#endif /* MD5_TEST */

#ifdef OPENSSL_AES_TEST

    char *key_aes = "1234567890";

    int i = 0;
    int sql_len = strlen(sql);
    unsigned char out1[((sql_len-1)/16+1)*16];
    unsigned char out2[((sql_len-1)/16+1)*16];
    memset(out1,0,((sql_len-1)/16+1)*16);
    memset(out2,0,((sql_len-1)/16+1)*16);
    if( aes_encrypt(key_aes, sql, out1) != 1){
        printf("error on encryption;\n");
    }

    for(i= 0;i < 32;i+=2){
        printf("%x",out1[i]);
    }
    printf("\n");

    if( aes_decrypt(key_aes, out1, out2)!= 1){
        printf("error on decryption;\n");
    }

    for(int k=0;k<32;k++){
        printf("%c",out2[k]);
    }
    printf("\nsql=%s\nout2=%s\n",sql,out2);
    if(sql == out2){
        printf("\n---------------aes  OK!--------------\n");
    }
#endif /* OPENSSL_AES_TEST */


#ifdef OPENSSL_CTR_TEST

    printf("\n---------------test openssl ctr--------------\n");
    // const unsigned char text[XDSGX_BLOCK_SIZE] = {'O','P','E','N','S','S','L','_','C','T','R','_','T','E','S','T'};
    const unsigned char *text = (const unsigned char *)sql ;

    //Receive hexadecimal 128 bits key 
    unsigned const char enc_key[AES_KEY_SIZE+1] = "1234567812345678";
    //unsigned const char * key = "9EF4BCDE";   
    unsigned char * cipher, * decrypted;

    int len = strlen(sql);
    //int len = strlen(text);
    printf("len = %d\n",len );
    printf("Clean text: %s\n", text);
    printf("Clear text (hex mode): ");
    for(int i=0; i<len; i++){
        printf("%02x ", text[i]);
    }
    printf("\n");

    printf("key = %s\n", enc_key);

    printf("Init, state.ivec (hex mode): ");
    for(int i=0; i<AES_BLOCK_SIZE; i++){
        printf("%02x ", state.ivec[i]);
    }
    printf("\n");

    cipher = TextEncrypt(enc_key, (const unsigned char *)text,len);
    // int cipher_len = strlen((const char*)cipher);
    // printf("cipher_len = %d\n", cipher_len);
    printf("cipher:%02x\n", cipher);

//FOR state.ecount
    //ivec, ecount_buf, key
    printf("\n------START test state.ecount------\n");
    unsigned char myout[XDSGX_BLOCK_SIZE];
    printf("\tBefore state.ecount (hex mode): ");
    for(int i=0; i<AES_BLOCK_SIZE; i++){
        printf("%02x ", state.ecount[i]);
    }
    printf("\n");
    printf("\tBefore state.ivec (hex mode): ");
    for(int i=0; i<AES_BLOCK_SIZE; i++){
        printf("%02x ", state.ivec[i]);
    }
    printf("\n");
    //AES_encrypt(state.ecount, myout, &key);
    AES_decrypt(state.ecount, myout, &dec_key);
    printf("\tAfter state.ecount (hex mode): ");
    for(int i=0; i<len; i++){
        printf("%02x ", myout[i]);
    }
    printf("\n");
    printf("------END test state.ecount------\n");

    //printf("Chiper text (hex mode): %.*s\n", len, cipher);
    printf("Chiper text (hex mode): ");
    for(int i=0; i<len; i++){
        printf("%02x ", cipher[i]);
    }
    printf("\n");

    printf("After Encpt, state.ivec (hex mode): ");
    for(int i=0; i<AES_BLOCK_SIZE; i++){
        printf("%02x ", state.ivec[i]);
    }
    printf("\n");

    //decrypted = TextDecrypt(enc_key, cipher,len);
    //printf("openssl Decrypted text: %.*s\n", len, decrypted);
//state.ecount  //state.ivec

    if ( (ret = ecall_transfer_cipher(global_eid, enc_key, cipher, state.ivec, len))
            !=SGX_SUCCESS ){
        printf("error");
    }

    printf("After Decpt state.ivec (hex mode): ");
    for(int i=0; i<AES_BLOCK_SIZE; i++){
        printf("%02x ", state.ivec[i]);
    }
    printf("\n");


    // if (strcmp(text, cipher) == 0){
    //     printf("\n---------------ctr  OK!--------------\n");
    // }else{
    //     printf("\n---------------ctr decrypt error!--------------\n");
    // }

#endif /* OPENSSL_CTR_TEST */

#ifdef VFS_SGX_TEST
    if ((ret = ecall_vfs_sgx_test(global_eid, &retval)) != SGX_SUCCESS){
        abort();
    }
    if (retval != 0) {
        goto sgx_destroy;
    }
#endif /* VFS_SGX_TEST */  

#ifdef SGX_CTR_TEST

    fprintf(stdout,"\n---TEST SGX CTR----\n");
    fprintf(stdout,"---test sgx_ctr_encrypt\n");

    const char sgx_ctr_key[16] = "1234567812345678";
    const char* sgx_text = sql;

    int s_len = strlen(sgx_text);
    unsigned char * SGXcipher = (unsigned char *)malloc(16*sizeof(char));
    unsigned char * SGXdecrypted = (unsigned char *)malloc(s_len*sizeof(char));
    unsigned char * SGXencrypted = (unsigned char *)malloc(s_len*sizeof(char));

    if ( (ret = ecall_sqlite3_ctr_encrypt(global_eid, &rc, sgx_text, sgx_ctr_key, SGXencrypted, s_len))
            !=SGX_SUCCESS ){
        printf("error");
    }

    printf("encrypted text: ");
    for(int i=0; i<21; i++){
        printf("%c", SGXencrypted[i]);
    }
    printf("\n");

    fprintf(stdout,"\n---test sgx_ctr_decrypt\n");

    if ( (ret = ecall_sqlite3_ctr_decrypt(global_eid, &rc, SGXencrypted, sgx_ctr_key, SGXdecrypted, s_len))
            !=SGX_SUCCESS ){
        printf("error");
    }

    printf("decrypted text: ");
    for(int i=0; i<21; i++){
        printf("%c", SGXdecrypted[i]);
    }
    printf("\n");


    if(strcmp((const char *)SGXdecrypted, (const char *)sql) == 0){
        printf("----sgx_ctr_encrypt & decrypt ok!\n");
    }else{
        printf("sgx_ctr_encrypt is not equal\n");
    }

    // fprintf(stdout,"\n---test sgx_ctr_decrypt\n");

    // SGXcipher = TextEncrypt((const unsigned char *)sgx_ctr_key, (const unsigned char *)sgx_text,s_len);

    // printf("cipher text: ");
    // for(int i=0; i<16; i++){
    //     printf("%02x ", SGXcipher[i]);
    // }
    // printf("\n");


    // if ( (ret = ecall_sqlite3_ctr_decrypt(global_eid, &rc, dbname, (const char *)SGXcipher, sgx_ctr_key, SGXencrypted))
    //         !=SGX_SUCCESS ){
    //     printf("error");
    // }

    // printf("encrypted text: ");
    // for(int i=0; i<s_len; i++){
    //     printf("%02x ", SGXencrypted[i]);
    // }
    // printf("\n");

    fprintf(stdout,"---TEST SGX CTR END---\n\n");


#endif /* SGX_CTR_TEST */

    



#ifdef SGX_GET_TABLE_TEST

    //get_table(); without callback
    fprintf(stdout, "\n-------run with get_table start-----------\n");

    char *pResult[100];
    int Row = 0;
    int Col = 0;
    int Result_len=0;
    int nAlloc = 20;
    int nResult = 0;

    //pResult = (char **)malloc(sizeof (char*)*nAlloc);

    nResult = ecall_sqlite3_get_table(global_eid, &rc, &tdb, sql, pResult, Result_len, Row, Col, errmsg, sizeof(pResult),sizeof(errmsg));

    if (nResult != SGX_SUCCESS){
        abort();
    }
    if( rc!=0 ){
      fprintf(stderr,"SQL error: %s\n", errmsg);
    }

    int nIndex = Col;
    for(int i=0;i<Row;i++){
        for(int j=0;j<Col;j++){
            fprintf(stdout,"%s:%s\n",pResult[j],pResult[nIndex]);
            ++nIndex;
        }
    }
fprintf(stdout, "\n-------run with get_table end-----------\n");
#endif /* SGX_GET_TABLE_TEST */

    //sqlite3_close(db);
    if ( (ret = ecall_sqlite3_close(global_eid, &rc, &tdb))!= SGX_SUCCESS ) {
        abort();
    }
    if( rc ){
            if ( (ret = ecall_sqlite3_errmsg(global_eid, &tdb, errmsg, sizeof(errmsg))) 
                    != SGX_SUCCESS ) {
                abort();
            }
            fprintf(stdout, "Can't close database: %s\n", errmsg);
            return(1);
        }
    fprintf(stdout, "DATABASE CLOSED! \n");
    fprintf(stdout,"---SQL Query End----\n");

    /* Destroy the enclave */
sgx_destroy:
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleSQLite3Enclave returned.\n");

    return 0;
}
