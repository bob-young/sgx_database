#ifndef _SPEED_H_
#define _SPEED_H_

#include <stdio.h>
#include <unistd.h>     // usleep();
#include <stdlib.h>     // exit();
#include <string.h>     // memset();
#include <sys/time.h>   // gettimeofday();
#include "../Include/user_types.h"
#include "../Enclave/sqlite3.h"

#include <time.h>
#include <fcntl.h>
//#include <sys/time.h>
typedef struct timespec timespec;

//
#include "Enclave_u.h"
#include "sgx_error.h"
#include "sgx_eid.h"
#include "sqlite3Client.h"

/* ********************************************** */

typedef enum {
    DUMMY,
    AUTOMODE,
    MANUALMODE
} RUNMODE;

RUNMODE runmode;


/* ********************************************** */

struct timeval tv1, tv2;

struct data_rt
{
    unsigned short  di;
    int             mp_no;
    unsigned char   data[8];
    long int        rec_time;
    unsigned char   data_type;
};

FILE *fp;
FILE *fclosetime;
FILE * pFile;
#define logPath "test/test.log"
#if defined(__cplusplus)
extern "C" {
#endif
//int oss_test(const char *logPath, const char *sqlPath);
	int oss_test(const char *sqlPath);

#if defined(__cplusplus)
}
#endif


#endif

