#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#include "Enclave_u.h"

time_t ocall_time(time_t *t, int *perrno){
	time_t ret = time(t);
	*perrno = errno;
	return ret;
}

int ocall_utimes(const char *filename, const struct timeval times[2], int *perrno){
	int ret =  utimes(filename,times);
	*perrno = errno;
	return ret;
}

int ocall_gettimeofday(struct timeval *tv, int *perrno){
	int ret =  gettimeofday(tv, 0);
	*perrno = errno;
	return ret;
}