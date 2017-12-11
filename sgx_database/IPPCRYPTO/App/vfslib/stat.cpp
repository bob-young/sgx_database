#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "Enclave_u.h"
//int ocall_stat([in, string]const char *pathname, [in, size=size]void *buf, unsigned int size)
//ocall_stat, (const char* pathname, void* buf, unsigned int size)


int ocall_stat(const char *pathname, struct stat *buf,int *perrno){
	int ret = stat(pathname,buf);
	*perrno = errno;
	return ret;
}

int ocall_fstat(int fd, struct stat *buf,int *perrno){
	int ret = fstat(fd,buf);
	*perrno = errno;
	return ret;
}

int ocall_fchmod(int fd, mode_t mode,int *perrno){
	int ret = fchmod(fd,mode);
	*perrno = errno;
	return ret;
}

int ocall_mkdir(const char* pathname, mode_t mode,int *perrno){
	int ret = mkdir(pathname,mode);
	*perrno = errno;
	return ret;
}

