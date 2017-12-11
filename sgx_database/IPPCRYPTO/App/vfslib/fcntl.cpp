#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "Enclave_u.h"

int ocall_open(const char* filename, int flags, mode_t mode, int *perrno) {
    int ret = open(filename, flags, mode);
	*perrno = errno;
	return ret;
}

int ocall_fallocate(int fd, int mode, off_t offset, off_t len, int *perrno){
	int ret = fallocate(fd, mode, offset, len);
	*perrno = errno;
	return ret;	
}
int ocall_fcntl_flock(int fd, int cmd, struct flock *p, int *perrno){
	int ret = fcntl(fd, cmd, p); 
	*perrno = errno;
	return ret;
}
int ocall_fcntl_void(int fd, int cmd, int *perrno){
	int ret = fcntl(fd, cmd); 
	*perrno = errno;
	return ret;
}
int ocall_fcntl_int(int fd, int cmd, int pa, int *perrno){
	int ret = fcntl(fd, cmd, pa); 
	*perrno = errno;
	return ret;
}
