#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "Enclave_u.h"
#include <stdio.h>
// #include "../sqlite3Client.h"

ssize_t ocall_read(int file, void *buf, size_t count, int *perrno) {
    ssize_t ret = read(file, buf, count);
    *perrno = errno;
    return ret;
}
ssize_t ocall_write(int file, const void *buf, size_t count, int *perrno) {
    ssize_t ret = write(file, buf, count);
    *perrno = errno;
    return ret;
}

int ocall_close(int fd, int *perrno) {
    int ret = close(fd);
    *perrno = errno;
    return ret;
}

int ocall_fchown(int fd, uid_t owner, gid_t group, int *perrno) {
    int ret = fchown(fd, owner, group);
    *perrno = errno;
    return ret;
}
char *ocall_getcwd(char *buf, size_t size, int *perrno){
	char *ret = getcwd(buf,size);
    *perrno = errno;
    return ret;
}
int ocall_truncate(const char *path, off_t length, int *perrno){
	int ret = truncate(path, length);
    *perrno = errno;
    return ret;
}

int ocall_ftruncate(int fd, off_t length, int *perrno){
	int ret = ftruncate(fd, length);
    *perrno = errno;
    return ret;
}
ssize_t ocall_pread(int fd, void *buf, size_t count, off_t offset, int *perrno){
	ssize_t ret = pread(fd, buf, count, offset);
    *perrno = errno;
    return ret;
}
ssize_t ocall_pwrite(int fd, const void *buf, size_t count, off_t offset, int *perrno){
	int ret = pwrite(fd, buf, count, offset);
    *perrno = errno;
    return ret;
}
int ocall_access(const char* pathname, int mode, int *perrno) {
    int ret = access(pathname,  mode);
    *perrno = errno;
    return ret;
}
int ocall_unlink(const char *pathname, int *perrno){
	int ret = unlink(pathname);
	*perrno = errno;
	return ret;
}
int ocall_rmdir(const char *pathname, int *perrno){
	int ret = rmdir(pathname);
    *perrno = errno;
    return ret;
}
uid_t ocall_geteuid(void){
	return geteuid();
}
//uid_t ocall_getuid(void){
//	return getuid();
//}
off_t ocall_lseek(int fd, off_t offset, int whence, int *perrno){
	off_t ret = lseek(fd, offset, whence);
    *perrno = errno;
    return ret;
}
int ocall_fsync(int fd, int *perrno){
	int ret = fsync(fd);
    *perrno = errno;
    return ret;
}
pid_t ocall_getpid(void){
	return getpid();
}
unsigned int ocall_sleep(unsigned int seconds){
	return sleep(seconds);
}

void *ocall_memcpy(void *dest, const void *src, size_t n){
    return memcpy(dest,src,n);
}

char *ocall_strcat(char *dest, size_t count, const char *src){
    return strcat(dest,src); 
};

