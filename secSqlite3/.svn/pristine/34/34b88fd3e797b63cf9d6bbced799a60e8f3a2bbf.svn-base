#include <stdio.h>
#include "Enclave_u.h"

int ocall_remove(const char *pathname, int *perrno){
	int ret = remove(pathname);
    *perrno = errno;
    return ret;
}