#include <stdlib.h>
#include "Enclave_u.h"

char *ocall_getenv(const char *name, int *perrno){
	char *ret = getenv(name);
	*perrno = errno;
	return ret;
}
