#ifndef VFS_SGX_TEST_H
#define VFS_SGX_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

int vfs_sgx_fcntl_test();

int vfs_sgx_stat_test();

int vfs_sgx_stdlib_test();

int vfs_sgx_time_test();

int vfs_sgx_unistd_test();

int vfs_sgx_test();

#ifdef __cplusplus
}
#endif

#endif /* VFS_SGX_TEST_H */