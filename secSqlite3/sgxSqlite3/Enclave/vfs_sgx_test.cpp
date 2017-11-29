#ifdef VFS_SGX_TEST
#include <stdarg.h>
#include <string.h>
#include "vfslib/stdio.h"
#include "vfslib/stat.h"
#include "vfslib/fcntl.h"
#include "vfslib/unistd.h"
#include "vfslib/stdlib.h"
#include "vfslib/time.h"
#include "vfslib/mman.h"
#include "vfs_sgx_test.h"

#define TEST_FOLDER "./test/"
#define LEN_TEST_FOLDER 7

int vfs_sgx_fcntl_test(){
	fprintf(stdin, "------Fcntl Start------\n");
	int fd = -1;
	unsigned long filesize = -1;
	char fname[60] = {'\0'};
	strncpy(fname, TEST_FOLDER, LEN_TEST_FOLDER);
	strncat(fname, "test.txt", 8);

	fprintf(stdout, "test open \n");

	if((fd = open(fname, O_RDWR|O_CREAT, 0666)) == -1){
		fprintf(stdout, "Can't creat file: %s\n", fname);
		return -1;
	}
	fprintf(stdout, "open sucess! fd=%d\n",fd);

	fprintf(stdout, "test fallocate \n");
	//manipulate file space
	int file_size=2097152; //2M
	if(fallocate(fd, 0, 0, file_size) == -1){
		fprintf(stderr, "fallocate error.\n");
		return -1;
	}
	fprintf(stdout, "fallocate sucess!\n");
	close(fd);

	fprintf(stdout, "test fcntl \n");
	// pid_t pid;
    //以追加的形式打开文件
    fd = open(fname, O_RDWR | O_APPEND | O_CREAT, 0777);
    if(fd < 0)
    {
    	fprintf(stderr, "open error.\n");
        return -1;
    }
    fprintf(stdout, "fd = %d\n", fd);
    if(fcntl(fd, F_SETFD, 0) == -1){
    	fprintf(stderr, "fcntl error.\n");
        return -1;
    };//关闭fd的close-on-exec标志
    write(fd, "hello c program!\n", strlen("hello c program!\n"));
    close(fd);

    if ( unlink(fname) != 0 ){
    	fprintf(stderr, "unlink() test failed : %s \n", fname);
    	return -1;
    }

    fprintf(stdout, "fcntl sucess!\n");

	fprintf(stdout, "------Fcntl End------\n\n");
    return 0;
}

// int vfs_sgx_mman_test(){
// fprintf(stdout, "------Mman Start------\n");
// 	void *s,*x;
//     x=malloc(8192);     
//     //x = reinterpret_cast<size_t>(x) + 0x1000;
//     //x = reinterpret_cast<size_t>(x) & 0xfffff000;
//     s=(void *)mremap(x,4000,8,0);
 
//     //perror("mremap");
//     fprintf(stdout,"old 0x%x new 0x%x\n",x,s);
// 	fprintf(stdout, "test mmap & munmap \n");
// 	int fd;  
//     void* buf;  
//     int i;
// 	struct stat statbuf;  
//     if(stat("test.txt",&statbuf)==-1){  
//         //文件不存在  
//         fprintf(stdout,"fail to get stat!!!!!\n");  
//         return -1;  
//     }  
//     fd = open("test.txt",O_RDONLY,0666);  
//     if(fd == -1){  
//         fprintf(stdout,"fail to open!!!!!\n");  
//         return -1;  
//     }  
//     //建立内存映射,)用来将某个文件内容映射到内存中，对该内存区域的存取即是直接对该文件内容的读写。  
//     buf = mmap(NULL,statbuf.st_size,PROT_READ,MAP_PRIVATE,fd,0); 
//     //fprintf(stdout,"  %s",buf); 
//     if(buf == (void *)MAP_FAILED){  
//         fprintf(stdout,"fail to mmap!!!!!!\n");  
//         return -1;  
//     }
//     i = 0;  
//     //while(i<statbuf.st_size){  
//     //     fprintf(stdout,"%c",buf[i]);  
//     //     i++;  
//     // }  
//     //fprintf(stdout,"\n");  
//     //解除内存映射  
//     if(munmap(buf,statbuf.st_size) == -1){  
//         fprintf(stdout,"fail to munmap!!!!!\n");  
//         return -1;  
//     }  
//     close(fd);  
//     fprintf(stdout, "mmap & munmap sucess!\n");
// 	 	fprintf(stdout, "------Mman End------\n\n");
// 	return 0;
// }

int vfs_sgx_stat_test(){
	fprintf(stdout, "------Stat Start------\n");

	int ret = 1;
    struct stat buf;
    int to_fd;
	char fname[60] = {'\0'};
	char pname[60] = {'\0'};
	strncpy(fname, TEST_FOLDER, LEN_TEST_FOLDER);
	strncat(fname, "aaabbb", 6);
	strncpy(pname, TEST_FOLDER, LEN_TEST_FOLDER);
	strncat(pname, "ddd", 3);
    to_fd = open(fname, O_RDWR|O_CREAT, 0666);
    if ( (ret = stat(TEST_FOLDER,&buf)) != 0 ) { 
    	fprintf(stderr, "stat() test failed : %s \n", TEST_FOLDER);
	}
    if(ret != 0){
    	fprintf(stderr,"The test of stat() is failed------!\n");
    	return -1;
    }
    	
    ret = fstat(to_fd,&buf);
    if(ret != 0){
    	fprintf(stderr,"fstat() test failed: %s \n", fname);
    	return -1;
    }
    ret = fchmod(to_fd,S_IRWXU);
    if(ret != 0){
    	fprintf(stderr,"The test of fchmod() is failed------!\n");
    	return -1;
    }
    //ret = fchmod(to_fd,00666);
    ret = mkdir(pname,0777);
    if(ret != 0){
    	fprintf(stderr,"The test of mkdir() is failed------!\n");
    	return -1;
    }

    //rmdir test
	if (rmdir(pname) != 0){
		fprintf(stderr,"rmdir() test failed : %s \n", pname);
		return -1;
	}


    if ( unlink(fname) != 0 ){
    	fprintf(stderr, "unlink() test failed : %s \n", fname);
    	return -1;
    }

	fprintf(stdout, "------Stat End------\n\n");
	return 0;
}

int vfs_sgx_stdlib_test(){
	fprintf(stdout, "------Stdlib Start------\n");

	char *s= NULL;
	s=getenv("USER"); /* get the comspec environment parameter */
	fprintf(stdout, "Command processor: %s, Getenv is OK!\n",s); /* display comspec parameter */

	fprintf(stdout, "------Stdlib End------\n\n");
	return 0;
}

int vfs_sgx_time_test(){
	fprintf(stdout, "------Time Start------\n");

	int seconds = 0; 
	int to_fd;
	struct timeval tv[2];
	char fname[60] = {'\0'};
	strncpy(fname, TEST_FOLDER, LEN_TEST_FOLDER);
	strncat(fname, "aaabbb", 6);
	int ret = 1;
	seconds = time((time_t*)NULL);
	fprintf(stdout, "%d\n", seconds);
    to_fd = open(fname, O_RDWR|O_CREAT, 0666);
    ret = utimes(fname, tv);
    fprintf(stdout, "tv[0].tv_sec = %ld\n", tv[0].tv_sec);
    fprintf(stdout, "tv[0].tv_usec = %ld\n", tv[0].tv_usec);
    fprintf(stdout, "tv[1].tv_sec = %ld\n", tv[1].tv_sec);
    fprintf(stdout, "tv[1].tv_usec = %ld\n", tv[1].tv_usec);
    
    fprintf(stdout, "test gettimeofday\n");
	struct timeval start;
	if(gettimeofday(&start,NULL) !=0){
		fprintf(stderr, "gettimeofday error!!!!!!!!\n");
		return -1;
	} //gettimeofday(&start,&tz);结果一样
	fprintf(stdout, "  start.tv_sec:%d\n",start.tv_sec);
	fprintf(stdout, "  start.tv_usec:%d\n",start.tv_usec);
	fprintf(stdout, "gettimeofday sucess!\n");

    if ( unlink(fname) != 0 ){
    	fprintf(stderr, "unlink() test failed : %s \n", fname);
    	return -1;
    }

	fprintf(stdout, "------Time End------\n\n");
	return 0;
}

int vfs_sgx_unistd_test(){
	fprintf(stdout, "------Unistd Start------\n");

	int to_fd = 0;
	char buf_cwd[80];
	char ch_in[10] = "123456789";
	char ch_out[10] = {'\0'};

	char fname[60] = {'\0'};
	strncpy(fname, TEST_FOLDER, LEN_TEST_FOLDER);
	strncat(fname, "test.txt", 8);


	char fname2[60] = {'\0'};
	strncpy(fname2, TEST_FOLDER, LEN_TEST_FOLDER);
	strncat(fname2, "aaabbb", 6);

	char fname3[60] = {'\0'};
	strncpy(fname3, TEST_FOLDER, LEN_TEST_FOLDER);
	strncat(fname3, "unlink.txt", 10);


	char pname[60] = {'\0'};
	strncpy(pname, TEST_FOLDER, LEN_TEST_FOLDER);
	strncat(pname, "a", 1);

	if((to_fd = open(fname, O_RDWR|O_CREAT, 0666)) == -1){
		fprintf(stderr, "Can't open file: %s\n", fname);
		return -1;
	}
	//read
	//read(to_fd, ch_out, 6);
	//~~  Should be tested thoroughly!
	//TODO!
	fprintf(stdout, "read: %d, read is OK!\n", read(to_fd, ch_out, 6));

	//write
	//write(to_fd, "hahaha", 6);
	//~~  Should be tested thoroughly!
	//TODO!
	fprintf(stdout, "write: %d, write is ok!\n", write(to_fd, "hahaha", 6));

	//fchown test
	if(fchown(to_fd,1000,1000) != 0) {
		fprintf(stderr,"Fchown is not OK!\n");
		return -1;
	}

	//getcwd test
	getcwd(buf_cwd, sizeof(buf_cwd));
	fprintf(stdout, "cwd: %s, ", buf_cwd);
	fprintf(stdout, "Getcwd is OK!\n");

	int fd_ftruncate;
	if((fd_ftruncate = open(fname2, O_RDWR|O_CREAT, 0666)) == -1){
		fprintf(stderr, "Can't open file: %s\n", "test/test.txt");
		return -1;
	}
	//truncate test
	if(truncate(fname2,64) != 0) {
		fprintf(stderr,"Truncate is not OK!\n");
		return -1;
	}
	//ftruncate test
	if(ftruncate(fd_ftruncate, 4) != 0) {
		fprintf(stderr,"Ftruncate is not OK!\n");
		return -1;
	}


    if ( unlink(fname2) != 0 ){
    	fprintf(stderr, "unlink() test failed : %s \n", fname2);
    	return -1;
    }

	//pread test
	//pread(to_fd, ch_out, 6, 2);
	fprintf(stdout, "pread: %d, pread is OK!\n", pread(to_fd, ch_out, 6, 2));
	//fprintf(stdout, "haha: %s\n", ch_out);

	//pwrite test
	//pwrite(to_fd, haha, 10, 2);
	fprintf(stdout, "pwrite: %d, pwrite is OK!\n", pwrite(to_fd, ch_in, 10, 2));	


	int unlink_fd;
	if((unlink_fd = open(fname3, O_RDWR|O_CREAT, 0666)) == -1){
		fprintf(stderr, "Can't open file: %s\n", fname3);
		return -1;
	}
	//access test
	int status = access(fname3,0);
    if (status != 0){
		fprintf(stderr,"access() test failed : %s \n", fname3);
		return -1;
    }


	//unlink test
	unlink(fname3);
	status = access(fname3,0);
    if (status == 0){
        fprintf(stderr,"unlink() test failed : %s \n", fname3);
        return -1;
    }
    else{
		fprintf(stdout,"File doesn't exist, unlink is OK!\n");
    }

	//rmdir test
	if (mkdir(pname,777) != 0){
		fprintf(stderr,"mkdir() test failed : %s \n", pname);
		return -1;
	}
	if(rmdir(pname) != 0){
		fprintf(stderr,"rmdir() test failed : %s \n", pname);
		return -1;
	}

	//geteuid test
	fprintf(stdout,"The effective user ID of the calling process is: %d, geteuid is OK!\n", geteuid());

	//lseek test
	off_t currpos;
	if (currpos = lseek(to_fd, 0, SEEK_CUR) != -1){
		fprintf(stdout,"The current file offset is: %d, Lseek is OK!\n", currpos);
	}
	else{
		fprintf(stdout,"Lseek is not OK!\n");
		return -1;	
	}

	//fsync tst
	if (fsync(to_fd) != 0){
		fprintf(stdout,"Fsync is not OK!\n");
		return -1;
	}

	//getpid test
	fprintf(stdout,"The process ID of the calling process is: %d, getpid is OK!\n", getpid());

	//sleep test
	if (sleep(3) != 0){
		fprintf(stdout,"Sleep is not OK!\n");
		return -1;
	}

	if (close(to_fd) != 0){
		fprintf(stdout,"Close is not OK!\n");
		return -1;
	}


    if ( unlink(fname) != 0 ){
    	fprintf(stderr, "unlink() test failed : %s \n", fname);
    	return -1;
    }

	fprintf(stdout, "------Unistd End------\n\n");
	return 0;
}

int vfs_sgx_test(){
	fprintf(stdout, "---Start Testing------\n\n");

    if( vfs_sgx_fcntl_test() != 0 ) {
		fprintf(stderr, "------    Fcntl Error, Test Failed------\n");
		return -1;
    }


	// if( vfs_sgx_mman_test() != 0 ) {
	// 	fprintf(stderr, "------    Mman Error, Test Failed------\n");
	// }

    if( vfs_sgx_stat_test() != 0 ) {
		fprintf(stderr, "------    Stat Error, Test Failed------\n");
		return -1;
    }


    if( vfs_sgx_stdlib_test() != 0 ) {
		fprintf(stderr, "------    Stdlib Error, Test Failed------\n");
		return -1;
    }


    if( vfs_sgx_time_test() != 0 ) {
		fprintf(stderr, "------    Time Error, Test Failed------\n");
		return -1;
    }


    if( vfs_sgx_unistd_test() != 0) {
		fprintf(stderr, "------    Unistd Error, Test Failed------\n");
		return -1;
    }
	
	fprintf(stdout, "---End Testing------\n\n");
	return 0;
}

#endif  /* VFS_SGX_TEST */