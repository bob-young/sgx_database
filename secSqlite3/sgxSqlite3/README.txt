------------------------
Purpose of sgxSqlite3
------------------------
The project demonstrates several fundamental usages of Intel(R) Software Guard 
Extensions (SGX) SDK:
- Initializing and destroying an enclave
- Creating ECALLs or OCALLs
- Calling trusted libraries inside the enclave

------------------------------------
How to Build/Execute the sgxSqlite3 Code
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:
    a. Simulation Mode, Debug build:
	//Disable Sqlite3 support
        $ make SQLITE3_SUPPORT=0
	//Enable Sqlite3 support, Default.
	$ make SQLITE3_SUPPORT=1
	or
	$ make
    b. Simulation Mode, Pre-release build:
        $ make SGX_PRERELEASE=1 SGX_DEBUG=0
    c. Simulation Mode, Release build:
        $ make SGX_DEBUG=0
    d. Hardware Mode, Debug build:
        $ make SGX_MODE=HW
    e. Hardware Mode, Pre-release build:
        $ make SGX_MODE=HW SGX_PRERELEASE=1 SGX_DEBUG=0
    f. Hardware Mode, Release build:
        $ make SGX_MODE=HW SGX_DEBUG=0
3. Execute the binary directly:
    $ ./sqlite3Client
4. Remember to "make clean" before switching build mode



----------------------
For Debuge in Enclave
[Notice: You can change the name of debug.bp to any file you like.]
$ sgx-gdb -ex "set breakpoint pending on" ./sqlite3Client
(gdb) source debug.bp
(gdb) start

...Do your debuging...
...
...
...
...If you set some meaningful breakpoints, you can save those breakponts using command below:
(gdb) save breakpoint debug.db



----------------------
For Coding...
-----This is just a TRADEOFF to solve the proble of using some definitions only in Enclave environment facing EDL file.
-----In file /opt/intel/sgxsdk/include/tlibc/sys/types.h 
-----after
#ifndef _SYS_TYPES_H_
#define _SYS_TYPES_H_
-----add a newline
#define __VIVI_SGX_IN_ENCLAVE__



----------------------
For Comparation with unmodified Sqlite3
To support readline:
#sudo apt-get install libreadline-dev  #安装readline模块
Build sqlite3 from source file of sqlite3.org
#gcc -O0 -g -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_OMIT_LOCALTIME -DSQLITE_DEFAULT_MMAP_SIZE=0 -DHAVE_READLINE shell.c sqlite3.c -ldl -lreadline -lncurses -o sqlite

------------------------
加密database
Makefile: SQLITE3_OPT_CONFIG := -DSQLITE_HAS_CODEC
指令：
./sqlite3Client test.db "pragma key='test'; create table t1 (id int, name char(8));" -crypt_ctr
./sqlite3Client test.db "pragma key='test'; insert into t1 values (1,'scc');" -crypt_ctr
./sqlite3Client test.db "pragma key='test'; select * from t1;" -crypt_ctr
hexdump -C test.db
-----------------------
TIME_TEST in sqlite3Client.CPP r65: #define SGX_SQLITE_TIME_TEST
ENC_DEC_TIME_TEST in user_types.h r38: #define SGX_ENC_DEC_TIME_TEST


