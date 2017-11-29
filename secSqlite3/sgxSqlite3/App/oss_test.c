#include "oss_test.h"
/* ********************************************** */

#define DBFILE "tpch"

/* ********************************************** */

static void time_test (char *que);
int rc;

/* ********************************************** */
static timespec time_start, time_stop;
static timespec time_diff(timespec start, timespec end)
{
   timespec temp;
   if ((end.tv_nsec-start.tv_nsec)<0) {
      temp.tv_sec = end.tv_sec-start.tv_sec-1;
      temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
   } else {
      temp.tv_sec = end.tv_sec-start.tv_sec;
      temp.tv_nsec = end.tv_nsec-start.tv_nsec;
   }
   return temp;
}
static void start_timing(){
    printf("Timming Start\n");
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_start);
}
static void stop_timing(){
    timespec delta_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_stop);
    printf("Timming End\n");
    delta_time = time_diff(time_start, time_stop);

   // FILE * fExpRlt = fopen(expRltFile, "a");
/*    if (!fp) {
        fprintf(stderr, "File not found.\n");
            exit(0);
     }*/

    fprintf(fp, "%f \n",
               delta_time.tv_sec +
               (double)delta_time.tv_nsec / 1000000000);
    //fclose(fExpRlt);
}
static void stop_timing_close(){
    timespec delta_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_stop);
    printf("Timming End\n");
    delta_time = time_diff(time_start, time_stop);

   // FILE * fExpRlt = fopen(expRltFile, "a");
/*    if (!fp) {
        fprintf(stderr, "File not found.\n");
            exit(0);
     }*/

    fprintf(fclosetime, "%f \n",
               delta_time.tv_sec +
               (double)delta_time.tv_nsec / 1000000000);
    //fclose(fExpRlt);
}


static void print_error (int ret, char *op, struct tDB *db)
{
    char errmsg[50] = {'\0'};
    ecall_sqlite3_errmsg (global_eid, db, errmsg, sizeof(errmsg));
    if (ret != SQLITE_OK)
    {
        fprintf (stderr, "ERROR IN %-30s: %d, %s\n", op, ret, errmsg);
        exit (ret);
    }
}

static void auto_mode (char *sqlname)
{
    printf ("---------------------------------time test start!------------------------------\n");
    usleep (1000000);

    int file_size;
    char *que;

    pFile = fopen(sqlname , "r");
    fseek( pFile , 0 , SEEK_END );
    file_size = ftell( pFile );

    fseek( pFile , 0 , SEEK_SET);
    que =  (char *)malloc( file_size * sizeof( char ) );
    if(fread( que, file_size, sizeof(char) , pFile)==0){
        exit(0);
    }
    que[file_size]='\0';
    // printf("%s" , que);
    //fprintf (fp, "%s --------------------------------------start!\n", sqlname);    
    //start_timing();
    time_test (que);
    //stop_timing();
    //fprintf (fp, "-----------------------------------------end! -------------------------- bye!!!!\n");
    free(que);
    printf ("---------------------------------time test end!------------------------------\n");

}
/* ********************************************** */

/* ********************************************** */

static void time_test (char *que)
{
    int ret = -1;
    char errmsg[50] = {'\0'};
    char errmsg1[50] = {'\0'};

    struct tDB db;
    //printf("~~\n");
    //ecall_sqlite3_exec (global_eid, &ret, &db, "pragma key='tpch';", errmsg, sizeof(errmsg));//
    //print_error (ret, "core_write(), ecall_sqlite3_exec()", &db);
    //printf("~~\n");
    // start_timing();
    ecall_sqlite3_open (global_eid, &ret, DBFILE, &db);
    // stop_timing();

    print_error (ret, "time_test(), ecall_sqlite3_open()", &db);

    ecall_sqlite3_exec (global_eid, &ret, &db, "pragma key='tpch';", errmsg, sizeof(errmsg));//
    print_error (ret, "time_test(), exec pragma", &db);

    //ret = gettimeofday (&tv1, NULL);
    start_timing();
    ecall_sqlite3_exec (global_eid, &ret, &db, que, errmsg1, sizeof(errmsg1));
    //ret = gettimeofday (&tv2, NULL);
    stop_timing();
    print_error (ret, "time_test(), exec sql", &db);
    //printf("Test Complete!\n" );
/*    if (AUTOMODE == runmode)
        fprintf (fp, "normal, one spend: %6dus\n", (int)((tv2.tv_sec - tv1.tv_sec)*1000000 + (tv2.tv_usec - tv1.tv_usec)) );*/
    // start_timing();
    ecall_sqlite3_close (global_eid, &ret, &db);
    // stop_timing_close();

    print_error (ret, "time_test(), ecall_sqlite3_close()", &db);
}

/* ********************************************** */

int oss_test(const char *sqlPath)
{
    char sqlname[80];
    strcpy (sqlname, sqlPath);
    //printf("~~\n");
    fp = fopen(logPath, "a+");
    fclosetime = fopen("test/close.log", "a+");
    if (!fp) {
        fprintf(stderr, "File not found.\n");
            exit(0);
    }
    auto_mode (sqlname);
    //printf("~~\n");
    fclose(fp);
    // pFile = fopen("encry_time.log", "a+");
    // fclose(pFile);

    //printf("~~\n");
    return 0;
    //printf("~~\n");
}
