
#include <iostream>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <fcntl.h>

#include "misc.h"
#include "judge.h"

using namespace std;

extern string executive, tmpdir, infile, outfile, spjexec;
extern int timelimit, memlimit, outlimit, lang;


void check_add_java_security(string &t){
    string sec = "security.manager";
    int len = (int)t.size(), len1 = (int) sec.size();
    int i, j;
    for (i = 0; i < len - len1 + 1; ++i){
        if(t[i] == 's'){
            for(j = 0; j < len1; ++j){
                if(t[i+j] != sec[j]) break;
            }
            if(j == len1) return;
        }
    }
    t += " -Djava.security.manager";
}

//打印使用信息
void usage(int argc, char *argv[]){
    (void)printf("Usage:\n");
    (void)printf("  %s <cmd> <lang=0~4> <TmpDir> <InFile> <OutFile> " 
                 "<TimeLimit> <MemLimit> <OutLimit> [SPJ]\n",
                 argv[0]);
    (void)printf("The last parameter [SPJ] is optional.\n");
}

//解析参数
void parse_argv(int argc, char *argv[]){

    //检查参数个数是否正确
    if(argc < 9 || argc > 10){
        usage(argc, argv);
        exit(EXIT_BAD_USAGE);
    }

    executive = argv[1]; //可执行程序的完整命令行

    //语言类型
    sscanf(argv[2], "%d", &lang);
    if(lang < 0 || lang > 3){
        fprintf(stderr, "BAD_LANG\n");
        exit(EXIT_BAD_LANG);
    }
    if(lang == 3) { //java
        check_add_java_security(executive);
    }

    tmpdir = argv[3]; //临时文件夹
    infile = argv[4]; //输入测试文件
    outfile = argv[5]; //输出测试文件


    sscanf(argv[6], "%d", &timelimit);
    if(timelimit <= 0){
        fprintf(stderr, "BAD_TIME_LIMIT\n");
        exit(EXIT_BAD_TIME_LIMIT);
    }

    sscanf(argv[7], "%d", &memlimit);
    if(memlimit <= 0){
        fprintf(stderr, "BAD_MEM_LIMIT\n");
        exit(EXIT_BAD_MEM_LIMIT);
    }

    sscanf(argv[8], "%d", &outlimit);
    if(outlimit <= 0){
        fprintf(stderr, "BAD_OUT_LIMIT\n");
        exit(EXIT_BAD_OUT_LIMIT);
    }

    if(argc == 10){
        spjexec = argv[9];
    }

#ifdef DEBUG
    printf("executive = %s\n", executive.c_str());
    printf("lang = %d\n", lang);
    printf("tmpdir = %s\n", tmpdir.c_str());
    printf("infile = %s\n", infile.c_str());
    printf("outfile = %s\n", outfile.c_str());
    printf("timelimit = %d ms\n", timelimit);
    printf("memlimit = %d KB\n", memlimit);
    printf("outlimit = %d KB\n", outlimit);
    printf("spjexec = %s\n", spjexec.c_str());
#endif
}

void dp(const char *fmt, ...){
#ifdef DEBUG
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
#endif
}

void set_limit(){

    rlimit lim;

    //时间限制
    lim.rlim_max = (timelimit + 999) / 1000 + 1; //秒，硬限制向上取整+1
    lim.rlim_cur = (timelimit + 999) / 1000; //软限制向上取整，不加1
    if(setrlimit(RLIMIT_CPU, &lim) < 0){
        perror("setrlimit");
        exit(EXIT_SETRLIMIT_TIME);
    }

    /*

    //内存限制
    //在这里进行内存限制可能导致MLE被判成RE
    //所以改成在每次wait以后判断
    lim.rlim_max = memlimit * 1024;
    lim.rlim_cur = memlimit * 1024;
    if(setrlimit(RLIMIT_AS, &lim) < 0){
        perror("setrlimit");
        exit(EXIT_SETRLIMIT_MEM);
    }

    */

    //堆栈空间限制
    lim.rlim_max = 4 * MEGA; // 4MB
    lim.rlim_cur = 4 * MEGA;
    if(setrlimit(RLIMIT_STACK, &lim) < 0){
        perror("setrlimit");
        exit(EXIT_SETRLIMIT_STACK);
    }

    //输出文件大小限制
    lim.rlim_max = outlimit * 1024;
    lim.rlim_cur = outlimit * 1024;
    if(setrlimit(RLIMIT_FSIZE, &lim) < 0){
        perror("setrlimit");
        exit(EXIT_SETRLIMIT_FSIZE);
    }

    dp("cpu/mem/stack/fsize limit set ok.\n");
}

void io_redirect(){
    //重定向输入
    if(freopen(infile.c_str(), "r", stdin) == NULL){
        perror("freopen(stdin)");
        exit(EXIT_FREOPEN_IN);
    }
    dp("in ok\n");
    //重定向输出
    if(freopen("stdout.txt", "w", stdout) == NULL){
        perror("freopen(stdout)");
        exit(EXIT_FREOPEN_OUT);
    }
    /*
    */

    //重定向错误输出
    if(freopen("stderr.txt", "w", stderr) == NULL){
        perror("freopen(stderr)");
        exit(EXIT_FREOPEN_ERR);
    }
}

void set_timer(){
    struct itimerval now;
    now.it_interval.tv_sec = timelimit / 1000;
    now.it_interval.tv_usec = timelimit % 1000000 + 100000; //放宽100ms
    now.it_value.tv_sec = timelimit / 1000;
    now.it_value.tv_usec = timelimit % 1000000 + 100000;
    //VIRTUAL TIMER, 进程实际执行时间
    if(setitimer(ITIMER_VIRTUAL, &now, NULL) < 0){
        perror("setitimer");
        exit(EXIT_SETITIMER);
    }
    now.it_interval.tv_sec *= 2;
    now.it_value.tv_sec *= 2;
    //REAL TIMER, 系统真实时间(以免sleep卡死)
    if(setitimer(ITIMER_REAL, &now, NULL) < 0){
        perror("setitimer");
        exit(EXIT_SETITIMER);
    }
    dp("setitimer ok.\n");
}

int RF_table[1024];
//C or C++
int LANG_CV[256]={SYS_execve, SYS_read, SYS_uname, SYS_write, SYS_open, SYS_close, SYS_access, SYS_brk, SYS_munmap, SYS_mprotect, SYS_mmap2, SYS_fstat64, SYS_set_thread_area, SYS_exit_group, SYS_exit, 0};
int LANG_CC[256]={1,          -1,       -1,        -1,        -1,       -1,        -1,         -1,      -1,         -1,           -1,        -1,          -1,                  -1,             -1,       0};
//Pascal
int LANG_PV[256]={SYS_execve, SYS_open, SYS_set_thread_area, SYS_brk, SYS_read, SYS_uname, SYS_write, SYS_ioctl, SYS_readlink, SYS_mmap, SYS_rt_sigaction, SYS_getrlimit, SYS_exit_group, SYS_exit, SYS_ugetrlimit, 0};
int LANG_PC[256]={1,          -1,       -1,                  -1,      -1,       -1,        -1,        -1,        -1,           -1,       -1,               -1,            -1,             -1,       -1,             0};
//Java
int LANG_JV[256]={SYS_execve, SYS_ugetrlimit, SYS_rt_sigprocmask, SYS_futex, SYS_read, SYS_mmap2, SYS_stat64, SYS_open, SYS_close, SYS_access, SYS_brk, SYS_readlink, SYS_munmap, SYS_close, SYS_uname, SYS_clone, SYS_uname, SYS_mprotect, SYS_rt_sigaction, SYS_sigprocmask, SYS_getrlimit, SYS_fstat64, SYS_getuid32, SYS_getgid32, SYS_geteuid32, SYS_getegid32, SYS_set_thread_area, SYS_set_tid_address, SYS_set_robust_list, SYS_exit_group, 0};
int LANG_JC[256]={2,          -1,            -1,                 -1,        -1,        -1,        -1,         -1,       -1,        -1,         -1,      -1,           -1,         -1,        -1,        1,         -1,        -1,           -1,               -1,              -1,            -1,          -1,           -1,           -1,            -1,            -1,                  -1,                  -1,                  -1,              0};

void init_RF_table(){
    int i;
    memset(RF_table, 0, sizeof(RF_table));
    if (lang == 0 || lang == 1){ // C & C++
        for (i = 0; LANG_CV[i]; i++) {
            RF_table[LANG_CV[i]]=LANG_CC[i];
        }
    }else if (lang == 2){ // Pascal
        for (i = 0; LANG_PV[i]; i++) {
            RF_table[LANG_PV[i]]=LANG_PC[i];
        }
    }else if (lang == 3){ // Java
        for (i = 0; LANG_JV[i]; i++) {
            RF_table[LANG_JV[i]]=LANG_JC[i];
        }
    }else{
        dp("BAD lang");
    }
}

bool is_valid_syscall(int num){
    static int in_syscall = 0;
    in_syscall = 1 - in_syscall;
    //dp("%d (%s)\n", num, in_syscall? "in" : "out");
    if(RF_table[num] == 0) {
        return false;
    } else{
        if(in_syscall == 0){
            RF_table[num]--;
        }
    }
    return true;
}

class filereader{
private:
    int fd;
    char buf[1024];
    int cnt;
    int pt;
    char get(){
        if(pt + 1 == cnt) cnt = 0;
        if(cnt == 0){
            pt = -1;
            cnt = read(fd, buf, 1024);
            if(cnt < 0){
                perror("read(filereader)");
                exit(EXIT_FILEREADER_READ);
            }
            if(cnt == 0){
                return -1;
            }
        }
        pt++;
        return buf[pt];
    }
public:
    filereader(const char *filename){
        fd = open(filename, O_RDONLY);
        if(fd < 0){
            perror("open(filereader)");
            exit(EXIT_FILEREADER_OPEN);
        }
        pt = -1;
        cnt = 0;
    }

    char next(){
        char t = '\r';
        while(t != -1 && t == '\r') t = get();
        return t;
    }
    void ret(){
        pt--;
    }
    ~filereader(){
        if(close(fd) < 0){
            perror("close(filereader)");
            exit(EXIT_FILEREADER_CLOSE);
        }
    }
};

bool isblank(char &t1){
    return 
      (t1 == ' '  ||
       t1 == '\t' ||
       t1 == '\r' ||
       t1 == '\n');
}

// RETURN: OJ_AC, OJ_PE, OJ_WA
int compare(const char * f1, const char * f2){
    filereader a(f1), b(f2);
    int ac = 1;
    char t1, t2;
    while(true){
        t1 = a.next();
        t2 = b.next();
        if(t1 == -1 || t2 == -1) break;
        if(ac == 1){
            if(t1 == t2){
                continue;
            }else /* t1 != t2 */ {
                if(isblank(t1) || isblank(t2)){
                    ac = 0;
                    a.ret();
                    b.ret();
                    continue;
                }else{
                    return OJ_WA;
                }
            }
        }else{
            while(t1 != -1 && isblank(t1)) t1 = a.next();
            while(t2 != -1 && isblank(t2)) t2 = b.next();
            if(t1 == -1 || t2 == -1) break;
            if(t1 != t2){
                return OJ_WA;
            }
        }
    }
    if(t1 != -1 || t2 != -1) ac = 0;
    while(t1 != -1 && isblank(t1)) t1 = a.next();
    while(t2 != -1 && isblank(t2)) t2 = b.next();

    if(t1 == -1 && t2 == -1){
        if(ac == 1){
            return OJ_AC;
        }else{
            return OJ_PE;
        }
    }else{
        return OJ_WA;
    }
}
