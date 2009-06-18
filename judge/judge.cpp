#include <iostream>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <algorithm>

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
#include <sys/wait.h>
#include <sys/signal.h>

#include "judge.h"
#include "misc.h"

using namespace std;

string executive, tmpdir, infile, outfile, spjexec;
int timelimit, memlimit, outlimit, lang;
int result;

/*
 *  使用 ./judge -h 来查看完整的说明
 */
int main(int argc, char *argv[]){

    parse_argv(argc, argv); //解析命令行参数

    init_RF_table(); //初始化对应RF的syscall的表

    if(chdir(tmpdir.c_str()) < 0){
        perror("chdir");
        exit(EXIT_CHDIR);
    }
    dp("chdir ok\n");


    pid_t child = fork();
    if(child < 0){
        //创建新进程出错了 -___-||
        perror("fork");
        exit(EXIT_BAD_FORK);

    }else if(child == 0){
        //子进程
        dp("before redirect\n");

        io_redirect(); //重定向输入/输出/错误

        set_limit(); //设置CPU/MEM/STACK/FSIZE的限制

        set_timer(timelimit); //设置定时器

        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            perror("ptrace(TRACEME)");
            exit(EXIT_PTRACE_TRACEME);
        }

        //载入程序
        execl(executive.c_str(), NULL, NULL);

        //载入出错
        perror("execl");
        exit(EXIT_EXECL);

    }else{
        //父进程
        int status = 0;
        long memuse = 0;
        int orig_eax = 0;
        struct rusage rused;
        struct user_regs_struct regs;

        while(true){
            if(wait4(child, &status, 0, &rused) < 0){
                perror("wait4");
                exit(EXIT_WAIT4);
            }
            //dp("wait ends (%d)\n", status);

            //正常退出
            if(WIFEXITED(status)){
                dp("AC or PE or WA\n");
                if(spjexec.empty()){
                    result = compare(outfile.c_str(), "stdout.txt");
                }else{
                    result = special_judge();
                }
                break;
            }

            //判RF
            if(WIFSIGNALED(status)){
                int sig = WTERMSIG(status);
                dp("sig = %d\n", sig);
                switch(sig){
                    //超时, TLE
                    case SIGALRM:    
                    case SIGXCPU:
                    case SIGKILL:
                        dp("TLE\n");
                        result = OJ_TLE;
                        break;
                    //输出过多，OLE
                    case SIGXFSZ:
                        dp("OLE\n");
                        result = OJ_OLE;
                        break;
                    //RE的各种情况
                    case SIGSEGV:
                        result = OJ_RE_SEGV;
                        break;
                    case SIGFPE:
                        result = OJ_RE_FPE;
                        break;
                    case SIGBUS:
                        result = OJ_RE_BUS;
                        break;
                    case SIGABRT:
                        result = OJ_RE_ABRT;
                        break;
                    default:
                        result = OJ_RE_UNKNOWN;
                        break;
                }
                break; //退出循环
            }

            //（根据Sempr的代码添加的，不理解判断条件）
            if(WEXITSTATUS(status) != 5){
                dp("EXITCODE = %d\n", WEXITSTATUS(status));
                switch(WEXITSTATUS(status)){
                    //超时, TLE
                    case SIGALRM:    
                    case SIGXCPU:
                    case SIGKILL:
                        dp("TLE\n");
                        result = OJ_TLE;
                        break;
                    //输出过多，OLE
                    case SIGXFSZ:
                        dp("OLE\n");
                        result = OJ_OLE;
                        break;
                    //RE的各种情况
                    case SIGSEGV:
                        result = OJ_RE_SEGV;
                        break;
                    case SIGFPE:
                        result = OJ_RE_FPE;
                        break;
                    case SIGBUS:
                        result = OJ_RE_BUS;
                        break;
                    case SIGABRT:
                        result = OJ_RE_ABRT;
                        break;
                    default:
                        result = OJ_RE_UNKNOWN;
                        break;
                }
                kill(child, SIGKILL);
                break; //退出循环
            }

            memuse = max(memuse, rused.ru_minflt * (getpagesize() / 1024));
            //内存使用超过限制 MLE
            if(memuse > memlimit){
                dp("MLE(%dKB)\n", memuse);
                result = OJ_MLE;
                kill(child, SIGKILL);
                break;
            }

            /**/
            //截获SYSCALL并进行检查
            if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
                perror("ptrace(PTRACE_GETREGS)");
                exit(EXIT_PTRACE_GETREGS);
            }

            //禁止的系统调用, RF
            if(regs.orig_eax >= 0 && !is_valid_syscall(regs.orig_eax)){
                dp("RF (SYSCALL = %d)\n", regs.orig_eax);
                result = OJ_RF;
                kill(child, SIGKILL);
                break;
            }

            //继续运行
            if(ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0){
                perror("ptrace(PTRACE_SYSCALL)");
                exit(EXIT_PTRACE_SYSCALL);
            }
        }
    //子进程结束, 统计资源使用, 返回结果
        int timeuse = (rused.ru_utime.tv_sec * 1000 + 
                       rused.ru_utime.tv_usec / 1000);
        dp("[child_ends]\n");
        printf("%d %ld %d\n", 
                result,    memuse,      timeuse);
    }

    return 0;
}

