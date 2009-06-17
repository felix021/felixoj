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

/*
 * Judge入口
 * 命令行包含6个参数
 * 1. 需要执行的程序(如果是java，则需要包含完整的java ooox命令行
 * 2. 语言类型(0 = C, 1 = C++, 2 = pascal, 3 = Java)
 * 3. 临时文件夹 (用于存储程序输出)
 * 4. 输入文件 (如data/1001/test.in)
 * 5. 输出文件 (如data/1001/test.out)
 * 6. 时间限制，毫秒为单位
 * 7. 内存限制，KB 为单位
 * 8. 输出大小限制，KB 为单位
 * 9. SPJ程序命令行，如不提供则表示不是SPJ
 *
 * SPJ: 
 *   接口: 输出1, 2, 4分别表示AC, PE, WA
 *         5s内返回0表示正常，否则judge将强行结束spj，并返回System Error
 *
 * Example:
 * 非SPJ
 *   ./judge "/oj/tmp/9527/a.out" "/oj/tmp/9527" 
 *       "/oj/data/1001/test.out" "/oj/data/1001/test.in" 
 *       1000 65536 512
 * SPJ
 *   ./judge "/oj/tmp/9527/a.out" "/oj/tmp/9527"
 *       "/oj/data/1001/test.out" "/oj/data/1001/test.in" 
 *       1000 65536 512 "/oj/data/1001/spj"
 */

string executive, tmpdir, infile, outfile, spjexec;
int timelimit, memlimit, outlimit, lang;
int result;

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
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            perror("ptrace(TRACEME)");
            exit(EXIT_PTRACE_TRACEME);
        }
        dp("ptrace me OK.\n");
        
        dp("before redirect\n");
        io_redirect(); //重定向输入/输出/错误

        usleep(1000); //延迟1ms
        set_limit(); //设置CPU/MEM/STACK/FSIZE的限制
        set_timer(); //设置定时器


        dp("Run: %s\n", executive.c_str());
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
            wait4(child, &status, 0, &rused);
            //dp("wait ends (%d)\n", status);

            //正常退出
            if(WIFEXITED(status)){
                dp("AC or PE or WA\n");
                result = compare(outfile.c_str(), "stdout.txt");
                goto child_ends;
            }

            //收到一个信号退出
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
                goto child_ends;
            }

            memuse = max(memuse, rused.ru_minflt * (getpagesize() / 1024));
            //内存使用超过限制 MLE
            if(memuse > memlimit){
                dp("MLE(%dKB)\n", memuse);
                result = OJ_MLE;
                kill(child, SIGKILL);
                goto child_ends;
            }

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
                goto child_ends;
            }

            //继续运行
            if(ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0){
                perror("ptrace(PTRACE_SYSCALL)");
                exit(EXIT_PTRACE_SYSCALL);
            }
        }
    //子进程结束, 统计资源使用, 返回结果
    child_ends:
        int timeuse = (rused.ru_utime.tv_sec * 1000 + 
                       rused.ru_utime.tv_usec / 1000);
        dp("[child_ends]\n");
        printf("%d, mem(%ld), time(%d)\n", 
                result,    memuse,      timeuse);
    }

    return 0;
}

