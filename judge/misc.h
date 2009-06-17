#ifndef __MISC_H__
#define __MISC_H__

#include <iostream>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <stdarg.h>

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

void usage(int argc, char *argv[]);
void parse_argv(int argc, char *argv[]);
void dp(const char *fmt, ...);
void set_limit();
void io_redirect();
void set_timer();
void init_RF_table();
bool is_valid_syscall(int num);
int compare(const char *f1, const char*f2);

#endif
