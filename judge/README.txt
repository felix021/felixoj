编译环境要求:
1. Linux (因为ptrace)
2. g++ (因为用c++ =.=)
3. make (因为有Makefile =.=，当然如果你会手工编译，你可以忽略它...)

编译:
$ make
然后就会生成可执行文件 judge
p.s. 如果是为了调试，可以修改Makefile
把MACRO行反注释，可以看到一些输出信息(都是输出到stderr的)

使用:
这是一个完全独立的judge，不依赖于某一个OJ，通过命令行的形式传送参数
详细情况使用 ./judge -h 查看，或者直接看下面吧:

FelixOJ Judge接口

  输入: 命令行参数(如果某参数包含空格，记得用引号...)
      -e 需要执行的程序(如果是java，则需要包含完整的java ooox命令行)
      -l 语言类型(0 = C, 1 = C++, 2 = pascal, 3 = Java)
      -d 临时文件夹 (用于存储程序输出)
      -I 输入文件 (如data/1001/test.in)
      -O 输出文件 (如data/1001/test.out)
      -t 时间限制，毫秒为单位(默认为1000ms)
      -m 内存限制，KB 为单位(默认为65536KB)
      -o 输出大小限制，KB 为单位(默认为8192KB)
      -s SPJ程序命令行，如不提供则表示不是SPJ
      -j -? 显示此提示
  输出:
   1. 如果judge过程正常结束，返回0，标准输出为
      %d %d %d，分别表示 OJ_RESULT, MEM_USED, TIME_USED
      其中OJ_RESULT参见 judge.h 中的定义
   2. 如果judge过程非正常结束，返回非0，标准输出空
      其中返回值的具体含义参见 judge.h 中的定义


  SPJ接口
      输入: 命令行包含3个文件名，按顺序为 标准输入 标准输出 程序输出
      输出: 1, 2, 4分别表示AC, PE, WA
      5s内返回0表示正常，否则judge将强行结束spj，并返回System Error
      spj不判RF

  Example:
  Non-SPJ
    ./judge -e "/oj/tmp/9527/a.out" -d "/oj/tmp/9527"
        -I "/oj/data/1001/test.out" -O "/oj/data/1001/test.in"
        -t 1000 -m 65536 -o 512 -l 1
  SPJ
    ./judge -e "/oj/tmp/9527/a.out" -d "/oj/tmp/9527"
        -I "/oj/data/1001/test.out" -O "/oj/data/1001/test.in"
        -t 1000 -m 65536 -o 512 -l 1 -s "/oj/data/1001/spj"

