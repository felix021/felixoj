Online Judge Based on Linux + Apache + MySQL + PHP

基本设计思路:

1. 架构是 Web/Client(a) <==> Database(b) <==> Daemon(c) <==> JudgeWrapper(d) <==> Judge(e)
> 前三者之间由于数据库的缘故，无法做到完全独立。
> 但是Judge是完全独立的，可以通过命令行参数的形式进行调用。
> 因此可以开发额外的Judge Wrapper作为Personal版，或者叫做 Offline Judge

2. 目前完成了Judge，大量参考了Sempr大牛设计的HustOJ(同是Google Code上的Project)
> 可能还有小BUG，欢迎大家测试使用

3. 其余部分考虑在2009年暑假完成。

@ 2009-06-18 By Felix021

@ 2010-02-10 非常悲痛地宣布此project被烂尾。

@ 2010-02-10 此项目在woj-land中继续。。 http://code.google.com/p/woj-land