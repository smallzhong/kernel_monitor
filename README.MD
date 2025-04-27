# kernel_monitor

+ 关于本框架的详细说明请见 [https://bbs.kanxue.com/thread-286641.htm](https://bbs.kanxue.com/thread-286641.htm)
+ 本项目使用了 [https://github.com/smallzhong/kernelhook](https://github.com/smallzhong/kernelhook) 这个内核 inlinehook 框架。

### 使用流程

+ 使用nuget导入米松哥封装的 [Musa.Runtime](https://github.com/MiroKaku/Musa.runtime)  ，开始愉快地在内核编写C++代码。

+ 把需要监控的驱动用IDA打开，打开 `scripts\AutoGen.py` ，ctrl + h 全局修改修改里面硬编码的保存路径后运行 `AutoGen.py` 脚本，得到 `available_funcs.inc` 、 `handlers.h` 、 `handlers.c` 三个自动生成的文件，并将其导入vs项目中。
+ 在 Image 回调中监控特定模块的加载，并记录其内存区域，加入监控范围。
+ 在 DriverMain 中特定 Hook 自己感兴趣的函数。
+ 加载驱动，查看日志。