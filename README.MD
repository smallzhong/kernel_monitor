# kernel_monitor

+ 关于本框架的详细说明请见 [https://bbs.kanxue.com/thread-286641.htm](https://bbs.kanxue.com/thread-286641.htm)
+ 本项目使用了 [https://github.com/smallzhong/kernelhook](https://github.com/smallzhong/kernelhook) 这个内核 inlinehook 框架。
+ 本项目的设计初衷是在CTF比赛中提高分析驱动程序逻辑的效率，项目的开发和测试都是在虚拟机中进行的，没有考虑过过PG等在真机中运行会遇到的问题。如果您希望用来分析外挂等带有反虚拟机、反测试模式，必须在真机中运行的程序，请自行解决过PG等问题。

## 使用流程

+ 使用nuget导入米松哥封装的 [Musa.Runtime](https://github.com/MiroKaku/Musa.runtime)  ，开始愉快地在内核编写C++代码。

+ 把当前系统的 `ntoskrnl.exe` 用IDA打开，打开 `scripts\AutoGen.py` ，ctrl + h 全局修改修改里面硬编码的保存路径后运行 `AutoGen.py` 脚本，得到 `available_funcs.inc` 、 `handlers.h` 、 `handlers.c` 三个自动生成的文件，并将其导入vs项目中。

+ 在 `ImageLoadCallback` 回调中监控特定模块的加载，并记录其内存区域，加入监控范围。

  ```cpp
  VOID ImageLoadCallback(
  	PUNICODE_STRING FullImageName,
  	HANDLE ProcessId,
  	PIMAGE_INFO ImageInfo)
  {
  
  	if (ProcessId == 0 && FullImageName != NULL)
  	{
  
  		// 检查是否是 ACEDriver.sys 被加载
  		if (wcsstr(FullImageName->Buffer, L"\\ACEDriver.sys"))
  		{
  			LOG_INFO("ACEDriver.sys" " has been loaded!\n");
  			LOG_INFO("Image Base: %p\n", ImageInfo->ImageBase);
  			LOG_INFO("Image Size: %llx\n", ImageInfo->ImageSize);
  
  			ADD_MONITOR_RANGE((ULONG64)ImageInfo->ImageBase, (ULONG64)ImageInfo->ImageBase + ImageInfo->ImageSize);
  		}
  	}
  }
  ```

+ 在 DriverMain 中特定 Hook 自己感兴趣的函数。

+ 加载驱动，查看日志。

## TODO

- [ ] 把日志模块封装一个消息队列，用另外一个线程异步地写日志。这样可以引入把日志写到文件的机制，在本机调试蓝屏了之后还能读取本地的日志查看蓝屏原因。
