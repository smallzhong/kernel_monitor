# kernel_monitor

+ 关于本框架的详细说明请见 [https://bbs.kanxue.com/thread-286641.htm](https://bbs.kanxue.com/thread-286641.htm)
+ 本项目使用了 [https://github.com/smallzhong/kernelhook](https://github.com/smallzhong/kernelhook) 这个内核 inlinehook 框架。

### 使用流程

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