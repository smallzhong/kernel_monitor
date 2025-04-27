#pragma once
#include<ntifs.h> 
#include <ntddk.h>
#include <ntstrsafe.h>
#include <vector>
#include <iostream>
#include <vector>
#include <ranges>
#include <concepts>
#include <format>
#include <optional>
#include <filesystem>
//#include <absl/strings/match.h>
#include "Veil.h"

namespace smallzhong {
	namespace search
	{
		struct KernelModuleInfo {
			PVOID BaseAddress;
			ULONG Size;

			KernelModuleInfo(PVOID base, ULONG size) : BaseAddress(base), Size(size) {}
		};

		std::optional<KernelModuleInfo> get_sys_module_info(std::string module_name);
	}
}




#define KdPrintEx(_x_) DbgPrintEx _x_ 
#define kdprintf(_x_) DbgPrintEx _x_ 
