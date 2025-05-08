#include "search.h"
#include "logging.h"
#include "hook.h"

namespace smallzhong {
	namespace search
	{
		bool equals_ignore_case(const std::string& a, const std::string& b) {
			if (a.size() != b.size()) {
				return false;
			}

			return std::equal(a.begin(), a.end(), b.begin(),
				[](char a, char b) {
					return std::tolower(a) == std::tolower(b);
				});
		}

		std::string extractFileName(const std::string& path) {
			size_t pos = path.find_last_of("\\/");
			if (pos != std::string::npos) {
				return path.substr(pos + 1);
			}

			return path;
		}

		std::optional<KernelModuleInfo> get_sys_module_info(std::string module_to_find)
		{
			NTSTATUS status;
			RTL_PROCESS_MODULES info = { 0 };
			ULONG required_size;

			status = ZwQuerySystemInformation(SystemModuleInformation, &info, sizeof(info), &required_size);
			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				ULONG t_len = required_size + sizeof(RTL_PROCESS_MODULES);
				std::unique_ptr<BYTE[]> buffer(new BYTE[t_len]);
				PRTL_PROCESS_MODULES module_information = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer.get());
				My_RtlZeroMemory(module_information, t_len);
				status = ZwQuerySystemInformation(SystemModuleInformation, module_information, t_len, &required_size);
				if (!NT_SUCCESS(status))
				{
					return std::nullopt;
				}


				for (ULONG i = 0; i < module_information->NumberOfModules; i++)
				{
					PRTL_PROCESS_MODULE_INFORMATION cur_module = &module_information->Modules[i];
					std::string cur_module_name = extractFileName(std::string(cur_module->FullPathName));

					//KdPrintEx((77, 0, "%s\n", cur_module_name.c_str()));
					if (equals_ignore_case(cur_module_name, module_to_find))
					{
						return std::optional<KernelModuleInfo>({ cur_module->ImageBase, cur_module->ImageSize });
					}
				}
			}

			return std::nullopt;
		}
	}
}