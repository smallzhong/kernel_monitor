#pragma once


#include<ntifs.h> 
#include <ntddk.h>
#include <ntstrsafe.h>
#include <vector>
#include <vector>
#include <ranges>
#include <concepts>
#include <format>
#include "search.h"
#include "AsmCode.h"
#include "hook.h"
#include <unordered_set>
#include <mutex>
#include <set>
#include <array>
#include <algorithm>
#include <atomic>
#include <array>
#include <stdint.h>
#include <string_view>

namespace smallzhong
{
	struct ExportedFunction {
		std::string function_name;
		ULONG64 address;
	};



	// �����ڹ�ϣ���� (FNV-1a ��ϣ�㷨)
	constexpr uint32_t CompileTimeHash(std::string_view str, uint32_t hash = 2166136261u) {
		return str.empty() ? hash : CompileTimeHash(
			str.substr(1),
			(hash ^ static_cast<uint32_t>(str[0])) * 16777619u
		);
	}

	// �����õıȽϺ���
	constexpr bool HashCompare(uint32_t a, uint32_t b) {
		return a < b;
	}

	constexpr auto  kFunctionHashes = []() {
		auto hashes = std::array{
			//CompileTimeHash("KiComputePriorityFloor"),
	#include "available_funcs.inc"
			// ... ��Ӹ����ַ�����ϣֵ
		};

		// �����ڶ������������
		//std::sort(hashes.begin(), hashes.end());

		return hashes;
		}();

	// ���ֲ��Ҽ�麯���Ƿ����
	template<typename Array>
	constexpr bool BinarySearch(const Array& arr, uint32_t value) {
		size_t left = 0;
		size_t right = arr.size() - 1;

		while (left <= right) {
			size_t mid = left + (right - left) / 2;

			if (arr[mid] == value) {
				return true;
			}

			if (arr[mid] < value) {
				left = mid + 1;
			}
			else {
				if (mid == 0) return false;
				right = mid - 1;
			}
		}

		return false;
	}

	// �����ڼ��汾 (����constexpr����)
	constexpr bool IsFunctionAvailableConstexpr(std::string_view funcName) {
		return BinarySearch(kFunctionHashes, CompileTimeHash(funcName));
	}

	// ��������֤�����Ƿ���������
	static_assert(BinarySearch(kFunctionHashes, CompileTimeHash("ExAllocatePoolWithQuota")),
		"Hash lookup failed at compile time");

	// ��麯���Ƿ��ڿ����б���
	BOOLEAN IsFunctionAvailable(const char* funcName);

	// ���� Hook �ķ�װ��
	class Hook {
	public:
		Hook(ULONG64 funcAddr, ULONG64 callbackFunc);

		// �ƶ����캯��
		Hook(Hook&& other) noexcept;

		// �ƶ���ֵ�����
		Hook& operator=(Hook&& other) noexcept;

		// ���ø���
		Hook(const Hook&) = delete;
		Hook& operator=(const Hook&) = delete;

		// ��������
		~Hook();

		// ��װ hook
		BOOLEAN install();

		// ����/ж�� hook
		void reset();

		// ��ȡ record number
		ULONG64 get_record_number() const;

		// ��� hook �Ƿ���Ч
		bool is_valid() const;
	private:
		std::optional<ULONG64> m_record_number;
		ULONG64 m_func_addr;
		ULONG64 m_callback_func;
	};

	// ȫ�� Hook ������ - ����ģʽ
	class HookManager {
	public:
		static HookManager& instance() {
			static HookManager instance;
			return instance;
		}

		// ����µ� hook������ hook ���������������ֶ��Ƴ���
		size_t add_hook(ULONG64 funcAddr, ULONG64 callbackFunc);

		// ʹ��ģ����� hook �ı�ݷ���
		template<typename Func>
		size_t add_hook(ULONG64 funcAddr, Func&& callback) {
			return add_hook(funcAddr, reinterpret_cast<ULONG64>(+std::forward<Func>(callback)));
		}

		// �Ƴ��ض��� hook (ͨ������)
		bool remove_hook(size_t index);

		// �Ƴ����� hooks
		void remove_all_hooks();

		// ��ȡ��ǰ hook ����
		size_t hook_count() const;

		// ���ø��ƺ��ƶ�
		HookManager(const HookManager&) = delete;
		HookManager& operator=(const HookManager&) = delete;
		HookManager(HookManager&&) = delete;
		HookManager& operator=(HookManager&&) = delete;

	private:
		// ˽�й��캯�� (����ģʽ)
		HookManager() = default;

		// ˽���������� (����ģʽ)
		~HookManager() {
			// ��������е� hook ����ͨ�� vector �����������Զ��ͷ�
		}

		std::vector<Hook> m_hooks;
		std::unordered_set<ULONG64> hooked_funcs;
		mutable std::mutex m_mutex;  // �������̷߳���
	};




	bool isFunctionLengthAtLeast16(void* functionAddress);

	std::optional<std::vector<ExportedFunction>> get_export_functions_by_imagebase(void* moduleBase);

}

// �����꣬����ʹ��
#define GLOBAL_HOOK_MANAGER smallzhong::HookManager::instance()