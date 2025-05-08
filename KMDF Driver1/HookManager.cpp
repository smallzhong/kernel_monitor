#include "HookManager.h"
#include "logging.h"
#include "MonitorAddressManager.h"
#include "handlers.h"

namespace smallzhong
{
	// ��麯���Ƿ��ڿ����б���
	BOOLEAN IsFunctionAvailable(const char* funcName) {
		uint32_t hash = RuntimeHash(funcName);
		return std::binary_search(kFunctionHashes.begin(), kFunctionHashes.end(), hash);
	}

	bool isFunctionLengthAtLeast16(void* functionAddress) {
		uint8_t* currentAddress = static_cast<uint8_t*>(functionAddress);
		int totalLength = 0;

		while (totalLength < 16) {
			int instructionLength;

			instructionLength = insn_len_x86_64(currentAddress);


			if (*currentAddress == 0xCC) {
				// ���� int3 ָ�� (0xCC),��������
				return FALSE;
			}

			totalLength += instructionLength;
			currentAddress += instructionLength;
		}

		return TRUE;
	}


	std::optional<std::vector<ExportedFunction>> get_export_functions_by_imagebase(void* moduleBase) {
		if (!moduleBase) {
			return std::nullopt;
		}

		auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			return std::nullopt;
		}

		auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
			reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
			);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
			return std::nullopt;
		}

		auto& exportDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (exportDirectory.Size == 0 || exportDirectory.VirtualAddress == 0) {
			return std::nullopt;
		}

		auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
			reinterpret_cast<BYTE*>(moduleBase) + exportDirectory.VirtualAddress
			);

		auto functionAddresses = reinterpret_cast<PDWORD>(
			reinterpret_cast<BYTE*>(moduleBase) + exportDir->AddressOfFunctions
			);
		auto functionNames = reinterpret_cast<PDWORD>(
			reinterpret_cast<BYTE*>(moduleBase) + exportDir->AddressOfNames
			);
		auto functionOrdinals = reinterpret_cast<PWORD>(
			reinterpret_cast<BYTE*>(moduleBase) + exportDir->AddressOfNameOrdinals
			);

		std::vector<ExportedFunction> exportedFunctions;
		exportedFunctions.reserve(exportDir->NumberOfNames);

		for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
			const char* functionName = reinterpret_cast<const char*>(
				reinterpret_cast<BYTE*>(moduleBase) + functionNames[i]
				);
			WORD ordinal = functionOrdinals[i];
			DWORD functionRVA = functionAddresses[ordinal];
			ULONG64 functionAddress = reinterpret_cast<ULONG64>(moduleBase) + functionRVA;

			exportedFunctions.push_back({ functionName, functionAddress });
		}

		return exportedFunctions;
	}


	// ���캯��
	Hook::Hook(ULONG64 funcAddr, ULONG64 callbackFunc)
		: m_record_number(std::nullopt), m_func_addr(funcAddr), m_callback_func(callbackFunc) {
		if (!install()) {
			throw std::runtime_error("Failed to install hook");
		}
	}

	// �ƶ����캯��
	Hook::Hook(Hook&& other) noexcept
		: m_record_number(std::exchange(other.m_record_number, std::nullopt)),
		m_func_addr(other.m_func_addr),
		m_callback_func(other.m_callback_func) {
	}

	// �ƶ���ֵ�����
	Hook& Hook::operator=(Hook&& other) noexcept {
		if (this != &other) {
			reset();
			m_record_number = std::exchange(other.m_record_number, std::nullopt);
			m_func_addr = other.m_func_addr;
			m_callback_func = other.m_callback_func;
		}
		return *this;
	}

	// ��������
	Hook::~Hook() {
		reset();
	}

	// TODO:�ĳ���throw������Ϣ��
	// ��װ hook
	BOOLEAN Hook::install() {
		if (m_record_number.has_value()) {
			return TRUE;  // �Ѿ���װ��
		}

		ULONG64 record_number;
		NTSTATUS status = hook_by_addr(m_func_addr, m_callback_func, &record_number);

		if (!NT_SUCCESS(status)) {
			return FALSE;
		}

		m_record_number = record_number;
		return TRUE;
	}

	// ����/ж�� hook
	void Hook::reset() {
		if (m_record_number.has_value()) {
			reset_hook(m_record_number.value());
			m_record_number = std::nullopt;
		}
	}

	// ��ȡ record number
	ULONG64 Hook::get_record_number() const {
		if (!m_record_number.has_value()) {
			throw std::runtime_error("No active hook");
		}
		return m_record_number.value();
	}

	// ��� hook �Ƿ���Ч
	bool Hook::is_valid() const {
		return m_record_number.has_value();
	}

	// ����µ� hook������ hook ���������������ֶ��Ƴ���
	size_t HookManager::add_hook(ULONG64 funcAddr, ULONG64 callbackFunc) {
		std::lock_guard<std::mutex> lock(m_mutex);
		if (hooked_funcs.count(funcAddr)) {
			throw std::runtime_error("Function already hooked");
		}

		try {
			m_hooks.emplace_back(funcAddr, callbackFunc);
			hooked_funcs.insert(funcAddr);
			return m_hooks.size() - 1;	
		}
		catch (const std::exception& e) {
			// ���� Hook ���캯�������׳����쳣
			LOG_WARN("Failed to hook function at %llx: %s\n", funcAddr, e.what());
			throw; // �����׳��쳣���õ����ߴ���
		}
	}

	// �Ƴ��ض��� hook (ͨ������)
	bool HookManager::remove_hook(size_t index) {
		std::lock_guard<std::mutex> lock(m_mutex);
		if (index >= m_hooks.size()) {
			return false;
		}

		// ʹ���ƶ���ֵ�����һ��Ԫ���ƶ���Ҫɾ����λ��
		if (index < m_hooks.size() - 1) {
			m_hooks[index] = std::move(m_hooks.back());
		}

		// �Ƴ����һ��Ԫ��
		m_hooks.pop_back();
		return true;
	}

	// �Ƴ����� hooks
	void HookManager::remove_all_hooks() {
		std::lock_guard<std::mutex> lock(m_mutex);
		m_hooks.clear();
	}

	// ��ȡ��ǰ hook ����
	size_t HookManager::hook_count() const {
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_hooks.size();
	}
}


