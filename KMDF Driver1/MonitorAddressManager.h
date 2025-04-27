#pragma once

#include "logging.h"
#include "search.h"
#include "HookManager.h"

namespace smallzhong
{
	// 非分页内存的地址范围映射管理器 - 单例模式
	class MonitorAddressManager {
	private:
		// 地址范围结构
		struct AddressRange {
			ULONG64 start_addr;
			ULONG64 end_addr;
			BOOLEAN is_deleted;
		};

		// 成员变量
		AddressRange* m_ranges;
		ULONG64 m_count;
		ULONG64 m_capacity;
		KSPIN_LOCK m_lock;

		// 自定义内存池标签
		static constexpr ULONG POOL_TAG = smallzhong::CompileTimeHash("smallzhong");

		// 私有构造函数 - 单例模式
		MonitorAddressManager(ULONG64 initialCapacity = 1000)
			: m_count(0), m_capacity(initialCapacity), m_ranges(nullptr) {

			// 分配非分页内存池
			m_ranges = static_cast<AddressRange*>(
				ExAllocatePoolWithTag(NonPagedPool,
					sizeof(AddressRange) * m_capacity,
					POOL_TAG));

			if (m_ranges != nullptr) {
				RtlZeroMemory(m_ranges, sizeof(AddressRange) * m_capacity);
			}

			// 初始化自旋锁
			KeInitializeSpinLock(&m_lock);
		}

		// 私有析构函数 - 单例模式
		~MonitorAddressManager() {
			if (m_ranges != nullptr) {
				ExFreePoolWithTag(m_ranges, POOL_TAG);
				m_ranges = nullptr;
			}
		}

		// 禁用拷贝构造和赋值操作
		MonitorAddressManager(const MonitorAddressManager&) = delete;
		MonitorAddressManager& operator=(const MonitorAddressManager&) = delete;

	public:
		// 获取单例实例的静态方法
		static MonitorAddressManager& GetInstance() {
			// 在内核中使用静态局部变量是安全的，因为它们在初始化时是线程安全的
			static MonitorAddressManager instance;
			return instance;
		}

		// 判断初始化是否成功
		bool IsInitialized() const {
			return m_ranges != nullptr;
		}

		// 添加监控范围
		NTSTATUS AddMonitorRange(ULONG64 start_addr, ULONG64 end_addr) {
			if (!IsInitialized()) {
				return STATUS_UNSUCCESSFUL;
			}

			KIRQL old_irql;
			NTSTATUS status = STATUS_SUCCESS;

			// 获取自旋锁，提升 IRQL
			KeAcquireSpinLock(&m_lock, &old_irql);

			// 检查是否超出最大容量
			if (m_count >= m_capacity) {
				status = STATUS_INSUFFICIENT_RESOURCES;
			}
			else {
				// 添加新的监控范围
				m_ranges[m_count].start_addr = start_addr;
				m_ranges[m_count].end_addr = end_addr;
				m_ranges[m_count].is_deleted = FALSE;
				m_count++;

				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"增加了一个监控区域 %llu，%llx %llx\r\n",
					m_count, start_addr, end_addr));
			}

			// 释放自旋锁，降低 IRQL
			KeReleaseSpinLock(&m_lock, old_irql);

			return status;
		}

		// 从监控列表删除地址范围
		VOID DelFromMonitorList(ULONG64 addr) {
			if (!IsInitialized()) {
				return;
			}

			KIRQL old_irql;
			ULONG64 index;

			// 获取自旋锁，提升 IRQL
			KeAcquireSpinLock(&m_lock, &old_irql);

			// 获取包含此地址的范围索引
			index = FilterRetAddr(addr, false); // 传递false表示不需要获取锁，因为我们已经获取了锁

			if (index == 0) {
				// 不在监控范围内，没法删除
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"不在监控范围内，没法del。函数调用addr = %llx\r\n", addr));
			}
			else {
				// FilterRetAddr 返回的索引从 1 开始，需要减 1
				index--;

				// 标记为已删除
				m_ranges[index].is_deleted = TRUE;

				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"删除index = %llx start_addr = %llx end_addr = %llx的监控区域。函数调用addr = %llx\r\n",
					index, m_ranges[index].start_addr, m_ranges[index].end_addr, addr));
			}

			// 释放自旋锁，降低 IRQL
			KeReleaseSpinLock(&m_lock, old_irql);
		}

		// 过滤返回地址，检查是否在监控范围内
		// 返回值：如果在监控范围内，返回索引+1；否则返回0
		ULONG64 FilterRetAddr(ULONG64 ret_addr, bool acquireLock = false) {
			if (!IsInitialized()) {
				return 0;
			}

			ULONG64 result = 0;
			KIRQL old_irql;

			// 获取自旋锁，提升 IRQL（如果需要）
			if (acquireLock) {
				KeAcquireSpinLock(&m_lock, &old_irql);
			}

			if (m_count == 0) {
				result = 0;
			}
			else {
				for (ULONG64 i = 0; i < m_count; i++) {
					// 跳过已删除的范围
					if (m_ranges[i].is_deleted) {
						continue;
					}

					ULONG64 cur_start_addr = m_ranges[i].start_addr;
					ULONG64 cur_end_addr = m_ranges[i].end_addr;

					if (ret_addr >= cur_start_addr && ret_addr <= cur_end_addr) {
						result = i + 1;  // 返回索引+1，0表示未找到
						break;
					}
				}
			}

			// 释放自旋锁，降低 IRQL（如果之前获取了锁）
			if (acquireLock) {
				KeReleaseSpinLock(&m_lock, old_irql);
			}

			return result;
		}
	};
}


#define ADD_MONITOR_RANGE(start, end) smallzhong::MonitorAddressManager::GetInstance().AddMonitorRange((start), (end))
#define DEL_FROM_MONITOR_LIST(addr) smallzhong::MonitorAddressManager::GetInstance().DelFromMonitorList((addr))
#define FILTER_RET_ADDR(ret_addr) smallzhong::MonitorAddressManager::GetInstance().FilterRetAddr((ret_addr))