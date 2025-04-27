#pragma once

#include "logging.h"
#include "search.h"
#include "HookManager.h"

namespace smallzhong
{
	// �Ƿ�ҳ�ڴ�ĵ�ַ��Χӳ������� - ����ģʽ
	class MonitorAddressManager {
	private:
		// ��ַ��Χ�ṹ
		struct AddressRange {
			ULONG64 start_addr;
			ULONG64 end_addr;
			BOOLEAN is_deleted;
		};

		// ��Ա����
		AddressRange* m_ranges;
		ULONG64 m_count;
		ULONG64 m_capacity;
		KSPIN_LOCK m_lock;

		// �Զ����ڴ�ر�ǩ
		static constexpr ULONG POOL_TAG = smallzhong::CompileTimeHash("smallzhong");

		// ˽�й��캯�� - ����ģʽ
		MonitorAddressManager(ULONG64 initialCapacity = 1000)
			: m_count(0), m_capacity(initialCapacity), m_ranges(nullptr) {

			// ����Ƿ�ҳ�ڴ��
			m_ranges = static_cast<AddressRange*>(
				ExAllocatePoolWithTag(NonPagedPool,
					sizeof(AddressRange) * m_capacity,
					POOL_TAG));

			if (m_ranges != nullptr) {
				RtlZeroMemory(m_ranges, sizeof(AddressRange) * m_capacity);
			}

			// ��ʼ��������
			KeInitializeSpinLock(&m_lock);
		}

		// ˽���������� - ����ģʽ
		~MonitorAddressManager() {
			if (m_ranges != nullptr) {
				ExFreePoolWithTag(m_ranges, POOL_TAG);
				m_ranges = nullptr;
			}
		}

		// ���ÿ�������͸�ֵ����
		MonitorAddressManager(const MonitorAddressManager&) = delete;
		MonitorAddressManager& operator=(const MonitorAddressManager&) = delete;

	public:
		// ��ȡ����ʵ���ľ�̬����
		static MonitorAddressManager& GetInstance() {
			// ���ں���ʹ�þ�̬�ֲ������ǰ�ȫ�ģ���Ϊ�����ڳ�ʼ��ʱ���̰߳�ȫ��
			static MonitorAddressManager instance;
			return instance;
		}

		// �жϳ�ʼ���Ƿ�ɹ�
		bool IsInitialized() const {
			return m_ranges != nullptr;
		}

		// ��Ӽ�ط�Χ
		NTSTATUS AddMonitorRange(ULONG64 start_addr, ULONG64 end_addr) {
			if (!IsInitialized()) {
				return STATUS_UNSUCCESSFUL;
			}

			KIRQL old_irql;
			NTSTATUS status = STATUS_SUCCESS;

			// ��ȡ������������ IRQL
			KeAcquireSpinLock(&m_lock, &old_irql);

			// ����Ƿ񳬳��������
			if (m_count >= m_capacity) {
				status = STATUS_INSUFFICIENT_RESOURCES;
			}
			else {
				// ����µļ�ط�Χ
				m_ranges[m_count].start_addr = start_addr;
				m_ranges[m_count].end_addr = end_addr;
				m_ranges[m_count].is_deleted = FALSE;
				m_count++;

				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"������һ��������� %llu��%llx %llx\r\n",
					m_count, start_addr, end_addr));
			}

			// �ͷ������������� IRQL
			KeReleaseSpinLock(&m_lock, old_irql);

			return status;
		}

		// �Ӽ���б�ɾ����ַ��Χ
		VOID DelFromMonitorList(ULONG64 addr) {
			if (!IsInitialized()) {
				return;
			}

			KIRQL old_irql;
			ULONG64 index;

			// ��ȡ������������ IRQL
			KeAcquireSpinLock(&m_lock, &old_irql);

			// ��ȡ�����˵�ַ�ķ�Χ����
			index = FilterRetAddr(addr, false); // ����false��ʾ����Ҫ��ȡ������Ϊ�����Ѿ���ȡ����

			if (index == 0) {
				// ���ڼ�ط�Χ�ڣ�û��ɾ��
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"���ڼ�ط�Χ�ڣ�û��del����������addr = %llx\r\n", addr));
			}
			else {
				// FilterRetAddr ���ص������� 1 ��ʼ����Ҫ�� 1
				index--;

				// ���Ϊ��ɾ��
				m_ranges[index].is_deleted = TRUE;

				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"ɾ��index = %llx start_addr = %llx end_addr = %llx�ļ�����򡣺�������addr = %llx\r\n",
					index, m_ranges[index].start_addr, m_ranges[index].end_addr, addr));
			}

			// �ͷ������������� IRQL
			KeReleaseSpinLock(&m_lock, old_irql);
		}

		// ���˷��ص�ַ������Ƿ��ڼ�ط�Χ��
		// ����ֵ������ڼ�ط�Χ�ڣ���������+1�����򷵻�0
		ULONG64 FilterRetAddr(ULONG64 ret_addr, bool acquireLock = false) {
			if (!IsInitialized()) {
				return 0;
			}

			ULONG64 result = 0;
			KIRQL old_irql;

			// ��ȡ������������ IRQL�������Ҫ��
			if (acquireLock) {
				KeAcquireSpinLock(&m_lock, &old_irql);
			}

			if (m_count == 0) {
				result = 0;
			}
			else {
				for (ULONG64 i = 0; i < m_count; i++) {
					// ������ɾ���ķ�Χ
					if (m_ranges[i].is_deleted) {
						continue;
					}

					ULONG64 cur_start_addr = m_ranges[i].start_addr;
					ULONG64 cur_end_addr = m_ranges[i].end_addr;

					if (ret_addr >= cur_start_addr && ret_addr <= cur_end_addr) {
						result = i + 1;  // ��������+1��0��ʾδ�ҵ�
						break;
					}
				}
			}

			// �ͷ������������� IRQL�����֮ǰ��ȡ������
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