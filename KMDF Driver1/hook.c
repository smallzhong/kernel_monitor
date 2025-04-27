#include "hook.h"
#include "stdio.h"

ULONG64 allocateMemory(ULONG64 size)
{
	// �����޸��ڴ���䷽ʽʹ�������
	PVOID memory = ExAllocatePoolWithTag(NonPagedPool, size, SMALLZHONG_POOLTAG);
	if (memory) {
		RtlZeroMemory(memory, size); // ��ʼ���ڴ�Ϊ��
	}
	else
	{
		LOG_FATAL("memory allocation failed!\r\n");
	}
	return (ULONG64)memory;
}

VOID freeMemory(ULONG64 addr)
{
	if (addr)
	{
		ExFreePoolWithTag((PVOID)addr, SMALLZHONG_POOLTAG);
	}
	else
	{
		LOG_FATAL("you want to free a NULL pointer ? \r\n");
	}
}

NTSTATUS makeWriteableMapping(void* const addr, unsigned int size, PMDL* my_mdl, PVOID* my_addr)
{
	PMDL mdl = IoAllocateMdl(addr, size, FALSE, FALSE, NULL);
	if (!mdl)
	{
		*my_mdl = NULL, * my_addr = NULL;
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	BOOLEAN locked = FALSE;
	__try
	{
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		locked = TRUE;

		PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
		if (mapped)
		{
			NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
			if (!NT_SUCCESS(status))
			{
				MmUnmapLockedPages(mapped, mdl);
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);

				*my_mdl = NULL, * my_addr = NULL;
				return STATUS_MEMORY_NOT_ALLOCATED;
			}

			*my_mdl = mdl, * my_addr = mapped;
			return STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (locked)
		{
			MmUnlockPages(mdl);
		}
	}

	IoFreeMdl(mdl);

	*my_mdl = NULL, * my_addr = NULL;
	return STATUS_MEMORY_NOT_ALLOCATED;
}

VOID freeMapping(PMDL my_mdl, PVOID my_addr)
{
	if (my_addr)
	{
		MmUnmapLockedPages(my_addr, my_mdl);
	}

	if (my_mdl)
	{
		MmUnlockPages(my_mdl);
		IoFreeMdl(my_mdl);
	}
}

BOOLEAN writeToKernel(PVOID dest, PVOID src, ULONG64 size)
{
	LOG_TRACE("writeToKernel %llx %llx %llx\r\n", dest, src, size);
	if (!dest || !src)
	{
		LOG_WARN("dest or src is 0! dest = %p src = %p size = %llx\r\n", dest, src, size);
		return FALSE;
	}
	if (!MmIsAddressValid(dest) || !MmIsAddressValid(src))
	{
		LOG_WARN("dest or src is not valid addr! dest = %p src = %p size = %llx\r\n", dest, src, size);
		return FALSE;
	}

	PMDL my_mdl = NULL;
	PVOID my_addr = NULL;
	NTSTATUS status = makeWriteableMapping(dest, size, &my_mdl, &my_addr);
	if (!NT_SUCCESS(status))
	{
		LOG_FATAL("makeWriteableMapping failed!\r\n");
		return FALSE;
	}

	RtlMoveMemory(my_addr, src, size);

	freeMapping(my_mdl, my_addr);
	return TRUE;
}


typedef struct _SMALLZHONG_WRITE_DPC_CONTEXT {
	ULONG PendingProcessorId;
	ULONG64 src;
	ULONG64 dest;
	ULONG64 size;
} SMALLZHONG_WRITE_DPC_CONTEXT, * PSMALLZHONG_WRITE_DPC_CONTEXT;

VOID handler_writeToKernelWithDPC(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	PSMALLZHONG_WRITE_DPC_CONTEXT p_context = (PSMALLZHONG_WRITE_DPC_CONTEXT)DeferredContext;
	if (!p_context)
	{
		LOG_FATAL("p_context is NULL!\r\n");
		return;
	}

	ULONG PendingProcessorId = p_context->PendingProcessorId;
	ULONG64 dest = p_context->dest;
	ULONG64 src = p_context->src;
	ULONG64 size = p_context->size;

	KeSignalCallDpcSynchronize(SystemArgument2);
	if (PendingProcessorId == KeGetCurrentProcessorNumber())
	{
		RtlMoveMemory(dest, src, size);
	}

	KeSignalCallDpcDone(SystemArgument1);
	return;
}


BOOLEAN writeToKernelWithDPC(PVOID dest, PVOID src, ULONG64 size)
{
	LOG_TRACE("writeToKernelWithDPC %llx %llx %llx\r\n", dest, src, size);

	if (!dest || !src)
	{
		LOG_WARN("dest or src is 0! dest = %p src = %p size = %llx\r\n", dest, src, size);
		return FALSE;
	}
	if (!MmIsAddressValid(dest) || !MmIsAddressValid(src))
	{
		LOG_WARN("dest or src is not valid addr! dest = %p src = %p size = %llx\r\n", dest, src, size);
		return FALSE;
	}

	PSMALLZHONG_WRITE_DPC_CONTEXT write_context = allocateMemory(sizeof(SMALLZHONG_WRITE_DPC_CONTEXT));
	if (!write_context)
	{
		LOG_FATAL("allocate memory failed!\r\n");
		return FALSE;
	}

	PMDL my_mdl = NULL;
	PVOID my_addr = NULL;
	NTSTATUS status = makeWriteableMapping(dest, size, &my_mdl, &my_addr);
	if (!NT_SUCCESS(status))
	{
		LOG_FATAL("makeWriteableMapping failed!\r\n");
		freeMemory(write_context);
		return FALSE;
	}

	write_context->PendingProcessorId = KeGetCurrentProcessorNumber();
	write_context->src = (ULONG64)src;
	write_context->dest = (ULONG64)my_addr;
	write_context->size = (ULONG64)size;

	// CALL!
	KeGenericCallDpc(handler_writeToKernelWithDPC, write_context);

	freeMapping(my_mdl, my_addr);
	freeMemory(write_context);
}


int get_hook_len(ULONG64 Addr, ULONG64 size, BOOLEAN isX64)
{
	PUCHAR tempAddr = Addr;
	int totalSize = 0;
	int len = 0;

	if (isX64)
	{
		do
		{
			len = insn_len_x86_64((ULONG64)tempAddr);

			tempAddr = tempAddr + len;

			totalSize += len;

		} while (totalSize < size);
	}
	else
	{
		do
		{
			len = insn_len_x86_32((ULONG64)tempAddr);

			tempAddr = tempAddr + len;

			totalSize += len;

		} while (totalSize < size);
	}

	return totalSize;
}

// 36��hookhandler��ƫ��
// 67��origin��ַ��ƫ��
UCHAR handler_shellcode[] =
{
0x54                            // push rsp    
,0x41,0x57                         // push r15                           
,0x41,0x56                       // push r14                           
,0x41,0x55                         // push r13                           
,0x41,0x54                         // push r12                           
,0x41,0x53                         // push r11                           
,0x41,0x52                         // push r10                           
,0x41,0x51                         // push r9                            
,0x41,0x50                         // push r8                            
,0x57                            // push rdi                           
,0x56                            // push rsi                           
,0x55                            // push rbp                                             
,0x53                            // push rbx                           
,0x52                            // push rdx                           
,0x51                            // push rcx                           
,0x50                            // push rax          
,0x9C                            // pushfq
,0x48,0x8B,0xCC                       // mov rcx,rsp                        
,0x48,0x81,0xEC,0x00,0x01,0x00,0x00              // sub rsp,100        

// call hookhandler
,0xEB,0x08 // jmp (��������Ĵ���)
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0x00,0x00 // add byte ptr ds : [rax] ,al |
,0xFF,0x15,0xF2,0xFF,0xFF,0xFF // call qword ptr ds : [7FF9AAEA069B] |

,0x48,0x81,0xC4,0x00,0x01,0x00,0x00 // add rsp,100 |

// ���rax=1��˵����Ҫֱ�ӷ��أ�����ֵ����rcx�С�����jmp��ԭ��Ҫִ�еĴ��봦����ִ�С�
,0x3C,0x00 // cmp al,0
,0x75,0x0E // jne (��������14���ֽ�)
,0xFF,0x25,0x00,0x00,0x00,0x00 // jmp qword ptr ds : [7FF9AAEA06FA] 
,0x00,0x00 // add byte ptr ds : [rax] ,al 
,0x00,0x00 // add byte ptr ds : [rax] ,al 
,0x00,0x00 // add byte ptr ds : [rax] ,al 
,0x00,0x00 // add byte ptr ds : [rax] ,al 

,0x9D                            // pop rflags
,0x58                            // pop rax   
,0x59                            // pop rcx                            
,0x5A                            // pop rdx                            
,0x5B                            // pop rbx                                                    
,0x5D                            // pop rbp                            
,0x5E                            // pop rsi                            
,0x5F                            // pop rdi                            
,0x41,0x58                         // pop r8                             
,0x41,0x59                         // pop r9                             
,0x41,0x5A                         // pop r10                            
,0x41,0x5B                         // pop r11                            
,0x41,0x5C                         // pop r12                            
,0x41,0x5D                         // pop r13                            
,0x41,0x5E                         // pop r14                            
,0x41,0x5F                         // pop r15
,0x5C                            // pop rsp    
,0xC3							   // ret
};

UCHAR resume_code[] =
{
0x9D                              // pop rflags
,0x58                             // pop rcx                    
,0x59                            // pop rcx                            
,0x5A                            // pop rdx                            
,0x5B                            // pop rbx                                                   
,0x5D                            // pop rbp                            
,0x5E                            // pop rsi                            
,0x5F                            // pop rdi                            
,0x41,0x58                         // pop r8                             
,0x41,0x59                         // pop r9                             
,0x41,0x5A                         // pop r10                            
,0x41,0x5B                         // pop r11                            
,0x41,0x5C                         // pop r12                            
,0x41,0x5D                         // pop r13                            
,0x41,0x5E                         // pop r14                            
,0x41,0x5F                         // pop r15
,0x5C                            // pop rsp     
};

static phook_record g_hook_record_head = NULL;
static ULONG64 g_record_ct = 0;

VOID
my_AppendTailList(
	_Inout_ PLIST_ENTRY ListHead,
	_Inout_ PLIST_ENTRY ListToAppend
)
{
	PLIST_ENTRY ListEnd = ListHead->Blink;

	RtlpCheckListEntry(ListHead);
	RtlpCheckListEntry(ListToAppend);
	ListHead->Blink->Flink = ListToAppend;
	ListHead->Blink = ListToAppend->Blink;
	ListToAppend->Blink->Flink = ListHead;
	ListToAppend->Blink = ListEnd;
	return;
}



ULONG64 get_module_base_by_an_addr_in_this_module(ULONG64 virt_addr)
{
	ULONG uNeedSize = 0;

	NTSTATUS status = STATUS_SUCCESS;
	PRTL_PROCESS_MODULES pSysInfo = NULL;
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &uNeedSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return NULL;
	}
	if (uNeedSize == 0)
	{
		return NULL;
	}

	pSysInfo = (PRTL_PROCESS_MODULES)allocateMemory(uNeedSize);
	if (pSysInfo == NULL)
	{
		return NULL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysInfo, uNeedSize, &uNeedSize);
	if (!NT_SUCCESS(status))
	{
		freeMemory(pSysInfo);
		return NULL;
	}

	for (int i = 0; i < pSysInfo->NumberOfModules; i++)
	{
		PRTL_PROCESS_MODULE_INFORMATION pModuleInfo = &pSysInfo->Modules[i];
		if (MmIsAddressValid(pModuleInfo) && pModuleInfo != NULL)
		{
			ULONG64 moduleStart = (ULONG64)pModuleInfo->ImageBase;
			ULONG64 moduleEnd = (ULONG64)pModuleInfo->ImageBase + pModuleInfo->ImageSize;

			if (virt_addr < moduleEnd && virt_addr >= moduleStart)
			{
				freeMemory(pSysInfo);
				return moduleStart;
			}
		}
	}

	freeMemory(pSysInfo);
	return NULL;
}

PIMAGE_SECTION_HEADER detour_va_to_section(PVOID base, PIMAGE_NT_HEADERS nt, PCHAR va)
{
	PIMAGE_SECTION_HEADER NtSection = IMAGE_FIRST_SECTION(nt);
	for (size_t i = 0u; i < nt->FileHeader.NumberOfSections; ++i) {
		if (va >= ((PCHAR)base + NtSection->VirtualAddress) &&
			va < ((PCHAR)base + NtSection->VirtualAddress + NtSection->Misc.VirtualSize)) {

			return NtSection;
		}
		++NtSection;
	}

	return NULL;
}

PCHAR get_blank_space_in_module(PCHAR virt_addr_in_this_module, ULONG64 size_needed)
{
	PVOID ImageBase = NULL;
	PIMAGE_SECTION_HEADER NtSection = NULL;
	PIMAGE_SECTION_HEADER NtSectionLast = NULL;

	if (RtlPcToFileHeader(virt_addr_in_this_module, &ImageBase) == NULL) {
		return NULL;
	}

	PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(ImageBase);
	if (NtHeader == NULL) {
		return NULL;
	}

	NtSection = detour_va_to_section(ImageBase, NtHeader, virt_addr_in_this_module);
	if (NtSection == NULL) {
		return NULL;
	}

	NtSectionLast = NtSection + 1;
	if (NtSectionLast >= (IMAGE_FIRST_SECTION(NtHeader) + NtHeader->FileHeader.NumberOfSections)) {
		NtSectionLast = NULL;
	}

	PCHAR CodeIn = (PCHAR)ImageBase + NtSection->VirtualAddress + NtSection->Misc.VirtualSize;
	PCHAR CodeInEnd = (PCHAR)ImageBase + (NtSectionLast != NULL
		? NtSectionLast->VirtualAddress
		: NtHeader->OptionalHeader.SizeOfImage);

	CodeIn = (PCHAR)(((ULONG_PTR)CodeIn / 0x10 + 1) * 0x10);

	// Calculate how many 8-byte blocks are needed
	ULONG64 blocks_needed = (size_needed + 0x7) / 0x8;

	while (CodeIn < CodeInEnd) {
		PCHAR CurrentCodeIn = CodeIn;
		ULONG64 blocks_found = 0;

		// Check for the number of contiguous 8-byte NULL blocks
		while (CurrentCodeIn < CodeInEnd && blocks_found < blocks_needed) {
			if (*(PVOID*)CurrentCodeIn == NULL) {
				blocks_found++;
				CurrentCodeIn += sizeof(PVOID);
			}
			else {
				break;
			}
		}

		// If the needed number of blocks are found, return the start pointer
		if (blocks_found == blocks_needed) {
			return CodeIn;
		}

		// Move to the next aligned 8-byte block if the current sequence is not sufficient
		CodeIn += sizeof(PVOID);
	}

	return NULL;
}


//PUCHAR get_blank_space_in_module(ULONG64 virt_addr_in_this_module, ULONG64 size_needed)
//{
//	// TODO:��������п����ҵ�һЩ��ʵ���ڱ�ʹ�õ��ڴ档��ʱ���ã������κ�4�ֽ�Ѱַ��ָ���
//	return NULL;
//
//	ULONG64 moduleBase = get_module_base_by_an_addr_in_this_module(virt_addr_in_this_module);
//	if (moduleBase == NULL)
//	{
//		return STATUS_NOT_FOUND;
//	}
//
//	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
//
//	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + pDos->e_lfanew);
//
//	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNts);
//
//	for (int i = 0; i < pNts->FileHeader.NumberOfSections; i++)
//	{
//		char bufName[9] = { 0 };
//		RtlMoveMemory(bufName, pSection->Name, 8);
//
//		// TODO:�����������ȫ��
//		if (_stricmp(bufName, ".text") == 0)
//		{
//			ULONG64 blank_space_start_addr = moduleBase + pSection->VirtualAddress + pSection->Misc.VirtualSize;
//			ULONG64 blank_space_end_addr = moduleBase + pSection->VirtualAddress + pSection->SizeOfRawData;
//
//			// TODO:���������һ�������档��ʱ���ñ����ѵ��߼���
//			ULONG64 cur_addr = blank_space_start_addr;
//			while (TRUE)
//			{
//				// ��ַ���Ϸ�����û����ô��ռ���
//				if (!MmIsAddressValid(cur_addr) || cur_addr + size_needed >= blank_space_end_addr || !MmIsAddressValid(cur_addr + size_needed))
//				{
//					return NULL;
//				}
//
//				for (int i = 0; i < size_needed; i++)
//				{
//					ULONG64 t_addr = cur_addr + i;
//					if (!MmIsAddressValid(t_addr))
//					{
//						return NULL;
//					}
//
//					if (*(PUCHAR)t_addr != 0x00)
//					{
//						cur_addr += 16;
//						continue;
//					}
//				}
//
//				// �ߵ�����˵����ַȫ���Ϸ�������ȫΪ0��
//				break;
//			}
//
//			if (cur_addr + size_needed > moduleBase + pSection->VirtualAddress + pSection->SizeOfRawData)
//			{
//				return NULL;
//			}
//			if (!MmIsAddressValid(cur_addr) || !MmIsAddressValid(cur_addr + size_needed))
//			{
//				return NULL;
//			}
//			return cur_addr;
//		}
//
//		pSection++;
//	}
//
//	return NULL;
//}

// TODO���жϺ�������
// ǰ������ģ�����ͺ���������������callback�ĵ�ַ�����ĸ������ģ���Ӧ���±�

NTSTATUS hook_by_addr(ULONG64 funcAddr, ULONG64 callbackFunc, OUT ULONG64* record_number)
{
	if (!funcAddr || !MmIsAddressValid(funcAddr))
	{
		return STATUS_NOT_FOUND;
	}

	ULONG64 handler_addr = allocateMemory(PAGE_SIZE);
	if (!handler_addr)
		return STATUS_MEMORY_NOT_ALLOCATED;
	RtlMoveMemory(handler_addr, handler_shellcode, sizeof(handler_shellcode));
	char bufcode[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, };

	// ��ȡ��Ҫpatch��ָ���
	ULONG64 inslen = get_hook_len(funcAddr, sizeof(bufcode), TRUE);
	ULONG64 shellcode_origin_addr = allocateMemory(PAGE_SIZE);
	if (!shellcode_origin_addr)
	{
		freeMemory(handler_addr);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}


	/*
	ԭʼ����
	ff 25 xxxxxx(����ԭ��)
	*/
	RtlMoveMemory(shellcode_origin_addr, resume_code, sizeof(resume_code));
	RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code), funcAddr, inslen);

	// ʹ��zydis�ҳ�ʹ������Ե�ַ�����
	ZyanU64 runtime_address = funcAddr;

	// ���������Ե�ַ�����ʱ�����˶೤�Ĵ��롣��������дff25��ʱ��Ҫ����ε�ַҲ��������
	ULONG64 resolve_relative_code_len = 0;

	// ����ȷ��ABC���Ƿ���ʹ������Ե�ַ�Ĵ���ı�ǡ�����еĻ��ں��滹Ҫ�ټ���һ��ebjmp��������resolve��Ե�ַ�Ĵ�������ԭʼ��ff25jmp����
	BOOLEAN relative_addr_used_in_abc = FALSE;

	ZyanUSize cur_disasm_offset = 0;
	ZydisDisassembledInstruction instruction;
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(
		/* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
		/* runtime_address: */ runtime_address,
		/* buffer:          */ shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset,
		/* length:          */ inslen - cur_disasm_offset,
		/* instruction:     */ &instruction
	))) {
		LOG_TRACE("%llx %s\n", runtime_address, instruction.text);


		// �ж��Ƿ�����Ե�ַ
		if (instruction.info.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			// ���flag��������flag�����˵Ļ�����Ҫ����һ��ebjmp��������ff25����ԭ��������Ĵ��봦��
			if (relative_addr_used_in_abc == FALSE)
			{
				relative_addr_used_in_abc = TRUE;
				// ��Ӧ���ǵ�һ�Σ�Ӧ��Ϊ0
				//ASSERT(resolve_relative_code_len == 0);
				if (resolve_relative_code_len != 0)
				{
					LOG_TRACE("resolve_relative_code_len != 0\r\n");
					freeMemory(handler_addr);
					freeMemory(shellcode_origin_addr);
					return STATUS_INTERNAL_ERROR;
				}
				UCHAR t_ebjmp[2] = { 0xeb, 0x00 };
				// ABC�����ټ���һ��ebjmp��������������resolve�Ĵ���
				RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, t_ebjmp, sizeof(t_ebjmp));
				// ����resolve�Ĵ���ĳ���+=2
				resolve_relative_code_len += sizeof(t_ebjmp);
			}

			LOG_TRACE("ZYDIS_ATTRIB_IS_RELATIVE\r\n");
			LOG_TRACE("���ָ�����Ϣ��%llx", funcAddr + cur_disasm_offset);
			for (int i = 0; i < instruction.info.length; i++)
				LOG_TRACE_NOPREFIX(" %02hhx", *(PUCHAR)(funcAddr + cur_disasm_offset + i));
			LOG_TRACE_NOPREFIX(" %s\r\n", instruction.text);
			// ���⴦�� lea rax, [rip+offset] ָ�� (48 8D 05)
			// ���⴦�� lea rax, [rip+offset] ָ�� (48 8D 05)
			if (*(PUCHAR)runtime_address == 0x48 &&
				*(PUCHAR)(runtime_address + 1) == 0x8D &&
				*(PUCHAR)(runtime_address + 2) == 0x05)
			{
				LOG_TRACE("��⵽ lea rax, [rip+offset] ָ����⴦��\r\n");

				// 1. ����leaָ��ľ��Ե�ַ
				LONG cur_offset = *(PLONG)(runtime_address + instruction.info.raw.disp.offset);
				ULONG64 target_addr = runtime_address + instruction.info.length + cur_offset;

				// 2. ��ԭ��leaָ��λ�÷�����תָ���������������ӵĴ�������
				UCHAR jmp_to_mov[2] = { 0xEB, 0x00 };

				// �����leaָ�����Ҫ��ӵ�mov rax���������ƫ��
				CHAR offset = (CHAR)(inslen - cur_disasm_offset - 2 + 2); // +2��Ϊ������ǰ����ӵ�eb jmp
				jmp_to_mov[1] = offset;

				// ��leaָ��λ�÷�����ת
				RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset, jmp_to_mov, sizeof(jmp_to_mov));

				// 3. ��shellcodeĩβ���mov rax, imm64ָ�������ָ��
				// mov rax, imm64ָ��
				UCHAR mov_rax_imm64[10] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				*(PULONG64)(mov_rax_imm64 + 2) = target_addr;

				// ���ص�leaָ������ָ��
				UCHAR jmp_back[2] = { 0xEB, 0x00 };

				// �������mov rax����ʼλ�ã����ڼ�������ƫ��
				ULONG64 mov_rax_location = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

				// ��mov raxָ����ӵ�����
				RtlMoveMemory(mov_rax_location, mov_rax_imm64, sizeof(mov_rax_imm64));

				// ��������ƫ�ƣ���jmp_back����һ���ֽڵ�leaָ������һ��ָ��
				// Ŀ�� = shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length
				// ��ǰλ�� = mov_rax_location + sizeof(mov_rax_imm64) + 2 (EB������ֽ�)
				// ƫ�� = Ŀ�� - ��ǰλ��
				CHAR back_offset = (CHAR)(
					(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length) -
					(mov_rax_location + sizeof(mov_rax_imm64) + 2)
					);

				jmp_back[1] = back_offset;

				// �������ָ��
				RtlMoveMemory(mov_rax_location + sizeof(mov_rax_imm64), jmp_back, sizeof(jmp_back));

				// ����resolve_relative_code_len
				resolve_relative_code_len += sizeof(mov_rax_imm64) + sizeof(jmp_back);

				// ���������Ϣ����֤��ȷ��
				LOG_TRACE("lea rax���⴦��: ԭʼָ��λ��=%llx, �滻��mov raxλ��=%llx, ����Ŀ��λ��=%llx, ����ƫ��=%d\r\n",
					shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset,
					mov_rax_location,
					shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length,
					back_offset);
			}
			// һ�ֽ������ת
			else if (instruction.info.length == 2 && (
				(*(PUCHAR)runtime_address <= 0x7f && *(PUCHAR)runtime_address >= 0x70) ||
				*(PUCHAR)runtime_address == 0xe0 ||
				*(PUCHAR)runtime_address == 0xe1 ||
				*(PUCHAR)runtime_address == 0xe2 ||
				*(PUCHAR)runtime_address == 0xe3 ||
				*(PUCHAR)runtime_address == 0xeb
				))
			{
#define OPCODE_LENGTH 1
#define OFFSET_TYPE CHAR
				do
				{
					// 1.ȷ������ָ��ԭ��Ҫ��ת���ĸ���ַ
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(OFFSET_TYPE*)(runtime_address + OPCODE_LENGTH); // ��һ����ַ+offset
					LOG_TRACE("original_jx_addr = %llx\r\n", original_jx_addr);

					// 1.1.�ж�����ָ����ת�ĵ�ַ�ǲ��������Ǹ��Ƶ�buffer��Χ�ڣ�����eb 02�����������������ȥ�Ļ�Ҳ�����Ӧ�ò�ȥ�޸�����
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// ���ȷʵ�ڷ�Χ�ڣ���ȥ�޸ģ�ֱ��break
						break;
					}
					// 2.����ff25jmp��д������

					// ��������ff25�ĵ�ַ���ں�������jcc��ת�ĵ�ַ��ʱ������õ�
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

					// 3.����jcc��ת�ĵ�ַ����֤���ܹ���ȷ��ת���ղŹ����ff25jmp��
					LOG_TRACE("runtime_address = %llx\r\n", runtime_address);
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						LOG_TRACE("offset_for_jx < 0 || offset_for_jx == 0\r\n");
						freeMemory(handler_addr);
						freeMemory(shellcode_origin_addr);
						return STATUS_INTERNAL_ERROR;
					}
					// д��jcc��ת�ĵ�ַ��ȥ��
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					LOG_TRACE("%llx\r\n", shellcode_origin_addr);
					LOG_TRACE("%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset);
				} while (0);
			}
			// һЩ��̫���ܳ��ֵĴ�����Чǰ׺�Ķ��������в�����UB��Ϊ��
			else if (instruction.info.length == 3 && (
				(*(PUCHAR)runtime_address >= 0x40 && *(PUCHAR)runtime_address <= 0x4f) ||
				*(PUCHAR)runtime_address == 0x26 ||
				*(PUCHAR)runtime_address == 0x2e ||
				*(PUCHAR)runtime_address == 0x36 ||
				*(PUCHAR)runtime_address == 0x3e ||
				*(PUCHAR)runtime_address == 0x64 ||
				*(PUCHAR)runtime_address == 0x65 ||
				*(PUCHAR)runtime_address == 0x66 ||
				*(PUCHAR)runtime_address == 0x67 ||
				*(PUCHAR)runtime_address == 0xf2 ||
				*(PUCHAR)runtime_address == 0xf3
				) && (
					(*(PUCHAR)(runtime_address + 1) <= 0x7f && *(PUCHAR)(runtime_address + 1) >= 0x70) ||
					*(PUCHAR)(runtime_address + 1) == 0xe0 ||
					*(PUCHAR)(runtime_address + 1) == 0xe1 ||
					*(PUCHAR)(runtime_address + 1) == 0xe2 ||
					*(PUCHAR)(runtime_address + 1) == 0xe3 ||
					*(PUCHAR)(runtime_address + 1) == 0xeb
					))
			{
#define OPCODE_LENGTH 2
#define OFFSET_TYPE CHAR
				do
				{
					// 1.ȷ������ָ��ԭ��Ҫ��ת���ĸ���ַ
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(OFFSET_TYPE*)(runtime_address + OPCODE_LENGTH); // ��һ����ַ+offset
					LOG_TRACE("original_jx_addr = %llx\r\n", original_jx_addr);

					// 1.1.�ж�����ָ����ת�ĵ�ַ�ǲ��������Ǹ��Ƶ�buffer��Χ�ڣ�����eb 02�����������������ȥ�Ļ�Ҳ�����Ӧ�ò�ȥ�޸�����
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// ���ȷʵ�ڷ�Χ�ڣ���ȥ�޸ģ�ֱ��break
						break;
					}
					// 2.����ff25jmp��д������

					// ��������ff25�ĵ�ַ���ں�������jcc��ת�ĵ�ַ��ʱ������õ�
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

					// 3.����jcc��ת�ĵ�ַ����֤���ܹ���ȷ��ת���ղŹ����ff25jmp��
					LOG_TRACE("runtime_address = %llx\r\n", runtime_address);
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						LOG_TRACE("offset_for_jx < 0 || offset_for_jx == 0\r\n");
						freeMemory(handler_addr);
						freeMemory(shellcode_origin_addr);
						return STATUS_INTERNAL_ERROR;
					}
					// д��jcc��ת�ĵ�ַ��ȥ��
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					LOG_TRACE("%llx\r\n", shellcode_origin_addr);
					LOG_TRACE("%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset);
				} while (0);
			}
			// 0x0f 0x8x xx xx xx xx ���ֽ������ת
			else if (instruction.info.length == 6 && *(PUCHAR)runtime_address == 0x0f && *(PCUCHAR)(runtime_address + 1) <= 0x8f && *(PCUCHAR)(runtime_address + 1) >= 0x80)
			{
#define OPCODE_LENGTH 2
#define OFFSET_TYPE LONG
				do
				{
					// 1.ȷ������ָ��ԭ��Ҫ��ת���ĸ���ַ
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(OFFSET_TYPE*)(runtime_address + OPCODE_LENGTH); // ��һ����ַ+offset
					LOG_TRACE("original_jx_addr = %llx\r\n", original_jx_addr);

					// 1.1.�ж�����ָ����ת�ĵ�ַ�ǲ��������Ǹ��Ƶ�buffer��Χ�ڣ�����eb 02�����������������ȥ�Ļ�Ҳ�����Ӧ�ò�ȥ�޸�����
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// ���ȷʵ�ڷ�Χ�ڣ���ȥ�޸ģ�ֱ��break
						break;
					}
					// 2.����ff25jmp��д������

					// ��������ff25�ĵ�ַ���ں�������jcc��ת�ĵ�ַ��ʱ������õ�
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

					// 3.����jcc��ת�ĵ�ַ����֤���ܹ���ȷ��ת���ղŹ����ff25jmp��
					LOG_TRACE("runtime_address = %llx\r\n", runtime_address);
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						LOG_TRACE("offset_for_jx < 0 || offset_for_jx == 0\r\n");
						freeMemory(handler_addr);
						freeMemory(shellcode_origin_addr);
						return STATUS_INTERNAL_ERROR;
					}
					// д��jcc��ת�ĵ�ַ��ȥ��
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					LOG_TRACE("%llx\r\n", shellcode_origin_addr);
					LOG_TRACE("%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset);
				} while (0);
			}
			// 0xe8(0xe9) xx xx xx xx ���ֽ������ת
			else if (instruction.info.length == 5 && (*(PUCHAR)runtime_address == 0xe8 || *(PUCHAR)runtime_address == 0xe9))
			{
#define OPCODE_LENGTH 1
#define OFFSET_TYPE LONG
				do
				{
					// 1.ȷ������ָ��ԭ��Ҫ��ת���ĸ���ַ
					ULONG64 original_jx_addr = funcAddr + cur_disasm_offset + instruction.info.length + *(OFFSET_TYPE*)(runtime_address + OPCODE_LENGTH); // ��һ����ַ+offset
					LOG_TRACE("original_jx_addr = %llx\r\n", original_jx_addr);

					// 1.1.�ж�����ָ����ת�ĵ�ַ�ǲ��������Ǹ��Ƶ�buffer��Χ�ڣ�����eb 02�����������������ȥ�Ļ�Ҳ�����Ӧ�ò�ȥ�޸�����
					if (original_jx_addr >= funcAddr && original_jx_addr < funcAddr + inslen)
					{
						// ���ȷʵ�ڷ�Χ�ڣ���ȥ�޸ģ�ֱ��break
						break;
					}
					// 2.����ff25jmp��д������

					// ��������ff25�ĵ�ַ���ں�������jcc��ת�ĵ�ַ��ʱ������õ�
					ULONG64 t_ff25jmp_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len;

					*(PULONG64)&bufcode[6] = original_jx_addr;
					RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
					resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

					// 3.����jcc��ת�ĵ�ַ����֤���ܹ���ȷ��ת���ղŹ����ff25jmp��
					LOG_TRACE("runtime_address = %llx\r\n", runtime_address);
					ULONG64 t_dummy = t_ff25jmp_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length);
					OFFSET_TYPE offset_for_jx = *(OFFSET_TYPE*)(&t_dummy);
					if (offset_for_jx < 0 || offset_for_jx == 0)
					{
						LOG_TRACE("offset_for_jx < 0 || offset_for_jx == 0\r\n");
						freeMemory(handler_addr);
						freeMemory(shellcode_origin_addr);
						return STATUS_INTERNAL_ERROR;
					}
					// д��jcc��ת�ĵ�ַ��ȥ��
					*(OFFSET_TYPE*)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + OPCODE_LENGTH) = offset_for_jx;
					LOG_TRACE("%llx\r\n", shellcode_origin_addr);
					LOG_TRACE("%llx\r\n", shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset);
				} while (0);
			}
			// ��������������ֽ�disp��Ե�ַ
			else if (instruction.info.raw.disp.size == 0x20)
			{
				LOG_INFO("δ���⴦�����Ѱַ��%llx", funcAddr + cur_disasm_offset);
				for (int i = 0; i < instruction.info.length; i++)
					LOG_INFO_NOPREFIX(" %02hhx", *(PUCHAR)(funcAddr + cur_disasm_offset + i));
				LOG_INFO_NOPREFIX(" %s\r\n", instruction.text);




				//return STATUS_NOT_SUPPORTED;
	/*			static int t = 0;
				t++;
				if (t > 50)
				{
					return STATUS_NOT_FOUND;
				}*/
				// 1.��ģ���ڲ���һ���������ŵ�ǰ����+ff25jmp����ĵ�ַ
				PUCHAR module_blank_area = get_blank_space_in_module(funcAddr, instruction.info.length + sizeof(bufcode));
				if (module_blank_area == NULL)
				{
					//DbgBreakPoint();
					LOG_INFO("can't find blank space in module\r\n");
					freeMemory(handler_addr);
					freeMemory(shellcode_origin_addr);

					return STATUS_NOT_FOUND;
				}
				LOG_INFO("found blank space %p length %llx\r\n", module_blank_area, instruction.info.length + sizeof(bufcode));

				writeToKernel(module_blank_area, runtime_address, instruction.info.length);

				// 2.����ת�����ĵ�ַд��bufcode����ת��ַ����
				ULONG64 addr_to_jmp_back = shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + instruction.info.length;
				*(PULONG64)&bufcode[6] = addr_to_jmp_back;

				// �޸�module_blank_area��fff25jmp����ת��ַΪ��һ��ָ��ĵ�ַ������ӵ�module_blank_area��
				writeToKernel(module_blank_area + instruction.info.length, bufcode, sizeof(bufcode));

				// TODO:��������ж�һ���Ƿ���2GB�ڣ�����ڵĻ��Ͳ������������ȥ�Ĵ�����
				// 3.������Ե�ַ��ȡ��Ե�ַ��Ӧ�ľ��Ե�ַ
				LONG cur_offset = *(PLONG)(runtime_address + instruction.info.raw.disp.offset);
				ULONG64 resolved_addr = runtime_address + instruction.info.length + cur_offset;

				// 4.��������checkһ�ּ�����������������67:0005 00000000���ִ��롣
				CHAR disasm_text_buf[96] = { 0 };
				// TODO:sprintf����ȫ���Ժ���Ի��ɰ�ȫ�ĺ�����
				sprintf(disasm_text_buf, "%llX", resolved_addr);
				if (strstr(instruction.text, disasm_text_buf) == 0)
				{
					// ֻ��һ�ִ�����ܵ����������runtime_address+length+disp�õ���Եĵ�ַ�� 67:0005 00000000 ���ִ���һ��address-size override prefix�Ĵ��롣����eipѰַ���������ִ���Ҳ̫�����ˣ��������Ժ��ԣ�û�б�����������д�����
					freeMemory(handler_addr);
					freeMemory(shellcode_origin_addr);
					return STATUS_INTERNAL_ERROR;
				}

				// 5.����disp����Ե�ַ������ָ��ͬһ��������
				// ����Ե�ַ��Ӧ�ľ��Ե�ַ��ȥ��һ��ָ�����ʼ��ַ
				ULONG64 t_dummy = resolved_addr - ((ULONG64)module_blank_area + instruction.info.length);
				// ���룬������
				writeToKernel((ULONG64)module_blank_area + instruction.info.raw.disp.offset, &t_dummy, sizeof(LONG));

				// 6.shellcode��ff25������jmp��module_blank_area����ӵ�����ֽ�disp�Ĵ����ִ�С�
				*(PULONG64)&bufcode[6] = module_blank_area;
				RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));
				resolve_relative_code_len += sizeof(bufcode); // resolve�Ĵ��볤��+=sizeof bufcode

				// 7.�޸�shellcode�еĶ�Ӧ���룬���eb xx������һ�����µ�ff25shellcode��
				ULONG64 ff25shellcode_addr = shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len - sizeof(bufcode);
				t_dummy = ff25shellcode_addr - (shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + 2);
				if (*(PCHAR)&t_dummy <= 0)
				{
					freeMemory(handler_addr);
					freeMemory(shellcode_origin_addr);
					return STATUS_INTERNAL_ERROR;
				}

				// 8.����eb xx
				*(PUCHAR)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset) = 0xEB;
				*(PCHAR)(shellcode_origin_addr + sizeof(resume_code) + cur_disasm_offset + 1) = *(PCHAR)&t_dummy;
				// TODO:���������90����CC֮��ģ����ﲻ����
			}
			else
			{
				freeMemory(handler_addr);
				freeMemory(shellcode_origin_addr);
				return STATUS_INTERNAL_ERROR;
			}
		}


		cur_disasm_offset += instruction.info.length;
		runtime_address += instruction.info.length;
	}

	// �Ѻ����Ǹ�������ת��ԭ�����Ǹ�jmp��eb�޸�һ��
	if (resolve_relative_code_len > 0x79)
	{
		LOG_TRACE("resolve_relative_code_len > 0x79\r\n");
		freeMemory(handler_addr);
		freeMemory(shellcode_origin_addr);
		return STATUS_INTERNAL_ERROR;
	}
	ULONG64 t_dummy = resolve_relative_code_len - 2;
	*(PCHAR)(shellcode_origin_addr + sizeof(resume_code) + inslen + 1) = *(PCHAR)(&t_dummy);
	// ��ff25 jmp����ԭ����ַ�Ĵ��뿽����ABC�ĺ���
	*(PULONG64)&bufcode[6] = funcAddr + inslen;
	RtlMoveMemory(shellcode_origin_addr + sizeof(resume_code) + inslen + resolve_relative_code_len, bufcode, sizeof(bufcode));

	// �޸�handler_shellcode+0x28������HookHandler
	// �޸�handler_shellcode+0x43������
	*(PULONG64)(handler_addr + 37) = callbackFunc;
	*(PULONG64)(handler_addr + 68) = shellcode_origin_addr;

	if (!g_hook_record_head)
	{
		g_hook_record_head = allocateMemory(PAGE_SIZE);
		InitializeListHead(&g_hook_record_head->entry);
	}

	// �����¼
	phook_record record = allocateMemory(PAGE_SIZE);
	record->num = g_record_ct;
	*record_number = g_record_ct;
	g_record_ct++;
	record->addr = funcAddr;
	record->len = inslen;
	record->handler_addr = handler_addr;
	record->shellcode_origin_addr = shellcode_origin_addr;
	RtlMoveMemory(&record->buf, funcAddr, inslen);
	//InsertHeadList(&head->entry, &record->entry);
	InitializeListHead(&record->entry);
	my_AppendTailList(&g_hook_record_head->entry, &record->entry);

	// patchԭ����
	*(PULONG64)&bufcode[6] = handler_addr;
	writeToKernelWithDPC(funcAddr, bufcode, sizeof(bufcode));

	return STATUS_SUCCESS;
}

ULONG64 KeFlushEntireTb();

NTSTATUS reset_hook(ULONG64 record_number)
{
	if (!g_hook_record_head)
	{
		return STATUS_NOT_FOUND;
	}

	PLIST_ENTRY entry = g_hook_record_head->entry.Flink;
	while (entry != &g_hook_record_head->entry)
	{
		phook_record cur = CONTAINING_RECORD(entry, hook_record, entry);

		if (cur->num == record_number)
		{
			writeToKernelWithDPC(cur->addr, &cur->buf, cur->len);
			freeMemory(cur->handler_addr);
			freeMemory(cur->shellcode_origin_addr);
			RemoveEntryList(&cur->entry);
			freeMemory(cur);
			KeFlushEntireTb();
			return STATUS_SUCCESS;
		}

		entry = entry->Flink;
	}

	return STATUS_NOT_FOUND;
}


// prehandler��ʽ��������
// cmp XXX
// jnz ��������ԭ����code������ԭʼ�߼���Ȼ�����ص�ԭ��λ��  ; ��һЩ���������ж�
// jmp [eip]  ; һ��ff25 jmp��offset��0
// 00 00
// 00 00
// 00 00
// 00 00
// @��������ԭ����code������ԭʼ�߼���Ȼ�����ص�ԭ��λ��
// ; ������ԭʼ�߼��ɺ���Ĵ����Զ����룬�����ֶ�д��
// 
// 
// ע�������п��ܻᵼ��eflags�ĸı䡣�����Ҫ���ı�eflags����Ҫ��ջ���ٱ���һ��eflags��
// ��hook��һ���ǳ�Ƶ�������õĺ���ʱ����������prehandler����prehandler�н���Ԥ�������ĳ������������Ҫ�󣬾Ͳ���������ı���context��handler��ȥ��
// ��һ��������hook��ţ��ڶ���������prehandler�����Ƶĵ�ַ��������������prehandler������Ĵ�С�����ĸ�������prehandler����jmp��Ŀ���ַ��ƫ�ƣ������滻��
// ������handler_addr+0x600��λ�á����Ҫȷ��prehandler_buf_sizeС��0x400
NTSTATUS set_fast_prehandler(ULONG64 record_number, PUCHAR prehandler_buf, ULONG64 prehandler_buf_size, ULONG64 jmp_addr_offset)
{
	if (!g_hook_record_head)
	{
		return STATUS_NOT_FOUND;
	}

	if (prehandler_buf_size > 0x350)
	{
		return STATUS_NO_MEMORY;
	}

	phook_record cur = g_hook_record_head->entry.Flink;
	BOOLEAN flag = FALSE;

	while (cur != g_hook_record_head)
	{
		if (cur->num == record_number)
		{
			flag = TRUE;
			PUCHAR prehook_buf_addr = (PUCHAR)(cur->handler_addr + 0x600);
			// �Ȱ�prehandler������+0x600��λ��
			RtlMoveMemory(prehook_buf_addr, prehandler_buf, prehandler_buf_size);
			// ���Ȼ�ȡhook����Ǹ�ff25��ת�ĵ�ַ��
			PULONG64 phook_point_jmp_addr = (PULONG64)((ULONG64)cur->addr + 6);
			ULONG64 hook_point_jmp_addr = *phook_point_jmp_addr;
			// Ȼ��������ת�ĵ�ַ���뵽prehandler��Ӧ��jmp_addr_offset��
			PULONG64 pPrehandlerJmpAddr = (PULONG64)((ULONG64)prehook_buf_addr + jmp_addr_offset);
			*pPrehandlerJmpAddr = hook_point_jmp_addr;

			// ���ѱ�����ֽڿ�����prehandler�����
			RtlMoveMemory(prehook_buf_addr + prehandler_buf_size, cur->buf, cur->len);
			// ��ff25��ת��ԭ�����Ĵ��뿽�����������
			UCHAR t_ff25_jmp_buf[] = {
				0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr ds : [7FF806EA0974] 
				0x00, 0x00, // add byte ptr ds : [rax] ,al 
				0x00, 0x00, // add byte ptr ds : [rax] ,al 
				0x00, 0x00, // add byte ptr ds : [rax] ,al 
				0x00, 0x00, // add byte ptr ds : [rax] ,al 
			};



			ULONG64 t_jmp_back_addr = cur->addr + cur->len;


			RtlMoveMemory(t_ff25_jmp_buf + 6, &t_jmp_back_addr, sizeof(ULONG64));
			RtlMoveMemory(prehook_buf_addr + prehandler_buf_size + cur->len, t_ff25_jmp_buf, sizeof t_ff25_jmp_buf);
			// ͨ��ԭ�Ӳ�����ԭʼ��hook���ff25��ת��λ�ý�����Ӧ���޸ģ���Ϊprehandler�ĵ�ַ
			//InterlockedExchange64(phook_point_jmp_addr, prehook_buf_addr);
			writeToKernel(phook_point_jmp_addr, &prehook_buf_addr, sizeof(PUCHAR));

			break;
		}
		cur = cur->entry.Flink;
	}

	if (!flag) return STATUS_NOT_FOUND;
	else return STATUS_SUCCESS;
}
























