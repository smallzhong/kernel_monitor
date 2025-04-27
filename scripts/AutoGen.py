import idaapi
import idc
import idautils
import csv
import random


# FNV-1a 哈希
def runtime_hash(s):
    hash_value = 2166136261
    for c in s:
        hash_value = (hash_value ^ ord(c)) * 16777619
        # 使其保持在32-bit值范围内
        hash_value = hash_value & 0xFFFFFFFF
    return hash_value


def has_relative_addressing(start_ea, end_ea):
    """检查指定范围内是否存在相对寻址的指令"""
    current_ea = start_ea
    while current_ea < end_ea:
        # 获取当前指令
        insn = idaapi.insn_t()
        insn_size = idaapi.decode_insn(insn, current_ea)

        # 检查指令的操作数是否包含相对寻址
        for i in range(len(insn.ops)):
            if insn.ops[i].type in [idaapi.o_near, idaapi.o_mem]:
                return True

        current_ea += insn_size
        if insn_size == 0:
            break
    return False


def has_xrefs_to_middle(start_ea, end_ea):
    instr_size = idc.get_item_size(start_ea)
    start_ea += instr_size
    while start_ea < end_ea:
        t = idautils.CodeRefsTo(start_ea, False)
        for i in t:
            return True
        instr_size = idc.get_item_size(start_ea)
        start_ea += instr_size
    return False


def analyze_functions():
    """分析所有函数并导出结果"""
    funcs = []
    handler_declarations = []
    handler_implementations = []
    handler_map_entries = []

    with open('D:\\github_miscellaneous\\kernel_monitor\\KMDF Driver1\\function_analysis.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # 写入表头
        writer.writerow(['Function Name', 'Size', 'Size >= 16', 'Has Relative Addressing', 'Has Xrefs to Middle'])

        # 遍历所有函数
        for func_ea in idautils.Functions():
            # 获取函数对象
            func = idaapi.get_func(func_ea)
            if not func:
                continue

            # 1. 获取函数名
            func_name = idc.get_func_name(func_ea)

            # 2. 计算函数大小
            func_size = func.end_ea - func.start_ea
            size_ge_14 = func_size >= 14  # 实测12字节够了，后面的覆盖几条CC无伤大雅。
            if not size_ge_14:
                writer.writerow([
                    func_name,
                    func_size,
                    'No',
                    'No',
                    'No',
                ])
                continue

            # 计算至少16字节后的指令结束地址
            current_ea = func.start_ea
            total_size = 0
            analysis_end = func.start_ea
            while current_ea < func.end_ea and total_size < 16:
                instr_size = idc.get_item_size(current_ea)
                total_size += instr_size
                analysis_end = current_ea + instr_size
                current_ea += instr_size

            # 3. 检查前16字节是否有相对寻址
            has_relative = has_relative_addressing(func.start_ea, analysis_end)

            # 4. 检查是否有跳转到前16字节中间
            has_xrefs = has_xrefs_to_middle(func.start_ea, analysis_end)

            # 写入结果
            writer.writerow([
                func_name,
                func_size,
                'Yes' if size_ge_14 else 'No',
                'Yes' if has_relative else 'No',
                'Yes' if has_xrefs else 'No'
            ])

            if size_ge_14 and not has_xrefs:
                random_number = 1  # random.randint(1, 12)
                if random_number == 1:
                    func_hash = runtime_hash(func_name.strip())
                    funcs.append((func_hash, func_name))

                    # 生成处理程序声明
                    handler_name = f"handler_{func_hash:08x}"
                    handler_declaration = f"BOOLEAN {handler_name}(PGuestContext context);"
                    handler_declarations.append(handler_declaration)

                    # 生成处理程序实现
                    handler_implementation = f'''
BOOLEAN {handler_name}(PGuestContext context)
{{
    ULONG64 origin_ret_addr = *(PULONG64)(context->mRsp);
    if (FILTER_RET_ADDR(origin_ret_addr))
    {{
        LOG_INFO("Function: {func_name}\\nRCX: %llx, RDX: %llx, R8: %llx, R9: %llx\\nReturn Address: %llx\\n\\n", 
            context->mRcx, context->mRdx, context->mR8, context->mR9, origin_ret_addr);
    }}
    return FALSE;
}}'''
                    handler_implementations.append(handler_implementation)

                    # 生成映射表条目
                    handler_map_entries.append(f'{{ 0x{func_hash:08x}u, {handler_name} }}')

            print(f"Analyzed function: {func_name}")

    # 写入文件
    with open('D:\\github_miscellaneous\\kernel_monitor\\KMDF Driver1\\available_funcs.inc', 'w') as cpp_code:
        funcs.sort()
        for i in funcs:
            cpp_code.write(f'/* {i[1]} */ 0x{i[0]:08x}u,\n')

    # 写入处理程序声明(handlers.h)
    with open('D:\\github_miscellaneous\\kernel_monitor\\KMDF Driver1\\handlers.h', 'w') as handlers_header:
        handlers_header.write('''#pragma once
#include "hook.h"
#include "logging.h"
#include "MonitorAddressManager.h"

#ifdef __cplusplus
extern "C" {
#endif

// 运行时哈希函数声明
uint32_t RuntimeHash(const char* str);

// 函数处理程序声明
''')
        for handler_declaration in handler_declarations:
            handlers_header.write(handler_declaration + '\n')

        handlers_header.write('''
// 处理程序映射表结构
typedef struct {
    uint32_t func_hash;
    PFN_GUEST_CALLBACK handler;
} HandlerMapEntry;

// 处理程序查找函数声明
PFN_GUEST_CALLBACK find_handler_by_hash(uint32_t hash);
PFN_GUEST_CALLBACK find_handler_by_name(const char* func_name);

#ifdef __cplusplus
}
#endif
''')

    # 写入处理程序实现(handlers.c)
    with open('D:\\github_miscellaneous\\kernel_monitor\\KMDF Driver1\\handlers.c', 'w') as handlers_impl:
        handlers_impl.write('''#include "handlers.h"

// 运行时哈希函数 (与编译期哈希使用相同算法)
uint32_t RuntimeHash(const char* str) {
    uint32_t hash = 2166136261u;
    while (*str) {
        hash = (hash ^ (uint32_t)(*str)) * 16777619u;
        ++str;
    }
    return hash;
}

// 函数处理程序实现
''')
        for handler_impl in handler_implementations:
            handlers_impl.write(handler_impl + '\n\n')

        handlers_impl.write('''
// 处理程序映射表
static const HandlerMapEntry g_handler_map[] = {
''')
        for entry in handler_map_entries:
            handlers_impl.write('    ' + entry + ',\n')

        handlers_impl.write('''};

// 通过函数名哈希查找处理程序
PFN_GUEST_CALLBACK find_handler_by_hash(uint32_t hash) {
    for (int i = 0; i < sizeof(g_handler_map)/sizeof(g_handler_map[0]); i++) {
        if (g_handler_map[i].func_hash == hash) {
            return g_handler_map[i].handler;
        }
    }
    return NULL;
}

// 通过函数名查找处理程序
PFN_GUEST_CALLBACK find_handler_by_name(const char* func_name) {
    uint32_t hash = RuntimeHash(func_name);
    return find_handler_by_hash(hash);
}
''')


def main():
    print("Starting function analysis...")
    analyze_functions()
    print("Analysis complete. Results saved to function_analysis.csv")


if __name__ == '__main__':
    main()
