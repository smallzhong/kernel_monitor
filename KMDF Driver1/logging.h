#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <ntdef.h>
#include <ntimage.h>

// ��־������
#define LOG_LEVEL_NONE    0
#define LOG_LEVEL_FATAL   1
#define LOG_LEVEL_ERROR   2
#define LOG_LEVEL_WARNING 3
#define LOG_LEVEL_INFO    4
#define LOG_LEVEL_DEBUG   5
#define LOG_LEVEL_TRACE   6

// ȫ�ֱ�������̬������־���𣬳�ʼֵ����Ϊ��ߵȼ�
EXTERN_C ULONG g_LogLevel; // Ĭ��Ϊ LOG_LEVEL_TRACE������������ʱ���е���

// �жϵ�ǰ��־�����Ƿ������¼
#define LOG_IS_ENABLED(level) (g_LogLevel >= (level))

// ��־�궨��
#define LOG_FATAL(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_FATAL)) { \
            DbgPrintEx(77, 0, "[F][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            DbgBreakPoint(); \
        } \
    } while (0)

#define LOG_FATAL_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_FATAL)) { \
            DbgPrintEx(77, 0, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_ERROR(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_ERROR)) { \
            DbgPrintEx(77, 0, "[E][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_ERROR_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_ERROR)) { \
            DbgPrintEx(77, 0, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_WARN(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_WARNING)) { \
            DbgPrintEx(77, 0, "[W][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_WARN_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_WARNING)) { \
            DbgPrintEx(77, 0, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_INFO(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_INFO)) { \
            DbgPrintEx(77, 0, "[I][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_INFO_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_INFO)) { \
            DbgPrintEx(77, 0, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_DEBUG(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_DEBUG)) { \
            DbgPrintEx(77, 0, "[D][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_DEBUG_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_DEBUG)) { \
            DbgPrintEx(77, 0, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_TRACE(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_TRACE)) { \
            DbgPrintEx(77, 0, "[T][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_TRACE_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_TRACE)) { \
            DbgPrintEx(77, 0, fmt, ##__VA_ARGS__); \
        } \
    } while (0)
