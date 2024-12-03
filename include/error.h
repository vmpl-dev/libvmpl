#ifndef VMPL_ERROR_H
#define VMPL_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum vmpl_error_code {
    VMPL_SUCCESS = 0,                    // 成功
    VMPL_ERROR_INVALID_PARAM = -1,       // 无效参数
    VMPL_ERROR_OUT_OF_MEMORY = -2,       // 内存不足
    VMPL_ERROR_IO = -3,                  // IO错误
    VMPL_ERROR_NOT_INITIALIZED = -4,     // 未初始化
    VMPL_ERROR_ALREADY_INITIALIZED = -5, // 重复初始化
    VMPL_ERROR_NOT_SUPPORTED = -6,       // 不支持的操作
    VMPL_ERROR_TIMEOUT = -7,             // 超时
    VMPL_ERROR_BUSY = -8,               // 设备忙
    VMPL_ERROR_DEVICE_NOT_FOUND = -9,   // 设备未找到
    VMPL_ERROR_PERMISSION_DENIED = -10,  // 权限不足
    VMPL_ERROR_INVALID_STATE = -11,      // 无效状态
    VMPL_ERROR_RESOURCE_BUSY = -12,      // 资源忙
    VMPL_ERROR_RESOURCE_LIMIT = -13,     // 资源限制
    VMPL_ERROR_INVALID_ADDRESS = -14,    // 无效地址
    VMPL_ERROR_INVALID_OPERATION = -15,  // 无效操作
    VMPL_ERROR_INVALID_CPU = -16,        // 无效CPU
    VMPL_ERROR_INVALID_VCPU = -17,        // 无效VCPU
    VMPL_ERROR_INVALID_FPU = -18,         // 无效FPU
    VMPL_ERROR_INVALID_GDT = -19,         // 无效GDT
    VMPL_ERROR_INVALID_IDT = -20,         // 无效IDT
    VMPL_ERROR_INVALID_TSC = -21,         // 无效TSC
    VMPL_ERROR_INVALID_APIC = -22,        // 无效APIC
    VMPL_ERROR_UNKNOWN = -99             // 未知错误
} vmpl_error_t;

// 获取错误描述字符串
const char* vmpl_error_string(vmpl_error_t error);

// 设置最后的错误码
void vmpl_set_last_error(vmpl_error_t error);

// 获取最后的错误码
vmpl_error_t vmpl_get_last_error(void);

#ifdef __cplusplus
}
#endif

#endif // VMPL_ERROR_H