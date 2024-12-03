#include "error.h"
#include <string.h>

static __thread vmpl_error_t g_last_error = VMPL_SUCCESS;

// 错误码描述数组，按照错误码的绝对值索引
static const char* const error_messages[] = {
    [0] = "Success",                        // VMPL_SUCCESS
    [1] = "Invalid parameter",              // VMPL_ERROR_INVALID_PARAM
    [2] = "Out of memory",                  // VMPL_ERROR_OUT_OF_MEMORY
    [3] = "I/O error",                      // VMPL_ERROR_IO
    [4] = "Not initialized",                // VMPL_ERROR_NOT_INITIALIZED
    [5] = "Already initialized",            // VMPL_ERROR_ALREADY_INITIALIZED
    [6] = "Operation not supported",        // VMPL_ERROR_NOT_SUPPORTED
    [7] = "Operation timed out",            // VMPL_ERROR_TIMEOUT
    [8] = "Device or resource busy",        // VMPL_ERROR_BUSY
};

static const char unknown_error[] = "Unknown error";

const char* vmpl_error_string(vmpl_error_t error) {
    // 特殊处理 VMPL_ERROR_UNKNOWN
    if (error == VMPL_ERROR_UNKNOWN) {
        return unknown_error;
    }
    
    // 获取错误码的绝对值作为数组索引
    size_t index = (size_t)(-error);
    
    // 检查索引是否在有效范围内
    if (error > 0 || index >= sizeof(error_messages) / sizeof(error_messages[0]) || 
        error_messages[index] == NULL) {
        return unknown_error;
    }
    
    return error_messages[index];
}

void vmpl_set_last_error(vmpl_error_t error) {
    g_last_error = error;
}

vmpl_error_t vmpl_get_last_error(void) {
    return g_last_error;
}