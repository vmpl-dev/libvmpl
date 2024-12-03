#include "entry.h"

// 定义平台ID
enum vm_platform_id {
    VM_PLATFORM_UNKNOWN = 0,
    VM_PLATFORM_INTEL_VTX,
    VM_PLATFORM_AMD_SEV,
    VM_PLATFORM_MAX
};

// 平台匹配结构
struct vm_platform_id_entry {
    char vendor[13];      // CPU厂商ID
    uint32_t vendor_id;      // CPU厂商ID
    uint32_t feature_mask;   // 特性位掩码
    enum vm_platform_id platform_id;
};

// 平台驱动结构
struct vm_driver {
    const char *name;                    // 驱动名称
    enum vm_platform_id platform_id;     // 平台ID
    const struct vm_ops *ops;            // 平台操作接口
    struct vm_driver *next;              // 链表指针
};

// 平台注册/注销接口
int register_vm_driver(struct vm_driver *driver);
void unregister_vm_driver(struct vm_driver *driver);
struct vm_ops *find_vm_ops(void);

// 平台驱动注册宏
#define DECLARE_VM_DRIVER(_name, _platform_id, _ops) \
    static struct vm_driver __vm_driver_##_name = { \
        .name = #_name, \
        .platform_id = _platform_id, \
        .ops = _ops, \
    }; \
    static void __attribute__((constructor)) __vm_driver_init_##_name(void) { \
        register_vm_driver(&__vm_driver_##_name); \
    } \
    static void __attribute__((destructor)) __vm_driver_exit_##_name(void) { \
        unregister_vm_driver(&__vm_driver_##_name); \
    }

// 优先级版本的注册宏
#define DECLARE_VM_DRIVER_PRIORITY(_name, _platform_id, _ops, _priority) \
    static struct vm_driver __vm_driver_##_name = { \
        .name = #_name, \
        .platform_id = _platform_id, \
        .ops = _ops, \
    }; \
    static void __attribute__((constructor(_priority))) __vm_driver_init_##_name(void) { \
        register_vm_driver(&__vm_driver_##_name); \
    } \
    static void __attribute__((destructor(_priority))) __vm_driver_exit_##_name(void) { \
        unregister_vm_driver(&__vm_driver_##_name); \
    }
