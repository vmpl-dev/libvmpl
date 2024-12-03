#define _GNU_SOURCE
#include <cpuid.h>

#include "vmpl.h"
#include "log.h"
#include "platform.h"

// 已注册的平台驱动链表
static struct vm_driver *vm_drivers = NULL;

// 平台匹配表
static const struct vm_platform_id_entry platform_ids[] = {
    { 
        .vendor = "GenuineIntel",
        .vendor_id = 0x756E6547,        // "GenuineIntel"
        .feature_mask = (1 << 5),       // VMX位
        .platform_id = VM_PLATFORM_INTEL_VTX 
    },
    { 
        .vendor = "AuthenticAMD",
        .vendor_id = 0x68747541,        // "AuthenticAMD" 
        .feature_mask = (1 << 1),       // SVM位
        .platform_id = VM_PLATFORM_AMD_SEV
    },
    { 0 }
};

// 注册平台驱动
int register_vm_driver(struct vm_driver *driver)
{
    if (!driver || !driver->ops) {
        return -1;
    }

    // 添加到链表头部
    driver->next = vm_drivers;
    vm_drivers = driver;
    
    log_info("Registered VM platform driver: %s", driver->name);
    return 0;
}

// 注销平台驱动
void unregister_vm_driver(struct vm_driver *driver)
{
    struct vm_driver **pp = &vm_drivers;
    
    while (*pp) {
        if (*pp == driver) {
            *pp = driver->next;
            log_info("Unregistered VM platform driver: %s", driver->name);
            return;
        }
        pp = &(*pp)->next;
    }
}

// 检测CPU并匹配平台
static enum vm_platform_id detect_platform(void)
{
    unsigned int eax, ebx, ecx, edx;
    uint32_t vendor[4] = {0};  // 用于存储供应商字符串
    
    // 获取供应商字符串
    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        log_err("Failed to get CPU vendor");
        return VM_PLATFORM_UNKNOWN;
    }
    
    // 按照标准顺序存储供应商字符串
    vendor[0] = ebx;
    vendor[1] = edx;
    vendor[2] = ecx;
    vendor[3] = 0;

    log_info("CPU Vendor: %.12s", (char *)vendor);

    // 获取特性标志
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return VM_PLATFORM_UNKNOWN;
    }

    log_info("CPU Features - ECX: 0x%08x, EDX: 0x%08x", ecx, edx);

    // 遍历匹配表
    for (const struct vm_platform_id_entry *entry = platform_ids; entry->vendor_id; entry++) {
        if (strcmp(entry->vendor, (char *)vendor) != 0) {
            continue;
        }

        log_info("Detected vendor: %s", entry->vendor);

        // 检查特性位
        if ((ecx & entry->feature_mask) == entry->feature_mask) {
            log_info("Detected platform ID: %d", entry->platform_id);
            return entry->platform_id;
        }
    }

    return VM_PLATFORM_UNKNOWN;
}

// 查找匹配的平台驱动
struct vm_ops *find_vm_ops(void)
{
    enum vm_platform_id platform_id = detect_platform();
    struct vm_driver *driver;

    if (platform_id == VM_PLATFORM_UNKNOWN) {
        return NULL;
    }

    // 遍历已注册驱动查找匹配项
    for (driver = vm_drivers; driver; driver = driver->next) {
        if (driver->platform_id == platform_id) {
            log_info("Found matching platform: %s", driver->name);
            return driver->ops;
        }
    }

    return NULL;
} 