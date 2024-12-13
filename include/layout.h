#ifndef _LAYOUT_H_
#define _LAYOUT_H_

#include <stdint.h>
#include <stdbool.h>

// VMPL配置结构体
struct vmpl_layout_t {
    uint64_t mmap_base;     // 映射基址
    uint64_t mmap_end;      // 映射结束地址
    uint64_t page_base;     // 页面基址
    uint64_t max_pages;     // 最大页面数
    uint64_t page_size;     // 页面大小
};

// DUNE配置结构体
struct dune_layout_t {
    uint64_t phys_limit;    // 物理内存限制
    uint64_t mmap_base;     // 映射内存基址
    uint64_t stack_base;    // 栈基址
    uint64_t stack_size;    // 栈大小
    uint64_t map_size;      // 映射内存大小
};

// 地址转换策略接口
typedef struct {
    const char *name;                          // 策略名称
    int (*init_config)(void);                  // 初始化配置
    uint64_t (*va_to_pa)(uint64_t va);        // 虚拟地址到物理地址的转换
    uint64_t (*pa_to_va)(uint64_t pa);        // 物理地址到虚拟地址的转换
    bool (*is_valid_va)(uint64_t va);         // 检查虚拟地址是否有效
    bool (*is_valid_pa)(uint64_t pa);         // 检查物理地址是否有效
    uintptr_t (*get_pagebase)(void);         // 获取页面基址
    uint64_t (*get_max_pages)(void);         // 获取最大页面数
} address_mapping_t;

// 获取VMPL映射策略
const address_mapping_t* get_vmpl_mapping(void);

// 获取DUNE映射策略
const address_mapping_t* get_dune_mapping(void);

// 初始化映射策略
int mapping_init(bool use_dune);

// 获取当前使用的映射策略
const address_mapping_t* get_current_mapping(void);

// 获取页面基址
uintptr_t get_pagebase(void);

// 获取最大页面数
uint64_t get_max_pages(void);

#endif /* _MAPPING_H_ */