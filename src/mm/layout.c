#define _GNU_SOURCE
#include <assert.h>
#include "vmpl-dev.h"
#include "layout.h"
#include "page.h"
#include "pgtable.h"
#include "vm.h"
#include "vmpl.h"
#include "log.h"
#include "mapping.h"

// 全局配置实例
static struct vmpl_layout_t vmpl_cfg;
static struct dune_layout_t dune_cfg;

// VMPL配置初始化
static int vmpl_init_config(void) {
    vmpl_cfg.mmap_base = PGTABLE_MMAP_BASE;
    vmpl_cfg.mmap_end = PGTABLE_MMAP_END;
    vmpl_cfg.page_base = PAGEBASE;
    vmpl_cfg.max_pages = MAX_PAGES;
    vmpl_cfg.page_size = PAGE_SIZE;
    
    log_debug("VMPL config initialized: mmap_base=0x%lx, mmap_end=0x%lx", 
              vmpl_cfg.mmap_base, vmpl_cfg.mmap_end);
    return 0;
}

// VMPL映射策略实现
static bool vmpl_is_valid_va(uint64_t va) {
    return (va >= vmpl_cfg.mmap_base && va < vmpl_cfg.mmap_end);
}

static bool vmpl_is_valid_pa(uint64_t pa) {
    return (pa >= vmpl_cfg.page_base && 
            pa < (vmpl_cfg.page_base + vmpl_cfg.max_pages * vmpl_cfg.page_size));
}

static uint64_t vmpl_va_to_pa(uint64_t va) {
    if (!vmpl_is_valid_va(va)) {
        return 0;
    }
    return va - vmpl_cfg.mmap_base;
}

static uint64_t vmpl_pa_to_va(uint64_t pa) {
    if (!vmpl_is_valid_pa(pa)) {
        return 0;
    }
    return pa + vmpl_cfg.mmap_base;
}

// DUNE配置初始化
static int dune_init_config(void) {
    dune_cfg.phys_limit = phys_limit;
    dune_cfg.mmap_base = mmap_base;
    dune_cfg.stack_base = start_stack;
    dune_cfg.stack_size = GPA_STACK_SIZE;
    dune_cfg.map_size = GPA_MAP_SIZE;
    
    log_debug("DUNE config initialized: mmap_base=0x%lx, stack_base=0x%lx",
              dune_cfg.mmap_base, dune_cfg.stack_base);
    return 0;
}

// DUNE映射策略实现
static bool dune_is_valid_va(uint64_t va) {
    return (va >= VA_START && va < VA_END) && 
           ((va >= dune_cfg.stack_base) ||
            (va >= dune_cfg.mmap_base && va < dune_cfg.stack_base) ||
            (va < dune_cfg.mmap_base));
}

static bool dune_is_valid_pa(uint64_t pa) {
    return pa < dune_cfg.phys_limit;
}

static uint64_t dune_va_to_pa(uint64_t va) {
    if (va >= dune_cfg.stack_base) {
        return va - dune_cfg.stack_base + 
               dune_cfg.phys_limit - dune_cfg.stack_size;
    } else if (va >= dune_cfg.mmap_base) {
        return va - dune_cfg.mmap_base + 
               dune_cfg.phys_limit - dune_cfg.stack_size - dune_cfg.map_size;
    } else {
        return va;
    }
}

static uint64_t dune_pa_to_va(uint64_t pa) {
    if (pa >= (dune_cfg.phys_limit - dune_cfg.stack_size)) {
        return pa - (dune_cfg.phys_limit - dune_cfg.stack_size) + 
               dune_cfg.stack_base;
    } else if (pa >= (dune_cfg.phys_limit - dune_cfg.stack_size - dune_cfg.map_size)) {
        return pa - (dune_cfg.phys_limit - dune_cfg.stack_size - dune_cfg.map_size) + 
               dune_cfg.mmap_base;
    } else {
        return pa;
    }
}

// 映射策略定义
static const address_mapping_t vmpl_mapping = {
    .name = "VMPL",
    .init_config = vmpl_init_config,
    .va_to_pa = vmpl_va_to_pa,
    .pa_to_va = vmpl_pa_to_va,
    .is_valid_va = vmpl_is_valid_va,
    .is_valid_pa = vmpl_is_valid_pa,
};

static const address_mapping_t dune_mapping = {
    .name = "DUNE",
    .init_config = dune_init_config,
    .va_to_pa = dune_va_to_pa,
    .pa_to_va = dune_pa_to_va,
    .is_valid_va = dune_is_valid_va,
    .is_valid_pa = dune_is_valid_pa,
};

// 当前使用的映射策略
static const address_mapping_t *current_mapping = NULL;

// 公共接口实现
const address_mapping_t* get_vmpl_mapping(void) {
    return &vmpl_mapping;
}

const address_mapping_t* get_dune_mapping(void) {
    return &dune_mapping;
}

int mapping_init(bool use_dune) {
    int rc;
    
    // 根据选择的映射策略初始化配置
    if (use_dune) {
        current_mapping = &dune_mapping;
        log_info("Using DUNE mapping strategy");
    } else {
        current_mapping = &vmpl_mapping;
        log_info("Using VMPL mapping strategy");
    }

    // 初始化映射策略配置
    rc = current_mapping->init_config();
    if (rc != 0) {
        log_err("Failed to initialize mapping strategy config");
        return rc;
    }
    
    return 0;
}

const address_mapping_t* get_current_mapping(void) {
    assert(current_mapping != NULL);
    return current_mapping;
} 