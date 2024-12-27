#ifndef __ENTRY_H_
#define __ENTRY_H_

#include <stdbool.h>
#include "page.h"
#include "mm.h"
#include "vmpl.h"
#include "percpu.h"
#include "vmpl-dev.h"

// 虚拟机CPU操作接口
struct vcpu_ops {
    struct percpu *(*alloc)();
    int (*free)(struct percpu *percpu);
    int (*init)(struct percpu *percpu);
    int (*enter)(struct percpu *percpu);
    int (*boot)(struct percpu *percpu);
    void (*dump)(struct percpu *percpu);
    int (*fpu_init)(struct percpu *percpu);
    int (*fpu_finish)(struct percpu *percpu);
};

// 虚拟化平台操作接口
struct vm_ops {
    const char *name;                     // 平台名称
    int (*init)(bool map_full);          // 初始化函数
    void (*banner)(void);                  // 打印banner
    void (*exit)(struct dune_config *);   // 退出处理
    void (*syscall)(struct dune_config *);// 系统调用处理
    void (*cleanup)(void);               // 清理资源
    void (*stats)(void);                  // 统计信息
    void (*test)(void);                   // 测试函数
    struct vcpu_ops vcpu_ops;            // 虚拟机CPU操作接口
};

// 虚拟化上下文
struct vmpl_context {
    int dune_fd;
    struct page_manager *g_manager;
    struct vmpl_mm_t *vmpl_mm;
    struct vm_ops *ops;
};

struct vmpl_context *get_current_context(void);
void set_current_context(struct vmpl_context *ctx);

#define BUILD_ASSERT(cond) _Static_assert(cond, #cond)

#endif /* __ENTRY_H_ */