#ifndef __ENTRY_H_
#define __ENTRY_H_

#include <stdbool.h>
#include "dune.h"
#include "vmpl.h"
#include "percpu.h"
#include "vmpl-dev.h"

// 虚拟机CPU操作接口
struct vcpu_ops {
    int (*init)(void *__percpu);         // 初始化函数
    int (*enter)(void *__percpu);        // 进入虚拟化模式
    int (*boot)(void *__percpu);        // 进入后处理函数
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

// 平台注册函数
const struct vm_ops *register_vmpl_ops(void);

#define BUILD_ASSERT(cond) _Static_assert(cond, #cond)

#endif /* __ENTRY_H_ */