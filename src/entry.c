#include <cpuid.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmpl.h"
#include "log.h"
#include "entry.h"
#include "percpu.h"
#include "error.h"
#include "platform.h"

int dune_fd;
static struct vmpl_context *g_context = NULL;

static struct vmpl_context *vmpl_context_create(void) {
    struct vmpl_context *ctx = malloc(sizeof(struct vmpl_context));
    if (!ctx) {
        log_err("Failed to allocate memory for vmpl_context");
        exit(EXIT_FAILURE);
    }

    memset(ctx, 0, sizeof(struct vmpl_context));

    ctx->dune_fd = -1;
    ctx->g_manager = NULL;
    ctx->vmpl_mm = NULL;
    ctx->ops = NULL;
    return ctx;
}

static void vmpl_context_destroy(struct vmpl_context *ctx) {
    if (ctx) {
        free(ctx);
    }
}

void set_current_context(struct vmpl_context *ctx) {
    g_context = ctx;
}

struct vmpl_context *get_current_context(void) {
    return g_context;
}

/**
 * @brief 检测CPU是否支持虚拟化并选择合适的平台
 * @return const struct vm_ops* 平台操作接口指针，NULL表示不支持
 */
static struct vm_ops *detect_vm_platform(void) {
    struct vm_ops *ops = find_vm_ops();
    if (!ops) {
        log_err("No supported platform found");
        vmpl_set_last_error(VMPL_ERROR_NOT_SUPPORTED);
    }
    return ops;
}

/**
 * @brief 统一初始化入口
 */
int vmpl_init(bool map_full) {
    // 确保 context 已初始化
    if (!g_context) {
        g_context = vmpl_context_create();
    }

    // 检测并选择虚拟化平台
    g_context->ops = detect_vm_platform();
    if (!g_context->ops) {
        vmpl_set_last_error(VMPL_ERROR_NOT_SUPPORTED);
        return -1;
    }

    // 打印虚拟化平台信息
    log_info("Detected platform: %s", g_context->ops->name);

    return g_context->ops->init(map_full);
}

/**
 * @brief 统一进入虚拟化模式入口
 */
int vmpl_enter(int argc, char *argv[]) {
    void *percpu = NULL;
    int ret = 0;
    
    // 检查虚拟化平台是否已初始化
    if (!g_context || !g_context->ops) {
        vmpl_set_last_error(VMPL_ERROR_NOT_INITIALIZED);
        return -1;
    }

    // 打印虚拟化平台信息
    log_info("Detected platform: %s", g_context->ops->name);

    // 初始化虚拟机CPU操作接口
    struct vcpu_ops *vcpu_ops = &g_context->ops->vcpu_ops;

    // 如果percpu已经存在，则直接进入虚拟化模式
    percpu = get_current_percpu();
    if (percpu) {
        ret = vcpu_ops->enter(percpu);
        if (ret != 0) {
            vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
            return ret;
        }
        return 0;
    }

    // 创建percpu
    percpu = create_percpu();
    if (!percpu) {
        vmpl_set_last_error(VMPL_ERROR_OUT_OF_MEMORY);
        return -1;
    }

    // 进入虚拟化模式前处理
    ret = vcpu_ops->init(percpu);
    if (ret != 0) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
        goto failed;
    }

    // 进入虚拟化模式
    ret = vcpu_ops->enter(percpu);
    if (ret != 0) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
        goto failed;
    }

    // 进入虚拟化模式后处理
    ret = vcpu_ops->boot(percpu);
    if (ret != 0) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
        goto failed;
    }

    // 设置percpu
    set_current_percpu(percpu);

#ifdef CONFIG_VMPL_BANNER
    // 打印banner
    g_context->ops->banner();
#endif
#ifdef CONFIG_VMPL_STATS
    // 打印统计信息
    g_context->ops->stats();
#endif
#ifdef CONFIG_VMPL_TEST
    // 测试
    g_context->ops->test();
#endif

    return 0;

failed:
    free_percpu(percpu);
    g_context->ops->cleanup();
    return ret;
}

int dune_enter_ex(void *percpu)
{
	int ret;

    if (!g_context || !g_context->ops) {
        vmpl_set_last_error(VMPL_ERROR_NOT_INITIALIZED);
        return -EINVAL;
    }

    struct vcpu_ops *vcpu_ops = &g_context->ops->vcpu_ops;

	// 进入虚拟化模式前处理
	ret = vcpu_ops->init(percpu);
	if (ret) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
		return ret;
	}

	// 进入虚拟化模式
	return vcpu_ops->enter(percpu);
}

/**
 * @brief 统一退出处理入口
 */
void on_dune_exit(struct dune_config *conf) {
    if (g_context && g_context->ops) {
        g_context->ops->cleanup();
        g_context->ops->exit(conf);
    }
    // 不会执行到这里，因为exit处理函数不会返回
}
