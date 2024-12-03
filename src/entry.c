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

// 当前使用的虚拟化平台
static const struct vm_ops *current_vm_ops = NULL;
int dune_fd;
__thread void *lpercpu = NULL;

/**
 * @brief 检测CPU是否支持虚拟化并选择合适的平台
 * @return const struct vm_ops* 平台操作接口指针，NULL表示不支持
 */
static const struct vm_ops *detect_vm_platform(void) {
    unsigned int eax, ebx, ecx, edx;
    
    // 检查 AMD SVM
    if (__get_cpuid(0x80000001, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1 << 2)) { // SVM bit
            return register_vmpl_ops();
        }
    }
    
    vmpl_set_last_error(VMPL_ERROR_NOT_SUPPORTED);
    return NULL;
}

/**
 * @brief 统一初始化入口
 */
int vmpl_init(bool map_full) {
    // 检测并选择虚拟化平台
    current_vm_ops = detect_vm_platform();
    if (!current_vm_ops) {
        vmpl_set_last_error(VMPL_ERROR_NOT_SUPPORTED);
        return -1;
    }

    return current_vm_ops->init(map_full);
}

/**
 * @brief 统一进入虚拟化模式入口
 */
int vmpl_enter(int argc, char *argv[]) {
    void *percpu = NULL;
    int ret = 0;
    // 检查虚拟化平台是否已初始化
    if (!current_vm_ops) {
        vmpl_set_last_error(VMPL_ERROR_NOT_INITIALIZED);
        return -1;
    }

    // 初始化虚拟机CPU操作接口
    struct vcpu_ops *vcpu_ops = &current_vm_ops->vcpu_ops;

    // 如果percpu已经存在，则直接进入虚拟化模式
    if (lpercpu) {
        ret = vcpu_ops->enter(lpercpu);
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
    lpercpu = percpu;

    // 打印banner
    current_vm_ops->banner();

    return 0;

failed:
    free_percpu(percpu);
    current_vm_ops->cleanup();
    return ret;
}

int dune_enter_ex(void *percpu)
{
	int ret;
    struct vm_ops *current_vm_ops;

    if ((current_vm_ops = detect_vm_platform()) == NULL) {
        vmpl_set_last_error(VMPL_ERROR_NOT_INITIALIZED);
        return -EINVAL;
    }

    struct vcpu_ops *vcpu_ops = &current_vm_ops->vcpu_ops;

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
    if (current_vm_ops) {
        current_vm_ops->cleanup();
        current_vm_ops->exit(conf);
    }
    // 不会执行到这里，因为exit处理函数不会返回
}
