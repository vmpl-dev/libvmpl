#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    // 申请一块内存，以便获取堆的起始地址
    void *heap_start = sbrk(0);

    // 申请一块小内存，以便获取堆的结束地址
    void *temp = malloc(10); // 假设分配了一块 10 字节大小的内存
    void *heap_end = sbrk(0);

    // 打印堆的起始和结束地址
    printf("Heap start address: %p\n", heap_start);
    printf("Heap end address: %p\n", heap_end);

    // 释放临时申请的内存
    free(temp);

    return 0;
}
