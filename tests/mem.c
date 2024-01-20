#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    int fd;
    unsigned long va; // virtual address
    unsigned long pa; // physical address
    void *ptr;

    // Open /dev/mem file
    fd = open("/dev/mem", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    // TODO: Replace this with the actual virtual address
    va = malloc(sizeof(int));

    // Map one page
    ptr = mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE, fd, va);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    // Read the physical address
    pa = *(unsigned long *)ptr;

    printf("Physical address: %lx\n", pa);

    // Clean up
    munmap(ptr, getpagesize());
    close(fd);

    return 0;
}