#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>

void print_mmap_limit() {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_AS, &rlim) == 0) {
        printf("Current process's mmap limit: %llu bytes\n", (unsigned long long)rlim.rlim_cur);
    } else {
        perror("getrlimit");
    }
}

#define MAP_START   NULL
#define MAP_SIZE    0x20000000UL       // 512MB

int main() {
    int fd;
    off_t offset = 0;
    void *mapped_area;

    print_mmap_limit();

    // Open /dev/zero pseudo-device to map memory
    fd = open("/dev/zero", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/zero");
        return EXIT_FAILURE;
    }

    // Map 64GB of virtual memory
    void *va_start = MAP_START;
    size_t size = MAP_SIZE;
    mapped_area = mmap(va_start, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, offset);
    if (mapped_area == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        return EXIT_FAILURE;
    }

    // Access the mapped memory (optional)
    printf("mapped_area: %lx, size: %lx\n", (unsigned long)mapped_area, size);

    // Print /proc/self/maps
    printf("/proc/self/maps content:\n");
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (maps_file == NULL) {
        perror("Failed to open /proc/self/maps");
        munmap(mapped_area, MAP_SIZE);
        close(fd);
        return EXIT_FAILURE;
    }

    char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), maps_file)) > 0) {
        fwrite(buffer, 1, bytes_read, stdout);
    }

    fclose(maps_file);

    // Unmap the memory
    if (munmap(mapped_area, MAP_SIZE) < 0) {
        perror("munmap failed");
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);
    return EXIT_SUCCESS;
}
