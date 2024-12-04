cmake_minimum_required(VERSION 3.10)
project(libvmpl VERSION 1.0.0)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置编译器
set(CMAKE_C_COMPILER musl-gcc)

# 添加编译选项
add_compile_options(-Wall -Wextra)

# 添加x86特定指令集支持
add_compile_options(-mxsave)  # 支持xsave指令
add_compile_options(-mxsaveopt)  # 支持xsaveopt指令
add_compile_options(-mavx)  # 支持AVX指令集

# 定义配置选项
option(CONFIG_DUNE_BOOT "Enable DUNE boot configuration" ON)
if(CONFIG_DUNE_BOOT)
    add_definitions(-DCONFIG_DUNE_BOOT)
endif()

option(CONFIG_VMPL_DEBUG "Enable Vmpl debug" ON)
if(CONFIG_VMPL_DEBUG)
    add_definitions(-DCONFIG_VMPL_DEBUG)
endif()

# 源文件
file(GLOB_RECURSE SOURCES 
    "src/*.c"
    "src/core/*.c"
    "src/mm/*.c"
    "src/syscall/*.c"
    "src/vc/*.c"
    "src/utils/*.c"
)

# 头文件目录
include_directories(
    ${PROJECT_SOURCE_DIR}/../vmpl-dev
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
)

# 创建共享库
add_library(vmpl SHARED ${SOURCES})

# 设置版本号
set_target_properties(vmpl PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# 安装到指定目录
set(CMAKE_INSTALL_PREFIX /usr/local/musl)

# 安装规则
install(TARGETS vmpl
    LIBRARY DESTINATION lib
)

# 安装头文件
install(DIRECTORY include/
    DESTINATION include/vmpl
    FILES_MATCHING PATTERN "*.h"
) 

# 添加其他配置选项
option(CONFIG_VMPL_TEST "Enable vmpl test" OFF)
if(CONFIG_VMPL_TEST)
    add_definitions(-DCONFIG_VMPL_TEST)
endif()

option(CONFIG_VMPL_CPUSET "Enable cpuset" OFF)
if(CONFIG_VMPL_CPUSET)
    add_definitions(-DCONFIG_VMPL_CPUSET)
endif()

option(CONFIG_VMPL_SIGNAL "Enable signal" OFF)
if(CONFIG_VMPL_SIGNAL)
    add_definitions(-DCONFIG_VMPL_SIGNAL)
endif()

option(CONFIG_VMPL_APIC "Enable apic" ON)
if(CONFIG_VMPL_APIC)
    add_definitions(-DCONFIG_VMPL_APIC)
endif()

option(CONFIG_VMPL_MSR_PROTOCOL "Enable msr protocol" OFF)
if(CONFIG_VMPL_MSR_PROTOCOL)
    add_definitions(-DCONFIG_VMPL_MSR_PROTOCOL)
endif()

option(CONFIG_VMPL_GHCB "Enable ghcb" OFF)
if(CONFIG_VMPL_GHCB)
    add_definitions(-DCONFIG_VMPL_GHCB)
endif()

option(CONFIG_VMPL_MM "Enable mm" OFF)
if(CONFIG_VMPL_MM)
    add_definitions(-DCONFIG_VMPL_MM)
endif()

option(CONFIG_VMPL_SEIMI "Enable seimi" OFF)
if(CONFIG_VMPL_SEIMI)
    add_definitions(-DCONFIG_VMPL_SEIMI)
endif()

option(CONFIG_VMPL_HOTCALLS "Enable hotcalls" OFF)
if(CONFIG_VMPL_HOTCALLS)
    add_definitions(-DCONFIG_VMPL_HOTCALLS)
endif()

option(CONFIG_SYS_FILTER "Enable sys filter" OFF)
if(CONFIG_SYS_FILTER)
    add_definitions(-DCONFIG_SYS_FILTER)
endif()

option(CONFIG_DUMP_DETAILS "Enable dump details" OFF)
if(CONFIG_DUMP_DETAILS)
    add_definitions(-DCONFIG_DUMP_DETAILS)
endif()

option(CONFIG_PGTABLE_LA57 "Enable pgtable la57" OFF)
if(CONFIG_PGTABLE_LA57)
    add_definitions(-DCONFIG_PGTABLE_LA57)
endif()

option(CONFIG_STACK_TRACE "Enable stack trace" OFF)
if(CONFIG_STACK_TRACE)
    add_definitions(-DCONFIG_STACK_TRACE)
endif()

option(CONFIG_SERIAL_PORT "Enable serial port" OFF)
if(CONFIG_SERIAL_PORT AND CONFIG_VMPL_GHCB)
    add_definitions(-DCONFIG_SERIAL_PORT)
endif()

# 添加额外的编译标志
add_compile_options(-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -msoft-float)

# 设置配置变量
set(CONFIG_VMPL_VA_START "0x3fffff000000UL" CACHE STRING "vmpl va start")
set(CONFIG_VMPL_VA_SIZE "0x20000000UL" CACHE STRING "vmpl va size")
set(CONFIG_VMPL_FIT_ALGORITHM "2" CACHE STRING "vmpl fit algorithm")
set(CONFIG_VMPL_PAGE_GROW_SIZE "0x400" CACHE STRING "vmpl page grow size")
set(CONFIG_DUNE_PAGE_GROW_SIZE "0x200" CACHE STRING "dune page grow size")

add_definitions(
    -DCONFIG_VMPL_VA_START=${CONFIG_VMPL_VA_START}
    -DCONFIG_VMPL_VA_SIZE=${CONFIG_VMPL_VA_SIZE}
    -DCONFIG_VMPL_FIT_ALGORITHM=${CONFIG_VMPL_FIT_ALGORITHM}
    -DCONFIG_VMPL_PAGE_GROW_SIZE=${CONFIG_VMPL_PAGE_GROW_SIZE}
    -DCONFIG_DUNE_PAGE_GROW_SIZE=${CONFIG_DUNE_PAGE_GROW_SIZE}
)

# 添加其他库
add_library(dune SHARED src/libdune.c)
target_link_libraries(dune vmpl)

add_library(dunify SHARED src/dunify.c)
target_link_libraries(dunify vmpl dl)