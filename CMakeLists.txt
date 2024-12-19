cmake_minimum_required(VERSION 3.10)

# 正确的设置方式 - 在project声明前设置
set(CMAKE_C_COMPILER musl-gcc CACHE STRING "C compiler" FORCE)

project(libvmpl VERSION 1.0.0 LANGUAGES C ASM)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置安装前缀
set(CMAKE_INSTALL_PREFIX /usr/local/ CACHE PATH "Installation prefix")

# 添加编译选项
add_compile_options(-Wall -Wextra)

# 添加x86特定指令集支持
add_compile_options(-mxsave)  # 支持xsave指令
add_compile_options(-mxsaveopt)  # 支持xsaveopt指令
add_compile_options(-mavx)  # 支持AVX指令集

# 源文件
file(GLOB_RECURSE SOURCES 
    "src/entry.c"
    "src/error.c"
    "src/core/*.S"
    "src/core/*.c"
    "src/mm/*.c"
    "src/security/*.c"
    "src/syscall/*.S"
    "src/syscall/*.c"
    "src/vc/*.c"
    "src/utils/*.c"
)

# 头文件目录
include_directories(
    ${PROJECT_SOURCE_DIR}/../vmpl-dev
    ${PROJECT_SOURCE_DIR}/include
)

# 创建共享库
add_library(vmpl SHARED ${SOURCES})

# 链接依赖
target_link_libraries(vmpl 
    dict
    dl
)

# 设置全局打包变量
set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE) # 所有组件打包在一起

# 设置全局包信息
set(CPACK_PACKAGE_VENDOR "DUNE")
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)

# 添加包维护者信息
set(CPACK_PACKAGE_CONTACT "dune@example.com")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "DUNE Team <dune@example.com>")

# 添加包依赖
set(CPACK_DEBIAN_PACKAGE_DEPENDS "gcc (>= 12.0.0)")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libhotcalls (>= 1.0.0), libc6 (>= 2.3.1-6)")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsyscall_intercept (>= 0.1.1), libc6 (>= 2.3.1-6)")

# 设置包描述
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "DUNE Virtual Machine Protection Layer")
set(CPACK_PACKAGE_DESCRIPTION 
    "This package provides the DUNE Virtual Machine Protection Layer libraries and tools.\n"
    " libvmpl - core library\n"
    " libdune - DUNE support library\n"
    " libdunify - DUNE utilities library"
)

# 添加子项目
add_subdirectory(libdune)
add_subdirectory(libdunify)

# 配置组件
set(CPACK_COMPONENTS_ALL 
    runtime   # 所有运行时库
    devel     # 所有开发文件
)

# 设置组件描述
set(CPACK_COMPONENT_RUNTIME_DESCRIPTION "VMPL runtime libraries")
set(CPACK_COMPONENT_DEVEL_DESCRIPTION "VMPL development files")
set(CPACK_COMPONENT_DEVEL_DEPENDS runtime)

# 安装规则使用组件
install(TARGETS vmpl dune dunify
    COMPONENT runtime
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# 统一安装所有头文件
install(FILES ${VMPL_HEADERS}
    COMPONENT devel
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vmpl
)

install(FILES ${DUNE_HEADERS}
    COMPONENT devel
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dune
)

install(FILES ${DUNIFY_HEADERS}
    COMPONENT devel
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dunify
)

# 设置库的版本信息
set_target_properties(vmpl PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}"
    BUILD_WITH_INSTALL_RPATH TRUE
)

# 添加其他配置选项
option(CONFIG_DUNE_BOOT "Enable dune boot" ON)
if(CONFIG_DUNE_BOOT)
    add_definitions(-DCONFIG_DUNE_BOOT)
endif()

option(CONFIG_VMPL_TEST "Enable vmpl test" ON)
if(CONFIG_VMPL_TEST)
    add_definitions(-DCONFIG_VMPL_TEST)
endif()

option(CONFIG_VMPL_CPUSET "Enable cpuset" ON)
if(CONFIG_VMPL_CPUSET)
    add_definitions(-DCONFIG_VMPL_CPUSET)
endif()

option(CONFIG_VMPL_SIGNAL "Enable signal" ON)
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

option(CONFIG_VMPL_MM "Enable mm" ON)
if(CONFIG_VMPL_MM)
    add_definitions(-DCONFIG_VMPL_MM)
endif()

option(CONFIG_VMPL_SEIMI "Enable seimi" OFF)
if(CONFIG_VMPL_SEIMI)
    add_definitions(-DCONFIG_VMPL_SEIMI)
endif()

option(CONFIG_VMPL_HOTCALLS "Enable hotcalls" ON)
if(CONFIG_VMPL_HOTCALLS)
    add_definitions(-DCONFIG_VMPL_HOTCALLS)
endif()

option(CONFIG_SYS_FILTER "Enable sys filter" ON)
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

option(CONFIG_STACK_TRACE "Enable stack trace" ON)
if(CONFIG_STACK_TRACE)
    add_definitions(-DCONFIG_STACK_TRACE)
endif()

option(CONFIG_SERIAL_PORT "Enable serial port" OFF)
if(CONFIG_SERIAL_PORT AND CONFIG_VMPL_GHCB)
    add_definitions(-DCONFIG_SERIAL_PORT)
endif()

option(CONFIG_VMPL_DEBUG "Enable vmpl debug" ON)
if(CONFIG_VMPL_DEBUG)
    add_definitions(-DCONFIG_VMPL_DEBUG)
endif()

# 添加额外的编译标志
add_compile_options(-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -msoft-float)

# 设置配置变量
set(CONFIG_VMPL_VA_START "0x3fffff000000UL" CACHE STRING "vmpl va start")
set(CONFIG_VMPL_VA_SIZE "0x20000000UL" CACHE STRING "vmpl va size")
set(CONFIG_VMPL_FIT_ALGORITHM "2" CACHE STRING "vmpl fit algorithm")
set(CONFIG_VMPL_PAGE_GROW_SIZE "0x400" CACHE STRING "vmpl page grow size")
set(CONFIG_DUNE_PAGE_GROW_SIZE "0x200" CACHE STRING "dune page grow size")

# 确保 libdune 和 libdunify 也能找到 libvmpl
set_target_properties(dune PROPERTIES
    INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}"
    BUILD_WITH_INSTALL_RPATH TRUE
)

set_target_properties(dunify PROPERTIES
    INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}"
    BUILD_WITH_INSTALL_RPATH TRUE
)

# 设置包名称和版本
set(CPACK_PACKAGE_NAME "libvmpl")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})

# 设置包文件名格式
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-Linux")

# 包含CPack模块
include(CPack)