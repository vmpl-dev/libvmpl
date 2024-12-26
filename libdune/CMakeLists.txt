cmake_minimum_required(VERSION 3.10)

project(libdune VERSION 1.0.0 LANGUAGES C)

# 设置安装前缀（如果没有指定，则使用 /usr/local）
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Installation prefix" FORCE)
endif()

# 包含 GNUInstallDirs
include(GNUInstallDirs)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 添加编译选项
add_compile_options(-Wall -g -O3 -MD -fPIC -mxsave)

# 头文件目录
include_directories(
    ${PROJECT_SOURCE_DIR}/../include
    ${PROJECT_SOURCE_DIR}/../../vmpl-dev
)

# 创建共享库
add_library(dune SHARED libdune.c)

# 链接依赖
target_link_libraries(dune vmpl)

# 设置版本号
set_target_properties(dune PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# 设置组件
set(CPACK_COMPONENTS_ALL runtime devel)
set(CPACK_COMPONENT_RUNTIME_DISPLAY_NAME "Runtime Libraries")
set(CPACK_COMPONENT_DEVEL_DISPLAY_NAME "Development Files")
set(CPACK_COMPONENT_DEVEL_DEPENDS runtime)

# 运行时库安装
install(TARGETS dune
    COMPONENT runtime
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
)

# 定义头文件列表
file(GLOB DUNE_HEADERS
    "${PROJECT_SOURCE_DIR}/dune.h"
)

# 确保头文件被正确安装
install(FILES ${DUNE_HEADERS}
    COMPONENT devel
    DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/dune
)

# 生成两个独立的包
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "libdune")
set(CPACK_DEBIAN_DEVEL_PACKAGE_NAME "libdune-dev")

# 添加包配置
set(CPACK_PACKAGE_NAME "libdune")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "DUNE support library")
set(CPACK_PACKAGE_VENDOR "DUNE")

# DEB 包配置
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "DUNE Team <dune@example.com>")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libvmpl (>= ${PROJECT_VERSION}), libc6 (>= 2.3.1-6)")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

# 设置包文件名
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-Linux")

include(CPack)