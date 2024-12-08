cmake_minimum_required(VERSION 3.10)

project(libdune VERSION 1.0.0)

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

# 安装规则使用组件
install(TARGETS dune
    COMPONENT dune-lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)

install(FILES ${DUNE_HEADERS}
    COMPONENT dune-dev
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/dune
)