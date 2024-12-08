cmake_minimum_required(VERSION 3.10)

project(libdunify VERSION 1.0.0)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 头文件目录
include_directories(
    ${PROJECT_SOURCE_DIR}/../include
    ${PROJECT_SOURCE_DIR}/../../vmpl-dev
)

# 创建共享库
add_library(dunify SHARED dunify.c)

# 链接依赖
target_link_libraries(dunify 
    vmpl 
    dl
)

# 设置版本号
set_target_properties(dunify PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# 安装规则
install(TARGETS dunify
    COMPONENT dunify-lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)

install(FILES ${DUNIFY_HEADERS}
    COMPONENT dunify-dev
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/dunify
)

# CPack配置
set(CPACK_PACKAGE_NAME "libdunify")
set(CPACK_PACKAGE_VENDOR "DUNE")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "libdunify is a library for DUNIFY")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}") 
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

# 组件配置
set(CPACK_COMPONENTS_ALL libraries headers)
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "Libraries")
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "Development Headers")
set(CPACK_COMPONENT_HEADERS_DEPENDS libraries)

# DEB包配置
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "DUNE")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libvmpl (>= ${PROJECT_VERSION}), libc6 (>= 2.3.1-6)")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

# RPM包配置  
set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.3.1")

# 生成器配置
set(CPACK_GENERATOR "DEB;RPM;TGZ")

# 设置独立的包名
set(CPACK_PACKAGE_NAME "libdunify")
set(CPACK_DEBIAN_PACKAGE_NAME "libdunify")

# 添加对libvmpl的依赖
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libvmpl (>= ${PROJECT_VERSION}), libc6 (>= 2.3.1-6)")

# 设置独立的包文件名
set(CPACK_PACKAGE_FILE_NAME "libdunify-${PROJECT_VERSION}")

include(CPack)