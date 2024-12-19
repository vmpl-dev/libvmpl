#!/bin/bash

# 创建构建目录
mkdir -p build
cd build

# 配置和构建
rm -f CMakeCache.txt
cmake -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local/musl \
    -DCMAKE_C_COMPILER=musl-gcc ..
make clean
make all
make install

# 检查依赖
ldd /usr/local/musl/lib/libvmpl.so.1.0.0

# 一次性打包所有组件
cpack -G DEB -C Release
