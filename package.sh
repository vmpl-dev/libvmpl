#!/bin/bash

# 创建构建目录
mkdir -p build
cd build

# 配置和构建
cmake ..
make all

# 一次性打包所有组件
cpack -G DEB -C Debug
