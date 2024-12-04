#!/bin/bash

# Install dependencies
export CC=musl-gcc
export CC='clang --sysroot=/usr/local/musl -stdlib=libc'
export CC='clang --target=x86_64-linux-musl --sysroot=/usr/local/musl -nodefaultlibs -std=c11 -lgcc -ldl -lc'

# Create build directory
mkdir -p build

# Configure the project
meson setup --wipe build

# Build libvmpl, libdunify
meson compile -C build

# Install libvmpl, libdunify


# Install libexecinfo
git clone https://github.com/resslinux/libexecinfo.git
cd libexecinfo
sudo make install DESTDIR=/usr/local/musl INCLUDEDIR=/include LIBDIR=/lib