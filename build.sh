#!/bin/bash

# Install dependencies
export CC=musl-gcc

# Create build directory
mkdir -p build

# Configure the project
meson setup --wipe build

# Build libvmpl, libdunify
meson compile -C build

# Install libvmpl, libdunify
meson install -C build