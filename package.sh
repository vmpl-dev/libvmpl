CMAKE_PREFIX_PATH=/usr/local/

function build_with_musl() {
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local/musl \
        -DCMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT=OFF \
        -DCMAKE_C_COMPILER=musl-gcc ..
}

function build_with_glibc() {
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_C_COMPILER=gcc-12 ..
}

# 构建单个包: build_package <package_dir>
function build_package() {
    local package_dir=$1
    local package_name=$(basename ${package_dir})
    echo "Building package ${package_name}"
    pushd ${package_dir}
    mkdir -p build && cd build
    rm -rf CMakeCache.txt CMakeFiles
    if [ ${BUILD_WITH_MUSL} -eq 1 ]; then
        build_with_musl
    else
        build_with_glibc
    fi
    make clean
    make -j8 all
    cpack -G DEB
    install_package ${package_dir}
    cd ..
    popd
}

# 批量执行操作: foreach_packages <operation> <package_dir1> <package_dir2> ...
function foreach_packages() {
    local operation=$1
    shift
    for package_dir in "$@"; do
        case ${operation} in
            build)
                build_package ${package_dir}
                ;;
            install)
                install_package ${package_dir}
                ;;
            clean)
                clean_package ${package_dir}
                ;;
            check)
                check_package ${package_dir}
                ;;
            sync)
                sync_package ${package_dir}
                ;;
            *)
                echo "Invalid operation: ${operation}"
                exit 1
                ;;
        esac
    done
}

# 同步包: sync_package <package_dir>
function sync_package() {
    local package_dir=$1
    local package_name=$(basename ${package_dir})
    echo "Syncing package ${package_name}"
    pushd ${package_dir}
    scp build/${package_name}-1.0.0-Linux-runtime.deb ${server}:~/
    scp build/${package_name}-1.0.0-Linux-devel.deb ${server}:~/
    popd
}

# 安装包: install_package <package_dir>
function install_package() {
    local package_dir=$1
    local package_name=$(basename ${package_dir})
    echo "Installing package ${package_name}"
    pushd ${package_dir}
    sudo dpkg -i build/${package_name}-1.0.0-Linux-runtime.deb
    sudo dpkg -i build/${package_name}-1.0.0-Linux-devel.deb
    popd
}

# 清理包: clean_package <package_dir>
function clean_package() {
    local package_dir=$1
    local package_name=$(basename ${package_dir})
    echo "Cleaning package ${package_name}"
    pushd ${package_dir}
    rm -rf _CPack_Packages CMakeFiles
    rm -rf build
    popd
}

# 检查包: check_package <package_dir>
function check_package() {
    local package_dir=$1
    local package_name=$(basename ${package_dir})
    echo "Checking package ${package_name}"
    pushd ${package_dir}
    dpkg -c build/${package_name}-1.0.0-Linux-runtime.deb
    dpkg -c build/${package_name}-1.0.0-Linux-devel.deb
    if [ ${BUILD_WITH_MUSL} -eq 1 ]; then
        ldd /usr/local/musl/lib/${package_name}.so
    else
        ldd /usr/local/lib/${package_name}.so
    fi
    popd
}

PWD=$(pwd)
server=public@amd-guest

if [ $# -eq 0 ]; then
    echo "Usage: $0 {dict|hotcalls|vmpl|dune|dunify|all|clean|check}"
    exit 1
fi

BUILD_WITH_MUSL=${2:-0}
PACKAGE_DIRS="${PWD}/libdict ${PWD}/libhotcalls ${PWD} ${PWD}/libdune ${PWD}/libdunify"

# 构建包: build <package_dir>
case $1 in
    dict)
        foreach_packages build ${PWD}/libdict
        ;;
    hotcalls)
        foreach_packages build ${PWD}/libhotcalls
        ;;
    vmpl)
        foreach_packages build ${PWD}
        ;;
    dune)
        foreach_packages build ${PWD}/libdune
        ;;
    dunify)
        foreach_packages build ${PWD}/libdunify
        ;;
    all)
        foreach_packages build ${PACKAGE_DIRS}
        ;;
    install)
        foreach_packages install ${PACKAGE_DIRS}
        ;;
    clean)
        foreach_packages clean ${PACKAGE_DIRS}
        ;;
    check)
        foreach_packages check ${PACKAGE_DIRS}
        ;;
    sync)
        foreach_packages sync ${PACKAGE_DIRS}
        ;;
    *)
        echo "Usage: $0 {dict|vmpl|dune|dunify|hotcalls|all|clean|check|sync}"
        exit 1
        ;;
esac