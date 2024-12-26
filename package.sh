CMAKE_PREFIX_PATH=/usr/local/

function build_with_musl() {
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local/musl \
        -DCMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT=OFF \
        -DCMAKE_C_COMPILER=musl-gcc ..
}

function build_with_glibc() {
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
}

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
    scp ${package_name}-1.0.0-Linux-devel.deb ${server}:~/
    scp ${package_name}-1.0.0-Linux-runtime.deb ${server}:~/
    sudo dpkg -i ${package_name}-1.0.0-Linux-runtime.deb
    sudo dpkg -i ${package_name}-1.0.0-Linux-devel.deb
    cd ..
    popd
}

function clean_package() {
    local package_dir=$1
    local package_name=$(basename ${package_dir})
    echo "Cleaning package ${package_name}"
    pushd ${package_dir}
    rm -rf _CPack_Packages CMakeFiles
    rm -rf build
    popd
}

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

case $1 in
    dict)
        build_package ${PWD}/libdict
        ;;
    hotcalls)
        build_package ${PWD}/libhotcalls
        ;;
    vmpl)
        build_package ${PWD}
        ;;
    dune)
        build_package ${PWD}/libdune
        ;;
    dunify)
        build_package ${PWD}/libdunify
        ;;
    all)
        build_package ${PWD}/libdict
        build_package ${PWD}/libhotcalls
        build_package ${PWD}
        build_package ${PWD}/libdune
        build_package ${PWD}/libdunify
        ;;
    clean)
        clean_package ${PWD}/libdict
        clean_package ${PWD}
        clean_package ${PWD}/libdune
        clean_package ${PWD}/libdunify
        clean_package ${PWD}/libhotcalls
        ;;
    check)
        check_package ${PWD}/libdict
        check_package ${PWD}
        check_package ${PWD}/libdune
        check_package ${PWD}/libdunify
        check_package ${PWD}/libhotcalls
        ;;
    *)
        echo "Usage: $0 {dict|vmpl|dune|dunify|hotcalls|all|clean|check}"
        exit 1
        ;;
esac