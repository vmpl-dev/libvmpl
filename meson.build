project('vmpl', ['c'],
    version : '1.0.0',
    meson_version : '>= 0.61.2',
    default_options : [
        'warning_level=3',
        'buildtype=release',
        'optimization=3',
        'debug=true',
        'strip=true',
        'b_lto=true',
        'c_std=c11',
        'default_library=both',
        'prefix=/usr/local/musl',
    ],
)

# 设置编译器为 musl-gcc
cc = meson.get_compiler('c', native: false)

# 添加编译器标志
add_project_arguments(
    '-Wall',
    '-g',
    '-O3',
    '-fPIC',
    '-mxsave',
    '-D__ASSEMBLY__',      # 支持汇编
    '-D_GNU_SOURCE',       # 启用 GNU 扩展
    language: 'c'
)

# 包含目录
inc = include_directories('include', '../vmpl-dev', '/usr/local/musl/include')

# 配置选项，对应 configure.ac 中的选项
vmpl_va_start = get_option('vmpl-va-start')
vmpl_va_size = get_option('vmpl-va-size')
vmpl_fit_algorithm = get_option('vmpl-fit-algorithm')
vmpl_page_grow_size = get_option('vmpl-page-grow-size')
dune_page_grow_size = get_option('dune-page-grow-size')

# 配置数据
conf = configuration_data()
conf.set('CONFIG_VMPL_VA_START', vmpl_va_start)
conf.set('CONFIG_VMPL_VA_SIZE', vmpl_va_size)
conf.set('CONFIG_VMPL_FIT_ALGORITHM', vmpl_fit_algorithm)
conf.set('CONFIG_VMPL_PAGE_GROW_SIZE', vmpl_page_grow_size)
conf.set('CONFIG_DUNE_PAGE_GROW_SIZE', dune_page_grow_size)

# libvmpl 源文件
libvmpl_sources = files(
    'src/entry.c',
    'src/error.c',
    'src/core/_entry.S',
    'src/core/ioctl.c',
    'src/core/user.c',
    'src/core/percpu.c',
    'src/core/signals.c',
    'src/core/apic.c',
    'src/core/idt.c',
    'src/core/trap.c',
    'src/core/debug.c',
    'src/core/vmpl.c',
    'src/core/dune.c',
    'src/core/platform.c',
    'src/mm/page.c',
    'src/mm/pgtable.c',
    'src/mm/layout.c',
    'src/mm/mapping.c',
    'src/mm/procmap.c',
    'src/mm/vma.c',
    'src/mm/vm.c',
    'src/mm/mm.c',
    'src/syscall/hotcalls.c',
    'src/syscall/syscall.c',
    'src/syscall/vsyscall.S',
    'src/vc/ghcb.c',
    'src/vc/vc.c',
    'src/vc/serial.c',
    'src/security/seimi.c',
    'src/security/sys-filter.c',
    'src/utils/util.c',
    'src/utils/elf.c',
    'src/utils/env.c',
    'src/utils/log.c',
)

# 声明依赖
dict_dep = declare_dependency(
    link_args : ['-ldict']
)

hotcalls_dep = declare_dependency(
    link_args : ['-lhotcalls']
)

dl_dep = declare_dependency(
    link_args : ['-ldl']
)

# 构建 libvmpl
libvmpl = library('vmpl',
    libvmpl_sources,
    include_directories : inc,
    dependencies : [
        dict_dep,
        hotcalls_dep,
        dl_dep,
    ],
    version : '1.0.0',
    install : true,
)

# 构建 libdune
libdune = library('dune',
    'src/libdune.c',
    link_with : libvmpl,
    install : true,
)

# 构建 libdunify
libdunify = library('dunify',
    'src/dunify.c',
    link_with : libvmpl,
    dependencies : dl_dep,
    install : true,
)

# 安装头文件
install_headers(
    [
        'include/vmpl.h',
        'include/dune.h',
        'include/error.h',
        'include/sys.h',
        'include/vc.h',
        'include/pgtable.h',
        'include/seimi.h',
        'include/elf.h',
        'include/bitmap.h',
        'include/log.h',
    ],
    subdir : 'vmpl'
)

# pkgconfig 生成
pkg = import('pkgconfig')
pkg.generate(
    libvmpl,
    name : 'vmpl',
    description : 'VMPL library',
    version : '1.0.0',
)