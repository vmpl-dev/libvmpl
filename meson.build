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
        'cpp_std=c++17',
        'c_std=c11',
        'c_args=-O3',
        'c_link_args=-O3',
        'default_library=both',
        'prefix=/usr/local/musl',
    ],
)

add_project_arguments(language: 'c')

# Set the default compiler to musl-gcc
cc = meson.get_compiler('c')

# Print the compiler name
message('Compiler: ' + cc.get_id())

# Set the default build type to release
if meson.is_cross_build()
    message('Cross build')
endif

# Checks for programs
ar = find_program('ar')
as = find_program('as')

# Specify the desired archiver program with options
meson.add_dist_script('ar')
meson.add_dist_script('as')

# Options
vmpl_options = [
    ['cpuset', true],
    ['signal', false],
    ['apic', true],
    ['msr-protocol', false],
    ['ghcb', true],
    ['pgtable', true],
    ['seimi', false],
    ['syscall', false],
    ['vsyscall', false],
    ['debug', false],
    ['dune-boot', true],
    ['remap-syscall', false],
    ['remap-vsyscall', false],
    ['dump-details', false],
    ['pgtbale-la57', false],
    ['pgtable-selftest', false],
    ['stack-trace', false],
    ['ghcb-selftest', false],
    ['serial-port', false]
]

# Configuration file
conf = configuration_data()
conf.set('VERSION', meson.project_version())
conf.set('PACKAGE', meson.project_name())
conf.set('PACKAGE_BUGREPORT', '')
conf.set('PACKAGE_NAME', meson.project_name())
conf.set('PACKAGE_STRING', meson.project_name() + ' ' + meson.project_version())
conf.set('PACKAGE_TARNAME', meson.project_name())
conf.set('PACKAGE_URL', '')
conf.set('PACKAGE_VERSION', meson.project_version())
conf.set('VERSION', meson.project_version())
conf.set('VMPL_VERSION', meson.project_version())
conf.set('VMPL_MAJOR_VERSION', meson.project_version().split('.')[0])
conf.set('VMPL_MINOR_VERSION', meson.project_version().split('.')[1])

# Foreach option, set the value to the configuration file
foreach opt : vmpl_options
    opt_name = opt[0]
    opt_default = opt[1]
    opt_desc = 'Enable ' + opt_name + ' support'
    opt_define = 'CONFIG_' + opt_name.to_upper().replace('-', '_')
    opt_value = get_option('enable-' + opt_name)
    if opt_value
        conf.set(opt_define, opt_value)
    else
        conf.set(opt_define, opt_default)
    endif
endforeach

# Specify dependencies
deps = [
    cc.find_library('dl'),
    cc.find_library('pthread'),
    cc.find_library('m'),
]

# Generate config.h
configure_file(
    output : 'config.h',
    configuration : conf,
)

# Build targets
# executable('vmpl', 'source.c', dependencies : deps)

# Specify the include directories and the preprocessor flags
include_dir = include_directories('include', '../svsm-dev')
add_project_arguments('-include', 'config.h', language : 'c')

# Specify the compiler flags
add_project_arguments('-MD', '-fasm', language : 'c')

# Import the pkgconfig module
pkgconfig = import('pkgconfig')

# Specify shared libraries to be built
libvmpl_sources = files(
    'src/vmpl.c',
    'src/sys.c',
    'src/mm.c',
    'src/seimi.c',
    'src/ghcb.c',
    'src/vmsa.c',
    'src/vc.c',
    'src/dune.S',
    'src/vsyscall.S',
    'src/serial.c',
    'src/trap.c',
    'src/apic.c',
    'src/bitmap.c',
    'src/pmm.c',
    'src/env.c',
    'src/log.c',
)
libvmpl = library('vmpl', libvmpl_sources,
    include_directories : include_dir,
    version : '1.0.0',
    install : true,
)

# Generate the vmpl.pc file
pkgconfig.generate(
    name : 'vmpl',
    description : 'VMPL library',
    version : meson.project_version(),
    libraries : libvmpl,
    install_dir : get_option('libdir') + '/pkgconfig',
)

# Specify headers to be installed
libvmpl_headers = files(
    'include/vmpl.h',
    'include/sys.h',
    'include/syscall.h',
    'include/vc.h',
    'include/mm.h',
    'include/seimi.h',
    'include/apic.h',
    'include/bitmap.h',
    'include/log.h',
)

libdunify_sources = files('src/dunify.c')
libdunify = shared_library('dunify', libdunify_sources,
    link_with : libvmpl,
    include_directories : include_dir,
    dependencies : cc.find_library('dl'),
    version : '1.0.0',
    install : true,
)

# Generate the dunify.pc file
pkgconfig.generate(
    name : 'dunify',
    description : 'Dunify library',
    version : meson.project_version(),
    libraries : libdunify,
    requires : 'vmpl',
    requires_private : 'vmpl',
    install_dir : get_option('libdir') + '/pkgconfig',
)

# Install targets
install_dir = get_option('prefix') + '/bin'
install_headers(libvmpl_headers,
    subdir : 'vmpl',
    install_dir : 'include/vmpl',
)
install_subdir('vmpl', install_dir : 'include')