r_arch_sources = [
  'arch.c',
  'arch_session.c',
  'arch_instruction.c',
  'p/arch_bf.c'
]

r_arch_inc = [
  platform_inc,
  include_directories(
    '../../shlr'
  )
]

r_arch = library('r_arch', r_arch_sources,
  include_directories: r_arch_inc,
  c_args: library_cflags,
  dependencies: [
    r_util_dep,
    capstone_dep,
    spp_dep,
    java_dep
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_arch_dep = declare_dependency(link_with: r_arch,
                               include_directories: r_arch_inc)

pkgconfig_mod.generate(r_arch,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_arch',
  filebase: 'r_arch',
  requires: [
    'r_util'
  ],
  description: 'radare foundation libraries'
)
