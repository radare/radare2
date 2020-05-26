r_main_sources = [
  'main.c',
  'r2agent.c',
  'rabin2.c',
  'radare2.c',
  'radiff2.c',
  'rafind2.c',
  'ragg2.c',
  'rahash2.c',
  'rarun2.c',
  'rasign2.c',
  'rasm2.c',
  'rax2.c'
]

r_main = library('r_main', r_main_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: [
    r_config_dep,
    r_cons_dep,
    r_arch_dep,
    r_io_dep,
    r_util_dep,
    r_flag_dep,
    r_asm_dep,
    r_core_dep,
    r_debug_dep,
    r_hash_dep,
    r_bin_dep,
    r_lang_dep,
    r_io_dep,
    r_anal_dep,
    r_parse_dep,
    r_bp_dep,
    r_egg_dep,
    r_reg_dep,
    r_search_dep,
    r_syscall_dep,
    r_socket_dep,
    r_fs_dep,
    r_magic_dep,
    r_crypto_dep
  ],
  install: true,
  implicit_include_directories: false,
  soversion: r2_libversion
)

r_main_dep = declare_dependency(link_with: r_main,
                               include_directories: [platform_inc])

pkgconfig_mod.generate(r_main,
  subdirs: 'libr',
  version: r2_version,
  name: 'r_main',
  filebase: 'r_main',
  requires: [
    'r_core',
    'r_asm',
    'r_syscall'
  ],
  description: 'radare foundation libraries'
)
