project('radare2', 'c', license: 'LGPL3', meson_version: '>=0.50.1')

py3_exe = import('python').find_installation('python3')
git_exe = find_program('git', required: false)
pkgconfig_mod = import('pkgconfig')

# Get r2 version
r2_version = 'unknown-error'
r2_version_major = 0
r2_version_minor = 0
r2_version_patch = 0
r2_version_number = 0
r = run_command(py3_exe, 'sys/version.py', '--full-version')
if r.returncode() == 0
  vers = r.stdout().strip().split('\n')
  r2_version = vers[0]
  r2_version_major = vers[1]
  r2_version_minor = vers[2]
  r2_version_patch = vers[3]
  r2_version_number = vers[4]
  if host_machine.system() == 'darwin'
    r2_version = r2_version.split('-')[0]
  endif
else
  message('Cannot find project version with sys/version.py')
endif

repo = '.'
if meson.is_subproject()
  repo = meson.current_source_dir()
  if host_machine.system() == 'windows'
    py_cmd = 'print(__import__("os").readlink(r"@0@"))'.format(repo)
    py_cmd = run_command(py3_exe, '-c', py_cmd)
    if py_cmd.returncode() == 0
      repo = py_cmd.stdout().strip()
      message('r2 real path: ' + repo)
    endif
  endif
endif

# by default, not version commit is used
version_commit = '0'

gittap = ''
gittip = 'unknown'

if git_exe.found()
  # Get version_commit
  git_rev_list = run_command(git_exe, '-C', repo, 'rev-list', '--all', '--count')
  if git_rev_list.returncode() == 0
    version_commit = git_rev_list.stdout().strip()
  endif

  # Get gittap
  git_describe = run_command(git_exe, '-C', repo, 'describe', '--tags', '--match', '[0-9]*')
  if git_describe.returncode() == 0
    gittap = git_describe.stdout().strip()
  endif

  # Get gittip
  git_rev_parse = run_command(git_exe, '-C', repo, 'rev-parse', 'HEAD')
  if git_rev_parse.returncode() == 0
    gittip = git_rev_parse.stdout().strip()
  endif
endif

if get_option('r2_version_commit') != ''
  version_commit = get_option('r2_version_commit')
endif

if get_option('r2_gittap') != ''
  gittap = get_option('r2_gittap')
endif
# gittap is used for the version of each r_ library
# in case it has not been set (e.g. a release tarball) set it
if gittap == ''
  gittap = r2_version
endif

if get_option('r2_gittip') != ''
  gittip = get_option('r2_gittip')
endif

# Get current date
if host_machine.system() == 'windows'
  r2birth = run_command('cmd', '/c', 'echo %date%__%time%')
else
  r2birth = run_command('date', '+%Y-%m-%d__%H:%M:%S')
endif
if r2birth.returncode() != 0
  r2birth = ''
else
  r2birth = r2birth.stdout().strip()
endif

r2_libversion = host_machine.system() == 'windows' ? '' : r2_version
message('r2 lib version: ' + r2_libversion)

# system dependencies
cc = meson.get_compiler('c')
# required for linux
ldl = cc.find_library('dl', required: false)
pth = dependency('threads', required: false)
utl = cc.find_library('util', required: false)
if host_machine.system() == 'sunos'
  # workaround for Solaris until https://github.com/mesonbuild/meson/issues/4328 is fixed
  mth = declare_dependency(link_args: '-lm')
else
  mth = cc.find_library('m', required: false)
endif

platform_deps = []
platform_inc = ['.', 'libr/include']
if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32'), cc.find_library('psapi')]
endif
platform_inc = include_directories(platform_inc)

if get_option('static_runtime')
  if cc.get_id() == 'msvc'
    add_project_arguments('/MT', language: 'c')
  endif
endif

if cc.get_id() == 'clang-cl'
  add_project_arguments('-D__STDC__=1', language: 'c')
  add_project_arguments('-D_CRT_DECLARE_NONSTDC_NAMES ', language: 'c')
  add_project_arguments('-D_CRT_SECURE_NO_WARNINGS', language: 'c')
  add_project_arguments('-D_CRT_NONSTDC_NO_DEPRECATE', language: 'c')
endif

if get_option('default_library') == 'shared'
  if host_machine.system() != 'windows' or cc.get_id()!='msvc' and cc.get_id()!='clang-cl'
    add_project_arguments('-fvisibility=hidden', language: 'c')
  endif
endif

library_cflags = ['-DR2_PLUGIN_INCORE=1']

if host_machine.system() == 'windows'
  r2_prefix = '.'
  r2_libdir = 'lib'
  r2_incdir = 'include'
  r2_datdir = 'share'

  opts1 = [
    'r2_libdir',
    'r2_incdir',
    'r2_datdir'
  ]
  foreach opt : opts1
    val = get_option(opt)
    if val != ''
      set_variable(opt, val)
    endif
  endforeach

  r2_wwwroot = join_paths(r2_datdir, 'www')
  r2_sdb = join_paths(r2_datdir)
  r2_zigns = join_paths(r2_datdir, 'zigns')
  r2_themes = join_paths(r2_datdir, 'cons')
  r2_fortunes = join_paths(r2_datdir, 'doc')
  r2_flags = join_paths(r2_datdir, 'flag')
  r2_hud = join_paths(r2_datdir, 'hud')

  opts2 = [
    'r2_wwwroot',
    'r2_sdb',
    'r2_zigns',
    'r2_themes',
    'r2_fortunes',
    'r2_flags',
    'r2_hud'
  ]
  foreach opt : opts2
    val = get_option(opt)
    if val != ''
      set_variable(opt, val)
    endif
  endforeach

  opts3 = [
    'r2_plugins',
    'r2_extras',
    'r2_bindings'
  ]
  r2_plugins = join_paths(r2_libdir, 'plugins')
  r2_extras = join_paths(r2_libdir, 'extras')
  r2_bindings = join_paths(r2_libdir, 'bindings')

  foreach opt : opts1 + opts2 + opts3
    val = get_variable(opt)
    val = '\\\\'.join(val.split('/'))
    set_variable(opt, val)
  endforeach
else
  r2_prefix = get_option('prefix')
  r2_libdir = get_option('libdir')
  r2_incdir = join_paths(get_option('includedir'), 'libr')
  r2_datdir = get_option('datadir')
  r2_datdir_r2 = join_paths(r2_datdir, 'radare2')
  r2_wwwroot = join_paths(r2_datdir_r2, r2_version, 'www')
  r2_sdb = join_paths(r2_datdir_r2, r2_version)
  r2_zigns = join_paths(r2_datdir_r2, r2_version, 'zigns')
  r2_themes = join_paths(r2_datdir_r2, r2_version, 'cons')
  r2_fortunes = join_paths(r2_datdir, 'doc', 'radare2')
  r2_flags = join_paths(r2_datdir_r2, r2_version, 'flag')
  r2_hud = join_paths(r2_datdir_r2, r2_version, 'hud')
  r2_plugins = join_paths(r2_libdir, 'radare2', r2_version)
  r2_extras = join_paths(r2_libdir, 'radare2-extras', r2_version)
  r2_bindings = join_paths(r2_libdir, 'radare2-bindings', r2_version)
endif

r2_zsh_compdir = join_paths(r2_datdir, 'zsh', 'site-functions')

# load plugin configuration
subdir('libr')

conf_data = configuration_data()
conf_data.set('plugins_core', '&r_core_plugin_' + ', &r_core_plugin_'.join(core_plugins) + ', 0')
conf_data.set('plugins_anal', '&r_anal_plugin_' + ', &r_anal_plugin_'.join(anal_plugins) + ', 0')
conf_data.set('plugins_asm', '&r_asm_plugin_' + ', &r_asm_plugin_'.join(asm_plugins) + ', 0')
conf_data.set('plugins_arch', '&r_arch_plugin_' + ', &r_arch_plugin_'.join(arch_plugins) + ', 0')
conf_data.set('plugins_bp', '&r_bp_plugin_' + ', &r_bp_plugin_'.join(bp_plugins) + ', 0')
conf_data.set('plugins_bin', '&r_bin_plugin_' + ', &r_bin_plugin_'.join(bin_plugins) + ', 0')
conf_data.set('plugins_bin_ldr', '&r_bin_ldr_plugin_' + ', &r_bin_ldr_plugin_'.join(bin_ldr_plugins) + ', 0')
conf_data.set('plugins_bin_xtr', '&r_bin_xtr_plugin_' + ', &r_bin_xtr_plugin_'.join(bin_xtr_plugins) + ', 0')
conf_data.set('plugins_crypto', '&r_crypto_plugin_' + ', &r_crypto_plugin_'.join(crypto_plugins) + ', 0')
conf_data.set('plugins_io', '&r_io_plugin_' + ', &r_io_plugin_'.join(io_plugins) + ', 0')
conf_data.set('plugins_fs', '&r_fs_plugin_' + ', &r_fs_plugin_'.join(fs_plugins) + ', 0')
conf_data.set('plugins_debug', '&r_debug_plugin_' + ', &r_debug_plugin_'.join(debug_plugins) + ', 0')
conf_data.set('plugins_egg', '&r_egg_plugin_' + ', &r_egg_plugin_'.join(egg_plugins) + ', 0')
conf_data.set('plugins_lang', '&r_lang_plugin_' + ', &r_lang_plugin_'.join(lang_plugins) + ', 0')
conf_data.set('plugins_parse', '&r_parse_plugin_' + ', &r_parse_plugin_'.join(parse_plugins) + ', 0')
config_h = configure_file(
  input: 'libr/config.h.in',
  output: 'config.h',
  configuration: conf_data
)

# handle magic library
sys_magic = cc.find_library('magic', required: false)
use_syslib_magic = false

if sys_magic.found() and get_option('use_sys_magic')
  use_syslib_magic = true
endif

# handle xxhash library
sys_xxhash = dependency('xxhash', required: false)
use_sys_xxhash = false
if not sys_xxhash.found()
  sys_xxhash = cc.find_library('xxhash', required: false)
endif

if sys_xxhash.found() and get_option('use_sys_xxhash')
  message('Using system xxhash library')
  use_sys_xxhash = true
else
  message('Using bundled xxhash library')
endif

# handle openssl library
sys_openssl = dependency('openssl', required: false)
use_sys_openssl = false
if sys_openssl.found() and get_option('use_sys_openssl')
  message('Using system openssl library')
  use_sys_openssl = true
else
  message('Using bundled openssl code')
endif

# handle libuv library
if get_option('use_libuv')
  libuv_dep = dependency('libuv', version: '>=1.0.0', required: false)
  use_libuv = libuv_dep.found()
  if not libuv_dep.found()
    warning('use_libuv option was set to true, but libuv was not found.')
  endif
else
  use_libuv = false
endif

if use_libuv
  message('Using libuv')
else
  message('Not using libuv, thus using fallback server implementations')
endif

has_debugger = get_option('debugger')
have_ptrace = not ['windows', 'cygwin', 'sunos'].contains(host_machine.system())
use_ptrace_wrap = ['linux'].contains(host_machine.system())

have_ptrace = have_ptrace and has_debugger
use_ptrace_wrap = use_ptrace_wrap and has_debugger

message('HAVE_PTRACE: @0@'.format(have_ptrace))
message('USE_PTRACE_WRAP: @0@'.format(use_ptrace_wrap))

checks_level = get_option('checks_level')
if checks_level == 9999
  if get_option('buildtype') == 'release'
    checks_level = 1
  else
    checks_level = 2
  endif
endif

message('R2_CHECKS_LEVEL: @0@'.format(checks_level))

userconf = configuration_data()
userconf.set('R_CHECKS_LEVEL', checks_level)
userconf.set10('HAVE_LIB_MAGIC', sys_magic.found())
userconf.set10('USE_LIB_MAGIC', use_syslib_magic)
userconf.set10('HAVE_LIB_XXHASH', sys_xxhash.found())
userconf.set10('USE_LIB_XXHASH', use_sys_xxhash)
userconf.set10('DEBUGGER', has_debugger)
userconf.set('PREFIX', r2_prefix)
if host_machine.system() == 'windows'
  userconf.set('LIBDIR', r2_libdir)
  userconf.set('INCLUDEDIR', r2_incdir)
  userconf.set('DATADIR_R2', r2_datdir)
  userconf.set10('HAVE_JEMALLOC', false)
else
  userconf.set('LIBDIR', join_paths(r2_prefix, r2_libdir))
  userconf.set('INCLUDEDIR', join_paths(r2_prefix, r2_incdir))
  userconf.set('DATADIR_R2', r2_datdir_r2)
  userconf.set10('HAVE_JEMALLOC', true)
endif
userconf.set('DATADIR', join_paths(r2_prefix, r2_datdir))
userconf.set('WWWROOT', join_paths(r2_prefix, r2_wwwroot))
userconf.set('SDB', r2_sdb)
userconf.set('ZIGNS', r2_zigns)
userconf.set('THEMES', r2_themes)
userconf.set('FORTUNES', r2_fortunes)
userconf.set('FLAGS', r2_flags)
userconf.set('HUD', r2_hud)
userconf.set('PLUGINS', r2_plugins)
userconf.set('EXTRAS', r2_extras)
userconf.set('BINDINGS', r2_bindings)
userconf.set10('HAVE_OPENSSL', use_sys_openssl)
userconf.set10('HAVE_LIBUV', use_libuv)
userconf.set10('HAVE_FORK', true)
userconf.set10('HAVE_PTRACE', have_ptrace)
userconf.set10('USE_PTRACE_WRAP', use_ptrace_wrap)
userconf.set10('WITH_GPL', true)
ok = cc.has_header_symbol('sys/personality.h', 'ADDR_NO_RANDOMIZE')
userconf.set10('HAVE_DECL_ADDR_NO_RANDOMIZE', ok)

foreach item : [
    ['arc4random_uniform', '#include <stdlib.h>'],
    ['explicit_bzero', '#include <string.h>'],
    ['explicit_memset', '#include <string.h>'],
    ['clock_nanosleep', '#include <time.h>'],
    ['sigaction', '#include <signal.h>']
  ]
  func = item[0]
  ok = cc.has_function(func, prefix: item[1])
  userconf.set10('HAVE_@0@'.format(func.to_upper()), ok)
endforeach

r_userconf_h = configure_file(
  input: 'libr/include/r_userconf.h.acr',
  output: 'r_userconf.h',
  configuration: userconf,
  install_dir: join_paths(r2_incdir)
)

versionconf = configuration_data()
versionconf.set('MESON_VERSION', meson.version())
versionconf.set('VERSIONCOMMIT', version_commit)
versionconf.set('R2_VERSION_MAJOR', r2_version_major)
versionconf.set('R2_VERSION_MINOR', r2_version_minor)
versionconf.set('R2_VERSION_PATCH', r2_version_patch)
versionconf.set('R2_VERSION_NUMBER', r2_version_number)
versionconf.set('R2_VERSION', r2_version)
versionconf.set('R2_GITTAP', gittap)
versionconf.set('R2_GITTIP', gittip)
versionconf.set('R2_BIRTH', r2birth)
r_version_h = configure_file(
  input: 'libr/include/r_version.h.in',
  output: 'r_version.h',
  configuration: versionconf,
  install_dir: join_paths(r2_incdir)
)

# Copy missing header
run_command(py3_exe, '-c', '__import__("shutil").copyfile("shlr/spp/config.def.h", "shlr/spp/config.h")')

pcconf = configuration_data()
pcconf.set('PREFIX', get_option('prefix'))
pcconf.set('LIBDIR', join_paths(get_option('prefix'), get_option('libdir')))
pcconf.set('VERSION', r2_version)
libr_pc = configure_file(
  input: 'libr/libr.pc.acr',
  output: 'libr.pc',
  configuration: pcconf,
  install_dir: join_paths(get_option('libdir'), 'pkgconfig')
)

subdir('shlr')

subdir('libr/util')
subdir('libr/hash')
subdir('libr/crypto')
subdir('libr/socket')
subdir('libr/arch')
subdir('libr/cons')
subdir('shlr/gdb')
subdir('libr/io')
subdir('libr/bp')
subdir('libr/syscall')
subdir('libr/search')
subdir('libr/magic')
subdir('libr/flag')
subdir('libr/reg')
subdir('libr/bin')
subdir('libr/config')
subdir('libr/parse')
subdir('libr/lang')
subdir('libr/asm')
subdir('libr/anal')
subdir('libr/egg')
subdir('libr/fs')
subdir('libr/debug')
subdir('libr/core')

subdir('libr/anal/d')
subdir('libr/asm/d')
subdir('libr/bin/d')
subdir('libr/syscall/d')
subdir('libr/cons/d')
subdir('libr/magic/d')
subdir('libr/flag/d')
subdir('libr/main')

if not meson.is_subproject()
  rpath = get_option('local') and get_option('default_library') == 'shared' ? '$ORIGIN/../' + get_option('libdir') : ''
  subdir('binr/rahash2')
  subdir('binr/rarun2')
  subdir('binr/rasm2')
  subdir('binr/rabin2')
  subdir('binr/radare2')
  subdir('binr/ragg2')
  subdir('binr/r2agent')
  subdir('binr/radiff2')
  subdir('binr/rafind2')
  subdir('binr/rasign2')
  subdir('binr/rax2')
  subdir('binr/r2pm')
  subdir('binr/r2r')
else
  libr2_dep = declare_dependency(
    dependencies: [
      r_anal_dep,
      r_arch_dep,
      r_asm_dep,
      r_bin_dep,
      r_bp_dep,
      r_config_dep,
      r_cons_dep,
      r_core_dep,
      r_main_dep,
      r_crypto_dep,
      r_debug_dep,
      r_egg_dep,
      r_flag_dep,
      r_fs_dep,
      r_hash_dep,
      r_io_dep,
      r_lang_dep,
      r_magic_dep,
      r_parse_dep,
      r_reg_dep,
      r_search_dep,
      r_socket_dep,
      r_syscall_dep,
      r_util_dep
    ],
    include_directories: include_directories('.', 'libr/include'),
    version: r2_version
  )
endif

if get_option('use_webui')
  install_subdir('shlr/www',
    install_dir: r2_wwwroot,
    strip_directory: true
  )
endif

subdir('test/unit')

install_data(
  'doc/fortunes.creepy',
  'doc/fortunes.fun',
  'doc/fortunes.nsfw',
  'doc/fortunes.tips',
  install_dir: r2_fortunes
)

install_man(
  'man/r2agent.1',
  'man/r2-docker.1',
  'man/r2pm.1',
  'man/rabin2.1',
  'man/radare2.1',
  'man/radiff2.1',
  'man/rafind2.1',
  'man/ragg2.1',
  'man/rahash2.1',
  'man/rarun2.1',
  'man/rasm2.1',
  'man/rax2.1',
  'man/esil.7'
)

install_data('doc/hud',
  install_dir: r2_hud,
  rename: 'main'
)

install_data(
  'doc/zsh/_r2',
  'doc/zsh/_rabin2',
  'doc/zsh/_radiff2',
  'doc/zsh/_rafind2',
  'doc/zsh/_ragg2',
  'doc/zsh/_rahash2',
  'doc/zsh/_rasm2',
  'doc/zsh/_rax2',
  install_dir: r2_zsh_compdir
)
