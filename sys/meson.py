"""Meson build for radare2"""

import argparse
import glob
import logging
import os
import re
import shutil
import subprocess
import sys

from mesonbuild import mesonmain, mesonlib

BUILDDIR = 'build'
SDB_BUILDDIR = 'build_sdb'

BACKENDS = ['ninja', 'vs2015', 'vs2017']

PATH_FMT = {}

ROOT = None
log = None

def set_global_variables():
    """[R2_API] Set global variables"""
    global log
    global ROOT

    ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))

    logging.basicConfig(format='[%(name)s][%(levelname)s]: %(message)s',
            level=logging.DEBUG)
    log = logging.getLogger('r2-meson')

    with open(os.path.join(ROOT, 'configure.acr')) as f:
        f.readline()
        version = f.readline().split()[1].rstrip()

    PATH_FMT['ROOT'] = ROOT
    PATH_FMT['R2_VERSION'] = version

    log.debug('Root: %s', ROOT)
    log.debug('r2-version: %s', version)

def meson(root, build, prefix=None, backend=None,
          release=False, shared=False, *, options=[]):
    """[R2_API] Invoke meson"""
    command = [root, build]
    if prefix:
        command.append('--prefix={}'.format(prefix))
    if backend:
        command.append('--backend={}'.format(backend))
    if release:
        command.append('--buildtype=release')
    if shared:
        command.append('--default-library=shared')
    else:
        command.append('--default-library=static')
    if options:
        command.extend(options)

    launcher = os.path.join(ROOT, 'sys', 'meson.py')
    log.debug('Invoking meson: %s', [launcher] + command)
    meson_run(command, launcher)

def meson_run(args, launcher):
    ret = mesonmain.run(args, launcher)
    if ret != 0:
        log.error('Meson error. Exiting.')
        sys.exit(1)

def ninja(folder, *targets):
    """[R2_API] Invoke ninja"""
    command = ['ninja', '-C', folder]
    if targets:
        command.extend(targets)
    log.debug('Invoking ninja: %s', command)
    ret = subprocess.call(command)
    if ret != 0:
        log.error('Ninja error. Exiting.')
        sys.exit(1)

def msbuild(project, *params):
    """[R2_API] Invoke MSbuild"""
    command = ['msbuild', project]
    if params:
        command.extend(params)
    log.info('Invoking MSbuild: %s', command)
    ret = subprocess.call(command)
    if ret != 0:
        log.error('MSbuild error. Exiting.')
        sys.exit(1)

def copytree(src, dst):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT)
    log.debug('copytree "%s" -> "%s"', src, dst)
    shutil.copytree(src, dst)

def move(src, dst):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT)
    term = os.path.sep if os.path.isdir(dst) else ''
    log.debug('move "%s" -> "%s%s"', src, dst, term)
    for file in glob.iglob(src):
        shutil.move(file, dst)

def copy(src, dst):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT)
    term = os.path.sep if os.path.isdir(dst) else ''
    log.debug('copy "%s" -> "%s%s"', src, dst, term)
    for file in glob.iglob(src, recursive='**' in src):
        shutil.copy2(file, dst)

def makedirs(path):
    path = path.format(**PATH_FMT)
    log.debug('makedirs "%s"', path)
    os.makedirs(path)

def convert_sdb(f):
    """ Convert f to sdb format """
    sdb = os.path.splitext(f)[0]
    sdb_app = os.path.join(ROOT, SDB_BUILDDIR, 'sdb')
    log.debug('Converting %s to %s', f, sdb)
    os.system('{app} {outf} = <{inf}'.format(app=sdb_app, outf=sdb, inf=f))

def xp_compat(builddir):
    log.info('Running XP compat script')

    with open(os.path.join(builddir, 'REGEN.vcxproj'), 'r') as f:
        version = re.search('<PlatformToolset>(.*)</PlatformToolset>', f.read()).group(1)

    if version.endswith('_xp'):
        log.info('Skipping %s', builddir)
        return

    log.debug('Translating from %s to %s_xp', version, version)
    newversion = version+'_xp'

    for f in glob.iglob(os.path.join(builddir, '**', '*.vcxproj'), recursive=True):
        with open(f, 'r') as proj:
            c = proj.read()
        c = c.replace(version, newversion)
        with open(f, 'w') as proj:
            proj.write(c)
            log.debug("%s .. OK", f)

def win_dist(args):
    """Create r2 distribution for Windows"""
    builddir = os.path.join(ROOT, args.dir)
    PATH_FMT['DIST'] = args.install
    PATH_FMT['BIN'] = os.path.join(args.prefix, 'bin')
    PATH_FMT['LIB'] = os.path.join(args.prefix, 'lib')
    PATH_FMT['BUILDDIR'] = builddir

    if args.backend == 'ninja':
        ninja(builddir, 'install')
    else:
        for d in (r'{BIN}', r'{LIB}'):
            d = d.format(**PATH_FMT)
            if os.path.exists(d):
                shutil.rmtree(d)
            os.makedirs(d)
        copy(r'{BUILDDIR}\binr\**\*.exe', r'{BIN}')
        copy(r'{BUILDDIR}\libr\**\*.dll', r'{BIN}')
        copy(r'{BUILDDIR}\libr\**\*.lib', r'{LIB}')
        copy(r'{BUILDDIR}\libr\**\*.a', r'{LIB}')
    makedirs(r'{DIST}')
    move(r'{BIN}\*.exe', r'{DIST}')
    move(r'{BIN}\*.dll', r'{DIST}')
    if args.copylib:
        move(r'{LIB}\*.lib', r'{DIST}')
        move(r'{LIB}\*.a', r'{DIST}')
    #win_dist_libr2()

def win_dist_libr2(**path_fmt):
    """[R2_API] Add libr2 data (www, include, sdb's, ...) to dist directory"""
    PATH_FMT.update(path_fmt)

    copytree(r'{ROOT}\shlr\www', r'{DIST}\www')
    copytree(r'{ROOT}\libr\magic\d\default', r'{DIST}\share\radare2\{R2_VERSION}\magic')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\syscall')
    copy(r'{ROOT}\libr\syscall\d\*.sdb', r'{DIST}\share\radare2\{R2_VERSION}\syscall')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\fcnsign')
    copy(r'{ROOT}\libr\anal\d\*.sdb', r'{DIST}\share\radare2\{R2_VERSION}\fcnsign')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\opcodes')
    copy(r'{ROOT}\libr\asm\d\*.sdb', r'{DIST}\share\radare2\{R2_VERSION}\opcodes')
    makedirs(r'{DIST}\include\libr\sdb')
    makedirs(r'{DIST}\include\libr\r_util')
    copy(r'{ROOT}\libr\include\*.h', r'{DIST}\include\libr')
    copy(r'{ROOT}\libr\include\sdb\*.h', r'{DIST}\include\libr\sdb')
    copy(r'{ROOT}\libr\include\r_util\*.h', r'{DIST}\include\libr\r_util')
    makedirs(r'{DIST}\share\doc\radare2')
    copy(r'{ROOT}\doc\fortunes.*', r'{DIST}\share\doc\radare2')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\format\dll')
    copy(r'{ROOT}\libr\bin\d\elf32', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\elf64', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\elf_enums', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\pe32', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\trx', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\dll\*.sdb', r'{DIST}\share\radare2\{R2_VERSION}\format\dll')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\cons')
    copy(r'{ROOT}\libr\cons\d\*', r'{DIST}\share\radare2\{R2_VERSION}\cons')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\hud')
    copy(r'{ROOT}\doc\hud', r'{DIST}\share\radare2\{R2_VERSION}\hud\main')

def build_sdb(backend, release=True):
    """[R2_API] Build and generate sdb files"""
    log.info('Building SDB')
    sdb_builddir = os.path.join(ROOT, SDB_BUILDDIR)
    if not os.path.exists(sdb_builddir):
        meson(os.path.join(ROOT, 'shlr', 'sdb'), sdb_builddir,
              prefix=sdb_builddir, backend=backend, release=release)
    if backend != 'ninja':
        project = os.path.join(sdb_builddir, 'sdb.sln')
        msbuild(project, '/m')
    else:
        ninja(sdb_builddir)
    # Create .sdb files
    log.info('Generating sdb files.')
    with open(os.path.join(ROOT, 'Makefile'), 'r') as f:
        line = ''
        while 'DATADIRS' not in line:
            line = f.readline()
    datadirs = line.split('=')[1].split()
    datadirs = [os.path.join(ROOT, *p.split('/')) for p in datadirs]
    for folder in datadirs:
        log.debug('Looking up %s', folder)
        for f in glob.iglob(os.path.join(folder, '**', '*.sdb.txt'), recursive=True):
            if os.path.isdir(f) or os.path.islink(f):
                continue
            convert_sdb(f)
    log.debug('Done')

def build_r2(args):
    """ Build radare2 """
    log.info('Building radare2')
    r2_builddir = os.path.join(ROOT, args.dir)
    if not os.path.exists(r2_builddir):
        meson(ROOT, r2_builddir, prefix=args.prefix, backend=args.backend,
              release=args.release, shared=args.shared)
    if args.backend != 'ninja':
        if args.xp:
            xp_compat(r2_builddir)
        if not args.project:
            project = os.path.join(r2_builddir, 'radare2.sln')
            msbuild(project, '/m')
    else:
        ninja(r2_builddir)


def build(args):
    """ Prepare requirements and build radare2 """
    # Prepare capstone
    capstone_path = os.path.join(ROOT, 'shlr', 'capstone')
    if not os.path.isdir(capstone_path):
        log.info('Cloning capstone')
        git_cmd = 'git clone -b next --depth 10 https://github.com/aquynh/capstone.git'
        subprocess.call(git_cmd.split() + [capstone_path])

    # Build radare2
    build_r2(args)
    if args.install:
        win_dist(args)
    # Build sdb
    build_sdb(args.backend, release=args.release)
    if args.install:
        win_dist_libr2()

def install(args):
    """ Install radare2 """
    if os.name == 'nt':
        #win_dist(args)
        return
    log.warning('Install not implemented yet.')
    # TODO
    #if os.name == 'posix':
    #    os.system('DESTDIR="{destdir}" ninja -C {build} install'
    #            .format(destdir=destdir, build=args.dir))

def main():
    # Create logger and get applications paths
    set_global_variables()

    # Create parser
    parser = argparse.ArgumentParser(description='Mesonbuild scripts for radare2')
    parser.add_argument('--project', action='store_true',
            help='Create a visual studio project and do not build.')
    parser.add_argument('--release', action='store_true',
            help='Set the build as Release (remove debug info)')
    parser.add_argument('--backend', action='store', choices=BACKENDS,
            default='ninja', help='Choose build backend')
    parser.add_argument('--shared', action='store_true',
            help='Link dynamically (shared library) rather than statically')
    parser.add_argument('--prefix', action='store', default=None,
            help='Set project installation prefix (default: /usr/local)')
    parser.add_argument('--dir', action='store', default=BUILDDIR,
            help='Destination build directory (default: {})'.format(BUILDDIR),
            required=False)
    parser.add_argument('--xp', action='store_true',
            help='Adds support for Windows XP')
    if os.name == 'nt':
        parser.add_argument('--install', help='Installation directory')
        parser.add_argument('--copylib', action='store_true',
            help='Copy static libraries to the installation directory')
    else:
        parser.add_argument('--install', action='store_true',
            help='Install radare2 after building')
    args = parser.parse_args()

    # Check arguments
    if args.project and args.backend == 'ninja':
        log.error('--project is not compatible with --backend ninja')
        sys.exit(1)
    if args.xp and args.backend == 'ninja':
        log.error('--xp is not compatible with --backend ninja')
        sys.exit(1)
    if os.name == 'nt' and args.install and os.path.exists(args.install):
        log.error('%s already exists', args.install)
        sys.exit(1)
    if os.name == 'nt' and not args.prefix:
        args.prefix = os.path.join(ROOT, args.dir)

    # Build it!
    log.debug('Arguments: %s', args)
    build(args)
    if args.install:
        install(args)

if __name__ == '__main__':
    # meson internals
    if len(sys.argv) > 1 and sys.argv[1] in ('test', '--internal'):
        launcher = os.path.realpath(sys.argv[0])
        meson_run(sys.argv[1:], launcher)
        sys.exit()
    main()
