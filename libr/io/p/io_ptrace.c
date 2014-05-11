/* radare - LGPL - Copyright 2008-2014 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_debug.h>

#if __linux__ || __BSD__

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

typedef struct {
	int pid;
	int tid;
	int fd;
} RIOPtrace;
#define RIOPTRACE_PID(x) (((RIOPtrace*)x->data)->pid)
#define RIOPTRACE_FD(x) (((RIOPtrace*)x->data)->fd)

#undef R_IO_NFDS
#define R_IO_NFDS 2
#ifndef __ANDROID__
extern int errno;
#endif

static int __waitpid(int pid) {
	int st = 0;
	return (waitpid (pid, &st, 0) != -1);
}

#if __OpenBSD__ || __KFBSD__
#define debug_read_raw(x,y) ptrace(PTRACE_PEEKTEXT, (pid_t)(x), (caddr_t)(y), 0)
#define debug_write_raw(x,y,z) ptrace(PTRACE_POKEDATA, (pid_t)(x), (caddr_t)(y), (int)(size_t)(z))
typedef int ptrace_word;   // int ptrace(int request, pid_t pid, caddr_t addr, int data);
#else
#define debug_read_raw(x,y) ptrace(PTRACE_PEEKTEXT, x, y, 0)
#define debug_write_raw(x,y,z) ptrace(PTRACE_POKEDATA, x, y, z)
typedef long int ptrace_word; // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
#endif

static int debug_os_read_at(int pid, ut32 *buf, int sz, ut64 addr) {
	ut32 words = sz / sizeof (ut32);
	ut32 last = sz % sizeof (ut32);
	ut32 x, lr, *at = (ut32*)(size_t)addr;
	if (sz<1 || addr==UT64_MAX)
		return -1;
	for (x=0; x<words; x++)
		buf[x] = (ut32)debug_read_raw (pid, (void*)(at++));
	if (last) {
		lr = (ut32)debug_read_raw (pid, at);
		memcpy (buf+x, &lr, last) ;
	}
	return sz; 
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
	int ret, fd;
	ut64 addr = io->off;
	if (!desc || !desc->data)
		return -1;
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	fd = RIOPTRACE_FD (desc);
	if (fd != -1) {
		ret = lseek (fd, addr, SEEK_SET);
		if (ret < 0) return -1;
		ret = read (fd, buf, len);
		// Workaround for the buggy Debian Wheeze's /proc/pid/mem
		if (ret != -1) return ret;
	}
	return debug_os_read_at (RIOPTRACE_PID (desc), (ut32*)buf, len, addr);
}

static int ptrace_write_at(int pid, const ut8 *pbuf, int sz, ut64 addr) {
	ptrace_word *buf = (ptrace_word*)pbuf;
	ut32 words = sz / sizeof (ptrace_word);
	ut32 last = sz % sizeof (ptrace_word);
	ut32 x, *at = (ut32 *)(size_t)addr;
	ptrace_word lr;
	if (sz<1 || addr==UT64_MAX)
		return -1;
	for (x=0; x<words; x++)
		debug_write_raw (pid, (void*)(at++), buf[x]);
	if (last) {
		lr = debug_read_raw (pid, (void*)at);
		memcpy (&lr, buf+x, last);
		if (debug_write_raw (pid, (void*)at, lr))
			return sz-last;
	}
	return sz; 
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	if (!fd || !fd->data)
		return -1;
	return ptrace_write_at (RIOPTRACE_PID (fd), buf, len, io->off);
}

static void open_pidmem (RIOPtrace *iop) {
	char pidmem[32];
	snprintf (pidmem, sizeof (pidmem), "/proc/%d/mem", iop->pid);
	iop->fd = open (pidmem, O_RDWR);
#if 0
	if (iop->fd == -1)
		eprintf ("Warning: Cannot open /proc/%d/mem. "
			"Fallback to ptrace io.\n", iop->pid);
#endif
}

static void close_pidmem(RIOPtrace *iop) {
	if (iop->fd != -1) {
		close (iop->fd);
		iop->fd = -1;
	}
}

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	if (!strncmp (file, "ptrace://", 9))
		return R_TRUE;
	if (!strncmp (file, "attach://", 9))
		return R_TRUE;
	return R_FALSE;
}

static RIODesc *__open(struct r_io_t *io, const char *file, int rw, int mode) {
	char *pidpath;
	int ret = -1;
	if (__plugin_open (io, file,0)) {
		int pid = atoi (file+9);
		ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
		if (file[0]=='p')  //ptrace
			ret = 0;
		else
		if (ret == -1) {
#ifdef __ANDROID__
		eprintf ("ptrace_attach: Operation not permitted\n");
#else
			switch (errno) {
			case EPERM:
				ret = pid;
				eprintf ("ptrace_attach: Operation not permitted\n");
				break;
			case EINVAL:
				perror ("ptrace: Cannot attach");
				eprintf ("ERRNO: %d (EINVAL)\n", errno);
				break;
			}
#endif
		} else
		if (__waitpid (pid))
			ret = pid;
		else eprintf ("Error in waitpid\n");
		if (ret != -1) {
			RIODesc *desc;
			RIOPtrace *riop = R_NEW (RIOPtrace);
			riop->pid = riop->tid = pid;
			open_pidmem (riop);
			pidpath = r_sys_pid_to_path (pid);
			desc = r_io_desc_new (&r_io_plugin_ptrace, pid,
				pidpath, R_TRUE, mode, riop);
			free (pidpath);
			return desc;
		}
	}
	return NULL;
}

static ut64 __lseek(struct r_io_t *io, RIODesc *fd, ut64 offset, int whence) {
	return (!whence)?offset:whence==1?io->off+offset:UT64_MAX;
}


static int __close(RIODesc *desc) {
	int pid, fd;
	if (!desc || !desc->data)
		return -1;
	pid = RIOPTRACE_PID (desc);
	fd = RIOPTRACE_FD (desc);
	if (fd!=-1) close (fd);
	free (desc->data);
	desc->data = NULL;
	return ptrace (PTRACE_DETACH, pid, 0, 0);
}

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOPtrace *iop = (RIOPtrace*)fd->data;
	//printf("ptrace io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "help")) {
		eprintf ("Usage: =!cmd args\n"
			" =!ptrace   - use ptrace io\n"
			" =!mem      - use /proc/pid/mem io if possible\n"
			" =!pid      - show targeted pid\n");
	} else
	if (!strcmp (cmd, "ptrace")) {
		close_pidmem (iop);
	} else
	if (!strcmp (cmd, "mem")) {
		open_pidmem (iop);
	} else
	if (!strcmp (cmd, "pid")) {
		int pid = atoi (cmd+4);
		if (pid != 0)
			iop->pid = iop->tid = pid;
		io->printf ("%d\n", iop->pid);
		return pid;
	} else eprintf ("Try: '=!pid'\n");
	return R_TRUE;
}

// TODO: rename ptrace to io_ptrace .. err io.ptrace ??
RIOPlugin r_io_plugin_ptrace = {
	.name = "ptrace",
	.desc = "ptrace and /proc/pid/mem (if available) io",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
	.debug = (void*)(size_t)1
};
#else
struct r_io_plugin_t r_io_plugin_ptrace = {
	.name = NULL
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ptrace
};
#endif
