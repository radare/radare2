/* radare - LGPL - Copyright 2009-2018 - pancake */

#if __linux__
#include <time.h>
#endif

#include <r_userconf.h>
#include <stdlib.h>
#include <string.h>
#if defined(__NetBSD__)
# include <sys/param.h>
# if __NetBSD_Prereq__(7,0,0)
#  define NETBSD_WITH_BACKTRACE
# endif
#endif
#if defined(__FreeBSD__)
# include <sys/param.h>
# include <sys/sysctl.h>
# if __FreeBSD_version >= 1000000
#  define FREEBSD_WITH_BACKTRACE
# endif
#endif
#include <sys/types.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>

static char** env = NULL;

#if (__linux__ && __GNU_LIBRARY__) || defined(NETBSD_WITH_BACKTRACE) || \
  defined(FREEBSD_WITH_BACKTRACE) || __DragonFly__
# include <execinfo.h>
#endif
#if __APPLE__
#include <errno.h>
#ifdef __MAC_10_8
#define HAVE_ENVIRON 1
#else
#define HAVE_ENVIRON 0
#endif

#if HAVE_ENVIRON
#include <execinfo.h>
#endif
// iOS don't have this we can't hardcode
// #include <crt_externs.h>
extern char ***_NSGetEnviron(void);
# ifndef PROC_PIDPATHINFO_MAXSIZE
#  define PROC_PIDPATHINFO_MAXSIZE 1024
int proc_pidpath(int pid, void * buffer, ut32 buffersize);
//#  include <libproc.h>
# endif
#endif
#if __UNIX__
# include <sys/wait.h>
# include <sys/stat.h>
# include <errno.h>
# include <signal.h>
extern char **environ;

#ifdef __HAIKU__
# define Sleep sleep
#endif
#endif
#if __WINDOWS__
# include <io.h>
# include <winbase.h>
#define TMP_BUFSIZE	4096
#ifdef _MSC_VER
#include <psapi.h>
#include <process.h>  // to allow getpid under windows msvc compilation
#include <direct.h>  // to allow getcwd under windows msvc compilation
#endif
#endif

R_LIB_VERSION(r_util);
#ifdef _MSC_VER
// Required for GetModuleFileNameEx and GetProcessImageFileName linking
#pragma comment(lib, "psapi.lib")
#endif

static const struct {const char* name; ut64 bit;} arch_bit_array[] = {
    {"x86", R_SYS_ARCH_X86},
    {"arm", R_SYS_ARCH_ARM},
    {"ppc", R_SYS_ARCH_PPC},
    {"m68k", R_SYS_ARCH_M68K},
    {"java", R_SYS_ARCH_JAVA},
    {"mips", R_SYS_ARCH_MIPS},
    {"sparc", R_SYS_ARCH_SPARC},
    {"xap", R_SYS_ARCH_XAP},
    {"tms320", R_SYS_ARCH_TMS320},
    {"msil", R_SYS_ARCH_MSIL},
    {"objd", R_SYS_ARCH_OBJD},
    {"bf", R_SYS_ARCH_BF},
    {"sh", R_SYS_ARCH_SH},
    {"avr", R_SYS_ARCH_AVR},
    {"dalvik", R_SYS_ARCH_DALVIK},
    {"z80", R_SYS_ARCH_Z80},
    {"arc", R_SYS_ARCH_ARC},
    {"i8080", R_SYS_ARCH_I8080},
    {"rar", R_SYS_ARCH_RAR},
    {"lm32", R_SYS_ARCH_LM32},
    {"v850", R_SYS_ARCH_V850},
    {NULL, 0}
};

R_API int r_sys_fork() {
#if HAVE_FORK
#if __WINDOWS__
	return -1;
#else
	return fork ();
#endif
#else
	return -1;
#endif
}

R_API void r_sys_exit(int status, bool nocleanup) {
	if (nocleanup) {
		_exit (status);
	} else {
		exit (status);
	}
}

/* TODO: import stuff from bininfo/p/bininfo_addr2line */
/* TODO: check endianness issues here */
R_API ut64 r_sys_now(void) {
	ut64 ret;
	struct timeval now;
	gettimeofday (&now, NULL);
	ret = now.tv_sec;
	ret <<= 20;
	ret |= now.tv_usec;
	//(sizeof (now.tv_sec) == 4
	return ret;
}

R_API int r_sys_truncate(const char *file, int sz) {
#if __WINDOWS__
	int fd = r_sandbox_open (file, O_RDWR, 0644);
	if (fd == -1) {
		return false;
	}
#ifdef _MSC_VER
	int r = _chsize (fd, sz);
#else
	int r = ftruncate (fd, sz);
#endif
	if (r != 0) {
		eprintf ("Could not resize '%s' file\n", file);
		close (fd);
		return false;
	}
	close (fd);
	return true;
#else
	if (r_sandbox_enable (0)) {
		return false;
	}
	return truncate (file, sz)? false: true;
#endif
}

R_API os_info *r_sys_get_osinfo() {
#if __WINDOWS__
	return r_sys_get_winver();
#endif
	os_info *info = calloc (1, sizeof (os_info));
	if (!info) {
		return NULL;
	}
	int len = 0;
	char *output = r_sys_cmd_str ("uname -s", NULL, &len);
	if (len) {
		strncpy (info->name, output, sizeof (info->name));
		info->name[31] = '\0';
	}
	free (output);
	output = r_sys_cmd_str ("uname -r", NULL, &len);
	if (len) {
		char *dot = strtok (output, ".");
		if (dot) {
			info->major = atoi (dot);
		}
		dot = strtok (NULL, ".");
		if (dot) {
			info->minor = atoi (dot);
		}
		dot = strtok (NULL, ".");
		if (dot) {
			info->patch = atoi (dot);
		}
	}
	free (output);
	return info;
}

R_API RList *r_sys_dir(const char *path) {
	RList *list = NULL;
#if __WINDOWS__
	WIN32_FIND_DATAW entry;
	char *cfname;
	HANDLE fh = r_sandbox_opendir (path, &entry);
	if (fh == INVALID_HANDLE_VALUE) {
		//IFDGB eprintf ("Cannot open directory %ls\n", wcpath);
		return list;
	}
	list = r_list_newf (free);
	if (list) {
		do {
			if ((cfname = r_utf16_to_utf8 (entry.cFileName))) {
				r_list_append (list, strdup (cfname));
				free (cfname);
			}
		} while (FindNextFileW (fh, &entry));
	}
	FindClose (fh);
#else
	struct dirent *entry;
	DIR *dir = r_sandbox_opendir (path);
	if (dir) {
		list = r_list_new ();
		if (list) {
			list->free = free;
			while ((entry = readdir (dir))) {
				r_list_append (list, strdup (entry->d_name));
			}
		}
		closedir (dir);
	}
#endif	
	return list;
}

R_API char *r_sys_cmd_strf(const char *fmt, ...) {
	char *ret, cmd[4096];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = r_sys_cmd_str (cmd, NULL, NULL);
	va_end (ap);
	return ret;
}

#ifdef __MAC_10_7
#define APPLE_WITH_BACKTRACE 1
#endif
#ifdef __IPHONE_4_0
#define APPLE_WITH_BACKTRACE 1
#endif

#if (__linux__ && __GNU_LIBRARY__) || (__APPLE__ && APPLE_WITH_BACKTRACE) || \
  defined(NETBSD_WITH_BACKTRACE) || defined(FREEBSD_WITH_BACKTRACE) || \
  __DragonFly__
#define HAVE_BACKTRACE 1
#endif

R_API void r_sys_backtrace(void) {
#ifdef HAVE_BACKTRACE
	void *array[10];
	size_t size = backtrace (array, 10);
	eprintf ("Backtrace %zd stack frames.\n", size);
	backtrace_symbols_fd (array, size, 2);
#elif __APPLE__
	void **fp = (void **) __builtin_frame_address (0);
	void *saved_pc = __builtin_return_address (0);
	void *saved_fp = __builtin_frame_address (1);
	int depth = 0;

	printf ("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	fp = saved_fp;
	while (fp) {
		saved_fp = *fp;
		fp = saved_fp;
		if (!*fp) {
			break;
		}
		saved_pc = *(fp + 2);
		printf ("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	}
#else
#ifdef _MSC_VER
#pragma message ("TODO: r_sys_bt : unimplemented")
#else
#warning TODO: r_sys_bt : unimplemented
#endif
#endif
}

R_API int r_sys_sleep(int secs) {
#if HAS_CLOCK_NANOSLEEP
	struct timespec rqtp;
	rqtp.tv_sec = secs;
	rqtp.tv_nsec = 0;
	return clock_nanosleep (CLOCK_MONOTONIC, 0, &rqtp, NULL);
#elif __UNIX__
	return sleep (secs);
#else
	Sleep (secs * 1000); // W32
	return 0;
#endif
}

R_API int r_sys_usleep(int usecs) {
#if HAS_CLOCK_NANOSLEEP
	struct timespec rqtp;
	rqtp.tv_sec = usecs / 1000000;
	rqtp.tv_nsec = (usecs - (rqtp.tv_sec * 1000000)) * 1000;
	return clock_nanosleep (CLOCK_MONOTONIC, 0, &rqtp, NULL);
#elif __UNIX__
	return usleep (usecs);
#else
	// w32 api uses milliseconds
	usecs /= 1000;
	Sleep (usecs); // W32
	return 0;
#endif
}

R_API int r_sys_clearenv(void) {
#if __UNIX__
#if __APPLE__ && !HAVE_ENVIRON
	/* do nothing */
	if (!env) {
		env = r_sys_get_environ ();
		return 0;
	}
	if (env) {
		char **e = env;
		while (*e) {
			*e++ = NULL;
		}
	}
#else
	if (!environ) {
		return 0;
	}
	while (*environ) {
		*environ++ = NULL;
	}
#endif
	return 0;
#else
#ifdef _MSC_VER
#pragma message ("r_sys_clearenv : unimplemented for this platform")
#else
#warning r_sys_clearenv : unimplemented for this platform
#endif
	return 0;
#endif
}

R_API int r_sys_setenv(const char *key, const char *value) {
#if __UNIX__
	if (!key) {
		return 0;
	}
	if (!value) {
		unsetenv (key);
		return 0;
	}
	return setenv (key, value, 1);
#elif __WINDOWS__
	LPTSTR key_ = r_sys_conv_utf8_to_win (key);
	LPTSTR value_ = r_sys_conv_utf8_to_win (value);

	SetEnvironmentVariable (key_, value_);
	free (key_);
	free (value_);
	return 0; // TODO. get ret
#else
#warning r_sys_setenv : unimplemented for this platform
	return 0;
#endif
}

#if __UNIX__
static char *crash_handler_cmd = NULL;

static void signal_handler(int signum) {
	char cmd[1024];
	if (!crash_handler_cmd) {
		return;
	}
	snprintf (cmd, sizeof(cmd) - 1, crash_handler_cmd, getpid ());
	r_sys_backtrace ();
	exit (r_sys_cmd (cmd));
}

static int checkcmd(const char *c) {
	char oc = 0;
	for (;*c;c++) {
		if (oc == '%') {
			if (*c != 'd' && *c != '%') {
				return 0;
			}
		}
		oc = *c;
	}
	return 1;
}
#endif

R_API int r_sys_crash_handler(const char *cmd) {
#if __UNIX__
	struct sigaction sigact;
	if (!checkcmd (cmd)) {
		return false;
	}
#ifdef HAVE_BACKTRACE
	void *array[1];
	/* call this outside of the signal handler to init it safely */
	backtrace (array, 1);
#endif

	free (crash_handler_cmd);
	crash_handler_cmd = strdup (cmd);
	sigact.sa_handler = signal_handler;
	sigemptyset (&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaddset (&sigact.sa_mask, SIGINT);
	sigaddset (&sigact.sa_mask, SIGSEGV);
	sigaddset (&sigact.sa_mask, SIGBUS);
	sigaddset (&sigact.sa_mask, SIGQUIT);
	sigaddset (&sigact.sa_mask, SIGHUP);

	sigaction (SIGINT, &sigact, (struct sigaction *)NULL);
	sigaction (SIGSEGV, &sigact, (struct sigaction *)NULL);
	sigaction (SIGBUS, &sigact, (struct sigaction *)NULL);
	sigaction (SIGQUIT, &sigact, (struct sigaction *)NULL);
	sigaction (SIGHUP, &sigact, (struct sigaction *)NULL);
	return true;
#else
	return false;
#endif
}

R_API char *r_sys_getenv(const char *key) {
#if __WINDOWS__
	DWORD dwRet;
	LPTSTR envbuf = NULL, key_ = NULL, tmp_ptr;
	char *val = NULL;

	if (!key) {
		return NULL;
	}
	envbuf = (LPTSTR)malloc (sizeof (TCHAR) * TMP_BUFSIZE);
	if (!envbuf) {
		goto err_r_sys_get_env;
	}
	key_ = r_sys_conv_utf8_to_win (key);
	dwRet = GetEnvironmentVariable (key_, envbuf, TMP_BUFSIZE);
	if (dwRet == 0) {
		if (GetLastError () == ERROR_ENVVAR_NOT_FOUND) {
			goto err_r_sys_get_env;
		}
	} else if (TMP_BUFSIZE < dwRet) {
		tmp_ptr = (LPTSTR)realloc (envbuf, dwRet * sizeof (TCHAR));
		if (!tmp_ptr) {
			goto err_r_sys_get_env;
		}
		envbuf = tmp_ptr;
		dwRet = GetEnvironmentVariable (key_, envbuf, dwRet);
		if (!dwRet) {
			goto err_r_sys_get_env;
		}
	}
	val = r_sys_conv_win_to_utf8_l (envbuf, (int)dwRet);
err_r_sys_get_env:
	free (key_);
	free (envbuf);
	return val;
#else
	char *b;
	if (!key) {
		return NULL;
	}
	b = getenv (key);
	return b? strdup (b): NULL;
#endif
}

R_API char *r_sys_getdir(void) {
#if __WINDOWS__
	return _getcwd (NULL, 0);
#else
	return getcwd (NULL, 0);
#endif
}

R_API int r_sys_chdir(const char *s) {
	return r_sandbox_chdir (s)==0;
}

R_API bool r_sys_aslr(int val) {
	bool ret = true;
#if __linux__
	const char *rva = "/proc/sys/kernel/randomize_va_space";
	char buf[3] = {0};
	snprintf(buf, sizeof (buf), "%d\n", val != 0 ? 2 : 0);
	int fd = r_sandbox_open (rva, O_WRONLY, 0644);
	if (fd != -1) {
		if (r_sandbox_write (fd, (ut8 *)buf, sizeof (buf)) != sizeof (buf)) {
			eprintf ("Failed to set RVA\n");
			ret = false;
		}
		close (fd);
	}
#elif __FreeBSD__ && __FreeBSD_version >= 1300000
	size_t vlen = sizeof (val);
	if (sysctlbyname ("kern.elf32.aslr.enable", &val, &vlen, NULL, 0) == -1) {
		eprintf ("Failed to set RVA 32 bits\n");
		return false;
	}

#if __LP64__
	if (sysctlbyname ("kern.elf64.aslr.enable", &val, &vlen, NULL, 0) == -1) {
		eprintf ("Failed to set RVA 64 bits\n");
		ret = false;
	}
#endif
#endif
	return ret;
}

#if __UNIX__
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	char *mysterr = NULL;
	if (!sterr) {
		sterr = &mysterr;
	}
	char buffer[1024], *outputptr = NULL;
	char *inputptr = (char *)input;
	int pid, bytes = 0, status;
	int sh_in[2], sh_out[2], sh_err[2];

	if (len) {
		*len = 0;
	}
	if (pipe (sh_in)) {
		return false;
	}
	if (output) {
		if (pipe (sh_out)) {
			close (sh_in[0]);
			close (sh_in[1]);
			close (sh_out[0]);
			close (sh_out[1]);
			return false;
		}
	}
	if (pipe (sh_err)) {
		close (sh_in[0]);
		close (sh_in[1]);
		return false;
	}

	switch ((pid = r_sys_fork ())) {
	case -1:
		return false;
	case 0:
		dup2 (sh_in[0], 0);
		close (sh_in[0]);
		close (sh_in[1]);
		if (output) {
			dup2 (sh_out[1], 1);
			close (sh_out[0]);
			close (sh_out[1]);
		}
		if (sterr) {
			dup2 (sh_err[1], 2); 
		} else {
			close (2);
		}
		close (sh_err[0]);
		close (sh_err[1]);
		exit (r_sandbox_system (cmd, 0));
	default:
		outputptr = strdup ("");
		if (!outputptr) {
			return false;
		}
		if (sterr) {
			*sterr = strdup ("");
			if (!*sterr) {
				free (outputptr);
				return false;
			}
		}
		if (output) {
			close (sh_out[1]);
		}
		close (sh_err[1]);
		close (sh_in[0]);
		if (!inputptr || !*inputptr) {
			close (sh_in[1]);
		}
		// we should handle broken pipes somehow better
		signal (SIGPIPE, SIG_IGN);
		for (;;) {
			fd_set rfds, wfds;
			int nfd;
			FD_ZERO (&rfds);
			FD_ZERO (&wfds);
			if (output) {
				FD_SET (sh_out[0], &rfds);
			}
			if (sterr) {
				FD_SET (sh_err[0], &rfds);
			}
			if (inputptr && *inputptr) {
				FD_SET (sh_in[1], &wfds);
			}
			memset (buffer, 0, sizeof (buffer));
			nfd = select (sh_err[0] + 1, &rfds, &wfds, NULL, NULL);
			if (nfd < 0) {
				break;
			}
			if (output && FD_ISSET (sh_out[0], &rfds)) {
				if (!(bytes = read (sh_out[0], buffer, sizeof (buffer)-1))) {
					break;
				}
				buffer[sizeof (buffer) - 1] = '\0';
				if (len) {
					*len += bytes;
				}
				outputptr = r_str_append (outputptr, buffer);
			} else if (FD_ISSET (sh_err[0], &rfds) && sterr) {
				if (!read (sh_err[0], buffer, sizeof (buffer)-1)) {
					break;
				}
				buffer[sizeof (buffer) - 1] = '\0';
				*sterr = r_str_append (*sterr, buffer);
			} else if (FD_ISSET (sh_in[1], &wfds) && inputptr && *inputptr) {
				int inputptr_len = strlen (inputptr);
				bytes = write (sh_in[1], inputptr, inputptr_len);
				if (bytes != inputptr_len) {
					break;
				}
				inputptr += bytes;
				if (!*inputptr) {
					close (sh_in[1]);
					/* If neither stdout nor stderr should be captured,
					 * abort now - nothing more to do for select(). */
					if (!output && !sterr) {
						break;
					}
				}
			}
		}
		if (output) {
			close (sh_out[0]);
		}
		close (sh_err[0]);
		close (sh_in[1]);
		waitpid (pid, &status, 0);
		bool ret = true;
		if (status) {
			// char *escmd = r_str_escape (cmd);
			// eprintf ("error code %d (%s): %s\n", WEXITSTATUS (status), escmd, *sterr);
			// eprintf ("(%s)\n", output);
			// eprintf ("%s: failed command '%s'\n", __func__, escmd);
			// free (escmd);
			ret = false;
		}

		if (output) {
			*output = outputptr;
		} else {
			free (outputptr);
		}
		return ret;
	}
	return false;
}
#elif __WINDOWS__
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	return r_sys_cmd_str_full_w32 (cmd, input, output, len, sterr);
}
#else
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	eprintf ("r_sys_cmd_str: not yet implemented for this platform\n");
	return false;
}
#endif

R_API int r_sys_cmdf (const char *fmt, ...) {
	int ret;
	char cmd[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = r_sys_cmd (cmd);
	va_end (ap);
	return ret;
}

R_API int r_sys_cmdbg (const char *str) {
#if __UNIX__
	int ret, pid = r_sys_fork ();
	if (pid == -1) {
		return -1;
	}
	if (pid) {
		return pid;
	}
	ret = r_sandbox_system (str, 0);
	eprintf ("{exit: %d, pid: %d, cmd: \"%s\"}", ret, pid, str);
	exit (0);
	return -1;
#else
#ifdef _MSC_VER
#pragma message ("r_sys_cmdbg is not implemented for this platform")
#else
#warning r_sys_cmdbg is not implemented for this platform
#endif
	return -1;
#endif
}

R_API int r_sys_cmd(const char *str) {
	if (r_sandbox_enable (0)) {
		return false;
	}
#if __FreeBSD__
	/* freebsd system() is broken */
	int st, pid, fds[2];
	if (pipe (fds)) {
		return -1;
	}
	pid = vfork ();
	if (pid == -1) {
		return -1;
	}
	if (!pid) {
		dup2 (1, fds[1]);
		// char *argv[] = { "/bin/sh", "-c", str, NULL};
		// execv (argv[0], argv);
		r_sandbox_system (str, 0);
		_exit (127); /* error */
	} else {
		dup2 (1, fds[0]);
		waitpid (pid, &st, 0);
	}
	return WEXITSTATUS (st);
#else
	return r_sandbox_system (str, 1);
#endif
}

R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len) {
	char *output = NULL;
	if (r_sys_cmd_str_full (cmd, input, &output, len, NULL)) {
		return output;
	}
	free (output);
	return NULL;
}

R_API bool r_sys_mkdir(const char *dir) {
	bool ret;

	if (r_sandbox_enable (0)) {
		return false;
	}
#if __WINDOWS__
	LPTSTR dir_ = r_sys_conv_utf8_to_win (dir);

	ret = CreateDirectory (dir_, NULL) != 0;
	free (dir_);
#else
	ret = mkdir (dir, 0755) != -1;
#endif
	return ret;
}

R_API bool r_sys_mkdirp(const char *dir) {
	bool ret = true;
	char slash = R_SYS_DIR[0];
	char *path = strdup (dir), *ptr = path;
	if (!path) {
		eprintf ("r_sys_mkdirp: Unable to allocate memory\n");
		return false;
	}
	if (*ptr == slash) {
		ptr++;
	}
#if __WINDOWS__
	{
		char *p = strstr (ptr, ":\\");
		if (p) {
			ptr = p + 2;
		}
	}
#endif
	for (;;) {
		// find next slash
		for (; *ptr; ptr++) {
			if (*ptr == '/' || *ptr == '\\') {
				slash = *ptr;
				break;
			}
		}
		if (!*ptr) {
			break;
		}
		*ptr = 0;
		if (!r_sys_mkdir (path) && r_sys_mkdir_failed ()) {
			eprintf ("r_sys_mkdirp: fail '%s' of '%s'\n", path, dir);
			free (path);
			return false;
		}
		*ptr = slash;
		ptr++;
	}
	if (!r_sys_mkdir (path) && r_sys_mkdir_failed ()) {
		ret = false;
	}
	free (path);
	return ret;
}

R_API void r_sys_perror_str(const char *fun) {
#if __UNIX__
#pragma push_macro("perror")
#undef perror
	perror (fun);
#pragma pop_macro("perror")
#elif __WINDOWS__
	LPTSTR lpMsgBuf;
	DWORD dw = GetLastError();

	if (FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf,
			0, NULL )) {
		char *err = r_sys_conv_win_to_utf8 (lpMsgBuf);
		if (err) {
			eprintf ("%s: %s\n", fun, err);
			free (err);
		}
		LocalFree (lpMsgBuf);
	} else {
		eprintf ("%s\n", fun);
	}
#endif
}

R_API bool r_sys_arch_match(const char *archstr, const char *arch) {
	char *ptr;
	if (!archstr || !arch || !*archstr || !*arch) {
		return true;
	}
	if (!strcmp (archstr, "*") || !strcmp (archstr, "any")) {
		return true;
	}
	if (!strcmp (archstr, arch)) {
		return true;
	}
	if ((ptr = strstr (archstr, arch))) {
		char p = ptr[strlen (arch)];
		if (!p || p==',') {
			return true;
		}
	}
	return false;
}

R_API int r_sys_arch_id(const char *arch) {
	int i;
	for (i = 0; arch_bit_array[i].name; i++) {
		if (!strcmp (arch, arch_bit_array[i].name)) {
			return arch_bit_array[i].bit;
		}
	}
	return 0;
}

R_API const char *r_sys_arch_str(int arch) {
	int i;
	for (i = 0; arch_bit_array[i].name; i++) {
		if (arch & arch_bit_array[i].bit) {
			return arch_bit_array[i].name;
		}
	}
	return "none";
}

#define USE_FORK 0
R_API int r_sys_run(const ut8 *buf, int len) {
	const int sz = 4096;
	int pdelta, ret, (*cb)();
#if USE_FORK
	int st, pid;
#endif
// TODO: define R_SYS_ALIGN_FORWARD in r_util.h
	ut8 *ptr, *p = malloc ((sz + len) << 1);
	ptr = p;
	pdelta = ((size_t)(p)) & (4096 - 1);
	if (pdelta) {
		ptr += (4096 - pdelta);
	}
	if (!ptr || !buf) {
		eprintf ("r_sys_run: Cannot run empty buffer\n");
		free (p);
		return false;
	}
	memcpy (ptr, buf, len);
	r_mem_protect (ptr, sz, "rx");
	//r_mem_protect (ptr, sz, "rwx"); // try, ignore if fail
	cb = (int (*)())ptr;
#if USE_FORK
#if __UNIX__
	pid = r_sys_fork ();
#else
	pid = -1;
#endif
	if (pid < 0) {
		return cb ();
	}
	if (!pid) {
		ret = cb ();
		exit (ret);
		return ret;
	}
	st = 0;
	waitpid (pid, &st, 0);
	if (WIFSIGNALED (st)) {
		int num = WTERMSIG(st);
		eprintf ("Got signal %d\n", num);
		ret = num;
	} else {
		ret = WEXITSTATUS (st);
	}
#else
	ret = (*cb) ();
#endif
	free (p);
	return ret;
}

R_API int r_is_heap (void *p) {
	void *q = malloc (8);
	ut64 mask = UT64_MAX;
	ut64 addr = (ut64)(size_t)q;
	addr >>= 16;
	addr <<= 16;
	mask >>= 16;
	mask <<= 16;
	free (q);
	return (((ut64)(size_t)p) == mask);
}

R_API char *r_sys_pid_to_path(int pid) {
#if __WINDOWS__
	// TODO: add maximum path length support
	HANDLE processHandle;
	const DWORD maxlength = MAX_PATH;
	TCHAR filename[MAX_PATH];
	const char *result;

	processHandle = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!processHandle) {
		eprintf ("r_sys_pid_to_path: Cannot open process.\n");
		return NULL;
	}
	DWORD length = GetModuleFileNameEx (processHandle, NULL, filename, maxlength);
	if (length == 0) {
		// Upon failure fallback to GetProcessImageFileName
		length = GetProcessImageFileName (processHandle, filename, maxlength);
		CloseHandle (processHandle);
		if (length == 0) {
			eprintf ("r_sys_pid_to_path: Error calling GetProcessImageFileName\n");
			return NULL;
		}
		// Convert NT path to win32 path
		char *name = r_sys_conv_win_to_utf8 (filename);
		if (!name) {
			eprintf ("r_sys_pid_to_path: Error converting to utf8\n");
			return NULL;
		}
		char *tmp = strchr (name + 1, '\\');
		if (!tmp) {
			free (name);
			eprintf ("r_sys_pid_to_path: Malformed NT path\n");
			return NULL;
		}
		tmp = strchr (tmp + 1, '\\');
		if (!tmp) {
			free (name);
			eprintf ("r_sys_pid_to_path: Malformed NT path\n");
			return NULL;
		}
		length = tmp - name;
		tmp = malloc (length + 1);
		if (!tmp) {
			free (name);
			eprintf ("r_sys_pid_to_path: Error allocating memory\n");
			return NULL;
		}
		strncpy (tmp, name, length);
		tmp[length] = '\0';
		TCHAR device[MAX_PATH];
		for (TCHAR drv[] = TEXT("A:"); drv[0] <= TEXT('Z'); drv[0]++) {
			if (QueryDosDevice (drv, device, maxlength) > 0) {
				char *dvc = r_sys_conv_win_to_utf8 (device);
				if (!dvc) {
					free (name);
					free (tmp);
					eprintf ("r_sys_pid_to_path: Error converting to utf8\n");
					return NULL;
				}
				if (!strcmp (tmp, dvc)) {
					free (tmp);
					free (dvc);
					char *d = r_sys_conv_win_to_utf8 (drv);
					if (!d) {
						free (name);
						eprintf ("r_sys_pid_to_path: Error converting to utf8\n");
						return NULL;
					}
					tmp = r_str_newf ("%s%s", d, &name[length]);
					free (d);
					if (!tmp) {
						free (name);
						eprintf ("r_sys_pid_to_path: Error calling r_str_newf\n");
						return NULL;
					}
					result = strdup (tmp);
					break;
				}
				free (dvc);
			}
		}
		free (name);
		free (tmp);
	} else {
		CloseHandle (processHandle);
		result = r_sys_conv_win_to_utf8 (filename);
	}
	return result;
#elif __APPLE__
#if __POWERPC__
#warning TODO getpidproc
	return NULL;
#else
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	pathbuf[0] = 0;
	int ret = proc_pidpath (pid, pathbuf, sizeof (pathbuf));
	if (ret <= 0) {
		return NULL;
	}
	return strdup (pathbuf);
#endif
#else
	int ret;
#if __FreeBSD__
	char pathbuf[PATH_MAX];
	size_t pathbufl = sizeof (pathbuf);
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid};
	ret = sysctl (mib, 4, pathbuf, &pathbufl, NULL, 0);
	if (ret != 0) {
		return NULL;
	}
#else
	char buf[128], pathbuf[1024];
	snprintf (buf, sizeof (buf), "/proc/%d/exe", pid);
	ret = readlink (buf, pathbuf, sizeof (pathbuf)-1);
	if (ret < 1) {
		return NULL;
	}
	pathbuf[ret] = 0;
#endif
	return strdup (pathbuf);
#endif
}

// TODO: rename to r_sys_env_init()
R_API char **r_sys_get_environ () {
#if __APPLE__ && !HAVE_ENVIRON
	env = *_NSGetEnviron();
#else
	env = environ;
#endif
	// return environ if available??
	if (!env) {
		env = r_lib_dl_sym (NULL, "environ");
	}
	return env;
}

R_API void r_sys_set_environ (char **e) {
	env = e;
}

R_API char *r_sys_whoami (char *buf) {
	char _buf[32];
	int pid = getpid ();
	int hasbuf = (buf)? 1: 0;
	if (!hasbuf) {
		buf = _buf;
	}
	sprintf (buf, "pid%d", pid);
	return hasbuf? buf: strdup (buf);
}

R_API int r_sys_getpid() {
#if __UNIX__
	return getpid ();
#elif __WINDOWS__
	return GetCurrentProcessId();
#else
#warning r_sys_getpid not implemented for this platform
	return -1;
#endif
}

R_API bool r_sys_tts(const char *txt, bool bg) {
	int i;
	r_return_val_if_fail (txt, false);
	const char *says[] = {
		"say", "termux-tts-speak", NULL
	};
	for (i = 0; says[i]; i++) {
		char *sayPath = r_file_path (says[i]);
		if (sayPath) {
			char *line = r_str_replace (strdup (txt), "'", "\"", 1);
			r_sys_cmdf ("\"%s\" '%s'%s", sayPath, line, bg? " &": "");
			free (line);
			free (sayPath);
			return true;
		}
	}
	return false;
}

R_API const char *r_sys_prefix(const char *pfx) {
	static char prefix[1024] = {0};
	if (!*prefix) {
		r_str_ncpy (prefix, R2_PREFIX, sizeof (prefix));
	}
	if (pfx) {
		if (strlen (pfx) >= sizeof (prefix) - 1) {
			return NULL;
		}
		r_str_ncpy (prefix, pfx, sizeof (prefix) - 1);
	}
	return prefix;
}
