/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_userconf.h>

#if DEBUGGER
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <r_anal.h>
#include <signal.h>
#include <sys/uio.h>
#include <errno.h>
#include "linux_debug.h"
#include "../procfs.h"

#include <sys/syscall.h>
#include <unistd.h>
#include <elf.h>

#include "linux_ptrace.h"

#ifdef __GLIBC__
#define HAVE_YMM 1
#else
#define HAVE_YMM 0
#endif

char *linux_reg_profile (RDebug *dbg) {
#if __arm__
#	include "reg/linux-arm.h"
#elif __riscv
#	include "reg/linux-riscv64.h"
#elif __arm64__ || __aarch64__
#	include "reg/linux-arm64.h"
#elif __mips__
	if ((dbg->bits & R_SYS_BITS_32) && (dbg->bp->endian == 1)) {
#		include "reg/linux-mips.h"
	} else {
#		include "reg/linux-mips64.h"
	}
#elif (__i386__ || __x86_64__)
	if (dbg->bits & R_SYS_BITS_32) {
#if __x86_64__
#		include "reg/linux-x64-32.h"
#else
#		include "reg/linux-x86.h"
#endif
	} else {
#		include "reg/linux-x64.h"
	}
#elif __powerpc__
	if (dbg->bits & R_SYS_BITS_32) {
#		include "reg/linux-ppc.h"
	} else {
#		include "reg/linux-ppc64.h"
	}
#elif __s390x__
#	include "reg/linux-s390x.h"
#else
#	error "Unsupported Linux CPU"
	return NULL;
#endif
}

static void linux_detach_all(RDebug *dbg);
static char *read_link(int pid, const char *file);
static bool linux_attach_single_pid(RDebug *dbg, int ptid);
static void linux_remove_thread(RDebug *dbg, int pid);
static void linux_add_new_thread(RDebug *dbg, int tid);
static bool linux_stop_thread(RDebug *dbg, int tid);
static bool linux_kill_thread(int tid, int signo);
static void linux_dbg_wait_break_main(RDebug *dbg);
static void linux_dbg_wait_break(RDebug *dbg);
static RDebugReasonType linux_handle_new_task(RDebug *dbg, int tid);

int linux_handle_signals(RDebug *dbg, int tid) {
	siginfo_t siginfo = { 0 };
	int ret = r_debug_ptrace (dbg, PTRACE_GETSIGINFO, tid, 0, (r_ptrace_data_t)&siginfo);
	if (ret == -1) {
		/* ESRCH means the process already went away :-/ */
		if (errno == ESRCH) {
			dbg->reason.type = R_DEBUG_REASON_DEAD;
			return true;
		}
		r_sys_perror ("ptrace GETSIGINFO");
		return false;
	}

	if (siginfo.si_signo > 0) {
		//siginfo_t newsiginfo = {0};
		//ptrace (PTRACE_SETSIGINFO, dbg->pid, 0, &siginfo);
		dbg->reason.type = R_DEBUG_REASON_SIGNAL;
		dbg->reason.signum = siginfo.si_signo;
		dbg->stopaddr = (ut64)(size_t)siginfo.si_addr;
		//dbg->errno = siginfo.si_errno;
		// siginfo.si_code -> HWBKPT, USER, KERNEL or WHAT
		// TODO: DO MORE RDEBUGREASON HERE
		switch (dbg->reason.signum) {
		case SIGABRT: // 6 / SIGIOT // SIGABRT
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGALRM:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGBUS:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGCHLD:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;;
			break;
		case SIGCONT:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
#if __sparc__
		case SIGEMT:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
#endif
		case SIGFPE:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGHUP:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGILL:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGINT:
			dbg->reason.type = R_DEBUG_REASON_USERSUSP;
			break;
		case SIGKILL:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGPROF:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGQUIT:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGSEGV:
			dbg->reason.type = R_DEBUG_REASON_SEGFAULT;
			break;
		case SIGSTKFLT:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGSTOP:
			dbg->reason.type = R_DEBUG_REASON_STOPPED;
			break;
		case SIGSYS:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGTERM:
			dbg->reason.type = R_DEBUG_REASON_TERMINATED;
			break;
		case SIGTRAP:
		{
			if (dbg->glob_libs || dbg->glob_unlibs) {
				ut64 pc_addr = r_debug_reg_get (dbg, "PC");
				RBreakpointItem *b = r_bp_get_at (dbg->bp, pc_addr - dbg->bpsize);
				if (b && b->internal) {
					char *p = strstr (b->data, "dbg.");
					if (p) {
						if (r_str_startswith (p, "dbg.libs")) {
							const char *name;
							if (strstr (b->data, "sym.imp.dlopen")) {
								name = r_reg_get_name (dbg->reg, R_REG_NAME_A0);
							} else {
								name = r_reg_get_name (dbg->reg, R_REG_NAME_A1);
							}
							b->data = r_str_appendf (b->data, ";ps@r:%s", name);
							dbg->reason.type = R_DEBUG_REASON_NEW_LIB;
							break;
						} else if (r_str_startswith (p, "dbg.unlibs")) {
							dbg->reason.type = R_DEBUG_REASON_EXIT_LIB;
							break;
						}
					}
				}
			}
			if (dbg->reason.type != R_DEBUG_REASON_NEW_LIB &&
				dbg->reason.type != R_DEBUG_REASON_EXIT_LIB) {
				if (siginfo.si_code == TRAP_TRACE) {
					dbg->reason.type = R_DEBUG_REASON_STEP;
				} else {
					dbg->reason.bp_addr = (ut64)(size_t)siginfo.si_addr;
					dbg->reason.type = R_DEBUG_REASON_BREAKPOINT;
					// Switch to the thread that hit the breakpoint
					r_debug_select (dbg, dbg->pid, tid);
					dbg->tid = tid;
				}
			}
		} break;
		case SIGTSTP:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGTTIN:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGTTOU:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		//SIGUNUSED
		case SIGURG:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGUSR1:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGUSR2:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGVTALRM:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGWINCH:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGXCPU:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		case SIGXFSZ:
			dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			break;
		default:
			break;
		}
		if (dbg->reason.signum != SIGTRAP &&
			(dbg->reason.signum != SIGINT || !r_cons_is_breaked ())) {
			eprintf ("[+] SIGNAL %d errno=%d addr=0x%08"PFMT64x
				" code=%d si_pid=%d ret=%d\n",
				siginfo.si_signo, siginfo.si_errno,
				(ut64) (size_t)siginfo.si_addr, siginfo.si_code, siginfo.si_pid, ret);
		}
		return true;
	}
	return false;
}

#if __ANDROID__
#undef PT_GETEVENTMSG
#define PT_GETEVENTMSG
#endif

// Used to remove breakpoints before detaching from a fork, without it the child
// will die upon hitting a breakpoint while not being traced
static void linux_remove_fork_bps(RDebug *dbg) {
	RListIter *iter;
	RBreakpointItem *b;
	int prev_pid = dbg->pid;
	int prev_tid = dbg->tid;

	// Set dbg tid to the new child temporarily
	dbg->pid = dbg->forked_pid;
	dbg->tid = dbg->forked_pid;
	r_debug_select (dbg, dbg->forked_pid, dbg->forked_pid);

	// Unset all hw breakpoints in the child process
	r_debug_reg_sync (dbg, R_REG_TYPE_DRX, false);
	r_list_foreach (dbg->bp->bps, iter, b) {
		r_debug_drx_unset (dbg, r_bp_get_index_at (dbg->bp, b->addr));
	}
	r_debug_reg_sync (dbg, R_REG_TYPE_DRX, true);

	// Unset software breakpoints in the child process
	r_debug_bp_update (dbg);
	r_bp_restore (dbg->bp, false);

	// Return to the parent
	dbg->pid = prev_pid;
	dbg->tid = prev_tid;
	r_debug_select (dbg, dbg->pid, dbg->pid);

	// Restore sw breakpoints in the parent
	r_bp_restore (dbg->bp, true);
}

#ifdef PT_GETEVENTMSG
/*
 * @brief Handle PTRACE_EVENT_* when receiving SIGTRAP
 *
 * @param dowait Do waitpid to consume any signal in the newly created task
 * @return RDebugReasonType,
 * - R_DEBUG_REASON_UNKNOWN if the ptrace_event cannot be handled,
 * - R_DEBUG_REASON_ERROR if a ptrace command failed.
 *
 * NOTE: This API was added in Linux 2.5.46
 */
RDebugReasonType linux_ptrace_event (RDebug *dbg, int ptid, int status, bool dowait) {
	ut32 pt_evt;
#if __powerpc64__ || __arm64__ || __aarch64__ || __x86_64__
	ut64 data;
#else
	ut32 data;
#endif
	/* we only handle stops with SIGTRAP here */
	if (!WIFSTOPPED (status) || WSTOPSIG (status) != SIGTRAP) {
		return R_DEBUG_REASON_UNKNOWN;
	}

	pt_evt = status >> 16;
	switch (pt_evt) {
	case 0:
		/* NOTE: this case is handled by linux_handle_signals */
		break;
	case PTRACE_EVENT_CLONE:
		// Get the tid of the new thread
		if (r_debug_ptrace (dbg, PTRACE_GETEVENTMSG, ptid, 0, (r_ptrace_data_t)(size_t)&data) == -1) {
			r_sys_perror ("ptrace GETEVENTMSG");
			return R_DEBUG_REASON_ERROR;
		}
		if (dowait) {
			// The new child has a pending SIGSTOP.  We can't affect it until it
			// hits the SIGSTOP, but we're already attached.  */
			if (waitpid ((int)data, &status, 0) == -1) {
				perror ("waitpid");
			}
		}

		linux_add_new_thread (dbg, (int)data);
		if (dbg->trace_clone) {
			r_debug_select (dbg, dbg->pid, (int)data);
		}
		eprintf ("(%d) Created thread %d\n", ptid, (int)data);
		return R_DEBUG_REASON_NEW_TID;
	case PTRACE_EVENT_VFORK:
	case PTRACE_EVENT_FORK:
		// Get the pid of the new process
		if (r_debug_ptrace (dbg, PTRACE_GETEVENTMSG, ptid, 0, (r_ptrace_data_t)(size_t)&data) == -1) {
			r_sys_perror ("ptrace GETEVENTMSG");
			return R_DEBUG_REASON_ERROR;
		}
		dbg->forked_pid = data;
		if (dowait) {
			// The new child has a pending SIGSTOP. We can't affect it until it
			// hits the SIGSTOP, but we're already attached.  */
			if (waitpid (dbg->forked_pid, &status, 0) == -1) {
				perror ("waitpid");
			}
		}
		eprintf ("(%d) Created process %d\n", ptid, (int)data);
		if (!dbg->trace_forks) {
			// We need to do this even if the new process will be detached since the
			// breakpoints are inherited from the parent
			linux_remove_fork_bps (dbg);
			if (r_debug_ptrace (dbg, PTRACE_DETACH, dbg->forked_pid, NULL, (r_ptrace_data_t)(size_t)NULL) == -1) {
				perror ("PTRACE_DETACH");
			}
		}
		return R_DEBUG_REASON_NEW_PID;
	case PTRACE_EVENT_EXIT:
		// Get the exit status of the exiting task
		if (r_debug_ptrace (dbg, PTRACE_GETEVENTMSG, ptid, 0, (r_ptrace_data_t)(size_t)&data) == -1) {
			r_sys_perror ("ptrace GETEVENTMSG");
			return R_DEBUG_REASON_ERROR;
		}
		//TODO: Check other processes exit if dbg->trace_forks is on
		if (ptid != dbg->pid) {
			eprintf ("(%d) Thread exited with status=0x%"PFMT64x"\n", ptid, (ut64)data);
			return R_DEBUG_REASON_EXIT_TID;
		} else {
			eprintf ("(%d) Process exited with status=0x%"PFMT64x"\n", ptid, (ut64)data);
			return R_DEBUG_REASON_EXIT_PID;
		}
	default:
		eprintf ("Unknown PTRACE_EVENT encountered: %d\n", pt_evt);
		break;
	}
	return R_DEBUG_REASON_UNKNOWN;
}
#endif

/*
 * @brief Search for the parent of the newly created task and
 * handle the pending SIGTRAP with PTRACE_EVENT_*
 *
 * @param tid, TID of the new task
 * @return RDebugReasonType, Debug reason
 */
static RDebugReasonType linux_handle_new_task(RDebug *dbg, int tid) {
	int ret, status;
	if (dbg->threads) {
		RDebugPid *th;
		RListIter *it;
		// Search for SIGTRAP with PTRACE_EVENT_* in other threads.
		r_list_foreach (dbg->threads, it, th) {
			if (th->pid == tid) {
				continue;
			}
			// Retrieve the signal without consuming it with PTRACE_GETSIGINFO
			siginfo_t siginfo = { 0 };
			ret = r_debug_ptrace (dbg, PTRACE_GETSIGINFO, th->pid, 0, (r_ptrace_data_t)(size_t)&siginfo);
			// Skip if PTRACE_GETSIGINFO fails when the thread is running.
			if (ret == -1) {
				continue;
			}
#ifdef PT_GETEVENTMSG
			// NOTE: This API was added in Linux 2.5.46
			if (siginfo.si_signo == SIGTRAP) {
				// si_code = (SIGTRAP | PTRACE_EVENT_* << 8)
				int pt_evt = siginfo.si_code >> 8;
				// Handle PTRACE_EVENT_* that creates a new task (fork/clone)
				switch (pt_evt) {
				case PTRACE_EVENT_CLONE:
				case PTRACE_EVENT_VFORK:
				case PTRACE_EVENT_FORK:
					ret = waitpid (th->pid, &status, 0);
					return linux_ptrace_event (dbg, ret, status, false);
				default:
					break;
				}
			}
#endif
		}
	}
	return R_DEBUG_REASON_UNKNOWN;
}

int linux_step(RDebug *dbg) {
	int ret = false;
	int pid = dbg->tid;
	ret = r_debug_ptrace (dbg, PTRACE_SINGLESTEP, pid, 0, 0);
	//XXX(jjd): why?? //linux_handle_signals (dbg);
	if (ret == -1) {
		perror ("native-singlestep");
		ret = false;
	} else {
		ret = true;
	}
	return ret;
}

bool linux_set_options(RDebug *dbg, int pid) {
	int traceflags = 0;
	traceflags |= PTRACE_O_TRACEFORK;
	traceflags |= PTRACE_O_TRACEVFORK;
	traceflags |= PTRACE_O_TRACECLONE;
	if (dbg->trace_forks) {
		traceflags |= PTRACE_O_TRACEVFORKDONE;
	}
	if (dbg->trace_execs) {
		traceflags |= PTRACE_O_TRACEEXEC;
	}
	if (dbg->trace_aftersyscall) {
		traceflags |= PTRACE_O_TRACEEXIT;
	}
	/* SIGTRAP | 0x80 on signal handler .. not supported on all archs */
	traceflags |= PTRACE_O_TRACESYSGOOD;

	// PTRACE_SETOPTIONS can fail because of the asynchronous nature of ptrace
	// If the target is traced, the loop will always end with success
	while (r_debug_ptrace (dbg, PTRACE_SETOPTIONS, pid, 0, (r_ptrace_data_t)(size_t)traceflags) == -1) {
		void *bed = r_cons_sleep_begin ();
		usleep (1000);
		r_cons_sleep_end (bed);
	}
	return true;
}

static void linux_detach_all(RDebug *dbg) {
	RList *th_list = dbg->threads;
	if (th_list) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (th_list, it, th) {
			if (th->pid != dbg->main_pid) {
				if (r_debug_ptrace (dbg, PTRACE_DETACH, th->pid, NULL, (r_ptrace_data_t)(size_t)NULL) == -1) {
					perror ("PTRACE_DETACH");
				}
			}
		}
	}

	// Detaching from main proc
	if (r_debug_ptrace (dbg, PTRACE_DETACH, dbg->main_pid, NULL, (r_ptrace_data_t)(size_t)NULL) == -1) {
		perror ("PTRACE_DETACH");
	}
}

static void linux_remove_thread(RDebug *dbg, int tid) {
	if (dbg->threads) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (dbg->threads, it, th) {
			if (th->pid == tid) {
				r_list_delete (dbg->threads, it);
				dbg->n_threads--;
				break;
			}
		}
	}
}

bool linux_select(RDebug *dbg, int pid, int tid) {
	if (dbg->pid != -1 && dbg->pid != pid) {
		return linux_attach_new_process (dbg, pid);
	}
	return linux_attach (dbg, tid);
}

bool linux_attach_new_process(RDebug *dbg, int pid) {
	linux_detach_all (dbg);
	if (dbg->threads) {
		r_list_free (dbg->threads);
		dbg->threads = NULL;
	}

	if (!linux_attach (dbg, pid)) {
		return false;
	}

	// Call select to syncrhonize the thread's data.
	dbg->pid = pid;
	dbg->tid = pid;
	r_debug_select (dbg, pid, pid);

	return true;
}

static void linux_dbg_wait_break_main(RDebug *dbg) {
	// Get the debugger and debuggee process group ID
	pid_t dpgid = getpgid (0);
	if (dpgid == -1) {
		r_sys_perror ("getpgid");
		return;
	}
	pid_t tpgid = getpgid (dbg->pid);
	if (tpgid == -1) {
		r_sys_perror ("getpgid");
		return;
	}

	// If the debuggee process is created by the debugger, do nothing because
	// SIGINT is already sent to both the debugger and debuggee in the same
	// process group.

	// If the debuggee is attached by the debugger, send SIGINT to the debuggee
	// in another process group.
	if (dpgid != tpgid) {
		if (!linux_kill_thread (dbg->pid, SIGINT)) {
			eprintf ("Could not interrupt pid (%d)\n", dbg->pid);
		}
	}
}

static void linux_dbg_wait_break(RDebug *dbg) {
	if (!linux_kill_thread (dbg->pid, SIGINT)) {
		eprintf ("Could not interrupt pid (%d)\n", dbg->pid);
	}
}

RDebugReasonType linux_dbg_wait(RDebug *dbg, int pid) {
	RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;
	int tid = pid;
	int status, flags = __WALL;
	int ret = -1;

	if (pid == -1) {
		flags |= WNOHANG;
	}

	for (;;) {
		// In the main context, SIGINT is propagated to the debuggee if it is
		// in the same process group. Otherwise, the task is running in
		// background and SIGINT will not be propagated to the debuggee.
		if (r_cons_context_is_main ()) {
			r_cons_break_push ((RConsBreak)linux_dbg_wait_break_main, dbg);
		} else {
			r_cons_break_push ((RConsBreak)linux_dbg_wait_break, dbg);
		}
		void *bed = r_cons_sleep_begin ();
		if (dbg->continue_all_threads) {
			ret = waitpid (-1, &status, flags);
		} else {
			ret = waitpid (pid, &status, flags);
		}
		r_cons_sleep_end (bed);
		r_cons_break_pop ();

		if (ret < 0) {
			// Continue when interrupted by user;
			if (errno == EINTR) {
				continue;
			}
			perror ("waitpid");
			break;
		} else if (ret == 0) {
			// Unset WNOHANG to call next waitpid in blocking mode.
			flags &= ~WNOHANG;
		} else {
			tid = ret;

			// Handle SIGTRAP with PTRACE_EVENT_*
			reason = linux_ptrace_event (dbg, tid, status, true);
			if (reason != R_DEBUG_REASON_UNKNOWN) {
				break;
			}

			if (WIFEXITED (status)) {
				if (tid == dbg->main_pid) {
					r_list_free (dbg->threads);
					dbg->threads = NULL;
					reason = R_DEBUG_REASON_DEAD;
					eprintf ("(%d) Process terminated with status %d\n", tid, WEXITSTATUS (status));
					break;
				} else {
					eprintf ("(%d) Child terminated with status %d\n", tid, WEXITSTATUS (status));
					linux_remove_thread (dbg, tid);
					continue;
				}
			} else if (WIFSIGNALED (status)) {
				eprintf ("child received signal %d\n", WTERMSIG (status));
				reason = R_DEBUG_REASON_SIGNAL;
			} else if (WIFSTOPPED (status)) {
				// If tid is not in the thread list and stopped by SIGSTOP,
				// handle it as a new task.
				if (!r_list_find (dbg->threads, &tid, &match_pid) &&
					WSTOPSIG (status) == SIGSTOP) {
					reason = linux_handle_new_task (dbg, tid);
					if (reason != R_DEBUG_REASON_UNKNOWN) {
						break;
					}
				}

				if (linux_handle_signals (dbg, tid)) {
					reason = dbg->reason.type;
				} else {
					eprintf ("can't handle signals\n");
					return R_DEBUG_REASON_ERROR;
				}
#ifdef WIFCONTINUED
			} else if (WIFCONTINUED (status)) {
				eprintf ("child continued...\n");
				reason = R_DEBUG_REASON_NONE;
#endif
			} else if (status == 1) {
				eprintf ("EEK DEAD DEBUGEE!\n");
				reason = R_DEBUG_REASON_DEAD;
			} else if (status == 0) {
				eprintf ("STATUS=0?!?!?!?\n");
				reason = R_DEBUG_REASON_DEAD;
			} else {
				if (ret != tid) {
					reason = R_DEBUG_REASON_NEW_PID;
				} else {
					eprintf ("CRAP. returning from wait without knowing why...\n");
				}
			}
			if (reason != R_DEBUG_REASON_UNKNOWN) {
				break;
			}
		}
	}
	dbg->reason.tid = tid;
	return reason;
}

int match_pid(const void *pid_o, const void *th_o) {
	int pid = *(int *)pid_o;
	RDebugPid *th = (RDebugPid *)th_o;
	return (pid == th->pid)? 0 : 1;
}

static void linux_add_new_thread(RDebug *dbg, int tid) {
	int uid = getuid(); // XXX
	char info[1024] = {0};
	RDebugPid *tid_info;

	if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
		tid_info = fill_pid_info (info, NULL, tid);
	} else {
		tid_info = r_debug_pid_new ("new_path", tid, uid, 's', 0);
	}
	linux_set_options (dbg, tid);
	r_list_append (dbg->threads, tid_info);
	dbg->n_threads++;
}

static bool linux_kill_thread(int tid, int signo) {
	int ret = syscall (__NR_tkill, tid, signo);

	if (ret == -1) {
		perror ("tkill");
		return false;
	}

	return true;
}

static bool linux_stop_thread(RDebug *dbg, int tid) {
	int status, ret;
	siginfo_t siginfo = { 0 };

	// Return if the thread is already stopped
	ret = r_debug_ptrace (dbg, PTRACE_GETSIGINFO, tid, 0,
		(r_ptrace_data_t) (intptr_t)&siginfo);
	if (ret == 0) {
		return true;
	}

	if (linux_kill_thread (tid, SIGSTOP)) {
		if ((ret = waitpid (tid, &status, 0)) == -1) {
			perror ("waitpid");
		}
		return ret == tid;
	}
	return false;
}

bool linux_stop_threads(RDebug *dbg, int except) {
	bool ret = true;
	if (dbg->threads) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (dbg->threads, it, th) {
			if (th->pid && th->pid != except) {
				if (!linux_stop_thread (dbg, th->pid)) {
					ret = false;
				}
			}
		}
	}
	return ret;
}

static bool linux_attach_single_pid(RDebug *dbg, int ptid) {
	siginfo_t sig = { 0 };

	if (ptid < 0) {
		return false;
	}

	// Safely check if the PID has already been attached to avoid printing errors.
	// Attaching to a process that has already been started with PTRACE_TRACEME.
	// sets errno to "Operation not permitted" which may be misleading.
	// GETSIGINFO can be called multiple times and would fail without attachment.
	if (r_debug_ptrace (dbg, PTRACE_GETSIGINFO, ptid, NULL,
		(r_ptrace_data_t)&sig) == -1) {
		if (r_debug_ptrace (dbg, PTRACE_ATTACH, ptid, NULL, NULL) == -1) {
			perror ("ptrace (PT_ATTACH)");
			return false;
		}

		// Make sure SIGSTOP is delivered and wait for it since we can't affect the pid
		// until it hits SIGSTOP.
		if (!linux_stop_thread (dbg, ptid)) {
			eprintf ("Could not stop pid (%d)\n", ptid);
			return false;
		}
	}

	if (!linux_set_options (dbg, ptid)) {
		eprintf("failed set_options on %d\n", ptid);
		return false;
	}
	return true;
}

static RList *get_pid_thread_list(RDebug *dbg, int main_pid) {
	RList *list = r_list_new ();
	if (list) {
		list = linux_thread_list (dbg, main_pid, list);
		dbg->main_pid = main_pid;
	}
	return list;
}

int linux_attach(RDebug *dbg, int pid) {
	// First time we run: We try to attach to all "possible" threads and to the main pid
	if (!dbg->threads) {
		dbg->threads = get_pid_thread_list (dbg, pid);
	} else {
		// This means we did a first run, so we probably attached to all possible threads already.
		// So check if the requested thread is being traced already. If not, attach it
		if (!r_list_find (dbg->threads, &pid, &match_pid)) {
			linux_attach_single_pid (dbg, pid);
		}
	}
	return pid;
}

static char *read_link(int pid, const char *file) {
	char path[1024] = {0};
	char buf[1024] = {0};

	snprintf (path, sizeof (path), "/proc/%d/%s", pid, file);
	int ret = readlink (path, buf, sizeof (buf));
	if (ret > 0) {
		buf[sizeof (buf) - 1] = '\0';
		return strdup (buf);
	}
	return NULL;
}

RDebugInfo *linux_info(RDebug *dbg, const char *arg) {
	char proc_buff[1024];
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) {
		return NULL;
	}

	RList *th_list;
	bool list_alloc = false;
	if (dbg->threads) {
		th_list = dbg->threads;
	} else {
		th_list = r_list_new ();
		list_alloc = true;
		if (th_list) {
			th_list = linux_thread_list (dbg, dbg->pid, th_list);
		}
	}
	RDebugPid *th;
	RListIter *it;
	bool found = false;
	r_list_foreach (th_list, it, th) {
		if (th->pid == dbg->pid) {
			found = true;
			break;
		}
	}
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = found ? th->uid : -1;
	rdi->gid = found ? th->gid : -1;
	rdi->cwd = read_link (rdi->pid, "cwd");
	rdi->exe = read_link (rdi->pid, "exe");
	snprintf (proc_buff, sizeof (proc_buff), "/proc/%d/cmdline", rdi->pid);
	rdi->cmdline = r_file_slurp (proc_buff, NULL);
	snprintf (proc_buff, sizeof (proc_buff), "/proc/%d/stack", rdi->pid);
	rdi->kernel_stack = r_file_slurp (proc_buff, NULL);
	rdi->status = found ? th->status : R_DBG_PROC_STOP;
	if (list_alloc) {
		r_list_free (th_list);
	}
	return rdi;
}

RDebugPid *fill_pid_info(const char *info, const char *path, int tid) {
	RDebugPid *pid_info = R_NEW0 (RDebugPid);
	if (!pid_info) {
		return NULL;
	}
	char *ptr = strstr (info, "State:");
	if (ptr) {
		switch (*(ptr + 7)) {
		case 'R':
			pid_info->status = R_DBG_PROC_RUN;
			break;
		case 'S':
			pid_info->status = R_DBG_PROC_SLEEP;
			break;
		case 'T':
		case 't':
			pid_info->status = R_DBG_PROC_STOP;
			break;
		case 'Z':
			pid_info->status = R_DBG_PROC_ZOMBIE;
			break;
		case 'X':
			pid_info->status = R_DBG_PROC_DEAD;
			break;
		default:
			pid_info->status = R_DBG_PROC_SLEEP;
			break;
		}
	}
	ptr = strstr (info, "PPid:");
	if (ptr) {
		pid_info->ppid = atoi (ptr + 5);
	}
	ptr = strstr (info, "Uid:");
	if (ptr) {
		pid_info->uid = atoi (ptr + 5);
	}
	ptr = strstr (info, "Gid:");
	if (ptr) {
		pid_info->gid = atoi (ptr + 5);
	}

	pid_info->pid = tid;
	pid_info->path = path ? strdup (path) : NULL;
	pid_info->runnable = true;
	pid_info->pc = 0;
	return pid_info;
}

RList *linux_pid_list(int pid, RList *list) {
	list->free = (RListFree)&r_debug_pid_free;
	DIR *dh = NULL;
	struct dirent *de = NULL;
	char path[PATH_MAX], info[PATH_MAX];
	int i = -1;
	RDebugPid *pid_info = NULL;
	dh = opendir ("/proc");
	if (!dh) {
		r_sys_perror ("opendir /proc");
		r_list_free (list);
		return NULL;
	}
	while ((de = readdir (dh))) {
		path[0] = 0;
		info[0] = 0;
		// For each existing pid file
		if ((i = atoi (de->d_name)) <= 0) {
			continue;
		}

		procfs_pid_slurp (i, "cmdline", path, sizeof (path));
		if (!procfs_pid_slurp (i, "status", info, sizeof (info))) {
			// Get information about pid (status, pc, etc.)
			pid_info = fill_pid_info (info, path, i);
		} else {
			pid_info = r_debug_pid_new (path, i, 0, R_DBG_PROC_STOP, 0);
		}
		// Unless pid 0 is requested, only add the requested pid and it's child processes
		if (0 == pid || i == pid || pid_info->ppid == pid) {
			r_list_append (list, pid_info);
		}
	}
	closedir (dh);
	return list;
}

RList *linux_thread_list(RDebug *dbg, int pid, RList *list) {
	int i = 0, thid = 0;
	char *ptr, buf[PATH_MAX];
	RDebugPid *pid_info = NULL;
	ut64 pc = 0;
	int prev_tid = dbg->tid;

	if (!pid) {
		r_list_free (list);
		return NULL;
	}

	list->free = (RListFree)&r_debug_pid_free;
	/* if this process has a task directory, use that */
	snprintf (buf, sizeof (buf), "/proc/%d/task", pid);
	if (r_file_is_directory (buf)) {
		struct dirent *de;
		DIR *dh = opendir (buf);
		// Update the process' memory maps to set correct paths
		dbg->corebind.syncDebugMaps (dbg->corebind.core);
		while ((de = readdir (dh))) {
			if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) {
				continue;
			}
			int tid = atoi (de->d_name);
			char info[PATH_MAX];
			int uid = 0;
			if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
				ptr = strstr (info, "Uid:");
				if (ptr) {
					uid = atoi (ptr + 4);
				}
				ptr = strstr (info, "Tgid:");
				if (ptr) {
					int tgid = atoi (ptr + 5);
					if (tgid != pid) {
						/* Ignore threads that aren't in the pid's thread group */
						continue;
					}
				}
			}

			// Switch to the currently inspected thread to get it's program counter
			if (dbg->tid != tid) {
				linux_attach_single_pid (dbg, tid);
				dbg->tid = tid;
			}

			r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
			pc = r_debug_reg_get (dbg, "PC");

			if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
				// Get information about pid (status, pc, etc.)
				pid_info = fill_pid_info (info, NULL, tid);
				pid_info->pc = pc;
			} else {
				pid_info = r_debug_pid_new (NULL, tid, uid, 's', pc);
			}
			r_list_append (list, pid_info);
			dbg->n_threads++;
		}
		closedir (dh);
		// Return to the original thread
		linux_attach_single_pid (dbg, prev_tid);
		dbg->tid = prev_tid;
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
	} else {
		/* Some linux configurations might hide threads from /proc, use this workaround instead */
#undef MAXPID
#define MAXPID 99999
		/* otherwise, brute force the pids */
		for (i = pid; i < MAXPID; i++) { // XXX
			if (procfs_pid_slurp (i, "status", buf, sizeof(buf)) == -1) {
				continue;
			}
			int uid = 0;
			/* look for a thread group id */
			ptr = strstr (buf, "Uid:");
			if (ptr) {
				uid = atoi (ptr + 4);
			}
			ptr = strstr (buf, "Tgid:");
			if (ptr) {
				int tgid = atoi (ptr + 5);

				/* if it is not in our thread group, we don't want it */
				if (tgid != pid) {
					continue;
				}

				if (procfs_pid_slurp (i, "comm", buf, sizeof(buf)) == -1) {
					/* fall back to auto-id */
					snprintf (buf, sizeof(buf), "thread_%d", thid++);
				}
				r_list_append (list, r_debug_pid_new (buf, i, uid, 's', 0));
			}
		}
	}
	return list;
}

#define PRINT_FPU(fpregs) \
	r_cons_printf ("cwd = 0x%04x  ; control   ", (fpregs).cwd);\
	r_cons_printf ("swd = 0x%04x  ; status\n", (fpregs).swd);\
	r_cons_printf ("ftw = 0x%04x              ", (fpregs).ftw);\
	r_cons_printf ("fop = 0x%04x\n", (fpregs).fop);\
	r_cons_printf ("rip = 0x%016"PFMT64x"  ", (ut64)(fpregs).rip);\
	r_cons_printf ("rdp = 0x%016"PFMT64x"\n", (ut64)(fpregs).rdp);\
	r_cons_printf ("mxcsr = 0x%08x        ", (fpregs).mxcsr);\
	r_cons_printf ("mxcr_mask = 0x%08x\n", (fpregs).mxcr_mask)\

#define PRINT_FPU_NOXMM(fpregs) \
	r_cons_printf ("cwd = 0x%04lx  ; control   ", (fpregs).cwd);\
	r_cons_printf ("swd = 0x%04lx  ; status\n", (fpregs).swd);\
	r_cons_printf ("twd = 0x%04lx              ", (fpregs).twd);\
	r_cons_printf ("fip = 0x%04lx          \n", (fpregs).fip);\
	r_cons_printf ("fcs = 0x%04lx              ", (fpregs).fcs);\
	r_cons_printf ("foo = 0x%04lx          \n", (fpregs).foo);\
	r_cons_printf ("fos = 0x%04lx              ", (fpregs).fos)

static void print_fpu(void *f){
#if __x86_64__
	int i,j;
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
#if __ANDROID__
	PRINT_FPU (fpregs);
	for (i = 0;i < 8; i++) {
		ut64 *b = (ut64 *)&fpregs.st_space[i*4];
		ut32 *c = (ut32*)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		r_cons_printf ("st%d =%0.3lg (0x%016"PFMT64x") | %0.3f (%08x) | "\
			"%0.3f (%08x) \n", i,
			(double)*((double*)&fpregs.st_space[i*4]), *b, (float) f[0],
			c[0], (float) f[1], c[1]);
	}
#else
	r_cons_printf ("---- x86-64 ----\n");
	PRINT_FPU (fpregs);
	r_cons_printf ("size = 0x%08x\n", (ut32)sizeof (fpregs));
	for (i = 0; i < 16; i++) {
		ut32 *a = (ut32 *)&fpregs.xmm_space;
		a = a + (i * 4);
		r_cons_printf ("xmm%d = %08x %08x %08x %08x   ", i, (int)a[0], (int)a[1],
					   (int)a[2], (int)a[3] );
		if (i < 8) {
			ut64 *st_u64 = (ut64*)&fpregs.st_space[i * 4];
			ut8 *st_u8 = (ut8 *)&fpregs.st_space[i * 4];
			long double *st_ld = (long double *)&fpregs.st_space[i * 4];
			r_cons_printf ("mm%d = 0x%016" PFMT64x " | st%d = ", i, *st_u64, i);
			// print as hex TBYTE - always little endian
			for (j = 9; j >= 0; j--) {
				r_cons_printf ("%02x", st_u8[j]);
			}
			// Using %Lf and %Le even though we do not show the extra precision to avoid another cast
			// %f with (double)*st_ld would also work
			r_cons_printf (" %Le %Lf\n", *st_ld, *st_ld);
		} else {
			r_cons_printf ("\n");
		}
	}
#endif // __ANDROID__
#elif __i386__
	int i;
#if __ANDROID__
	struct user_fpxregs_struct fpxregs = *(struct user_fpxregs_struct*)f;
	r_cons_printf ("---- x86-32 ----\n");
	r_cons_printf ("cwd = 0x%04x  ; control   ", fpxregs.cwd);
	r_cons_printf ("swd = 0x%04x  ; status\n", fpxregs.swd);
	r_cons_printf ("twd = 0x%04x ", fpxregs.twd);
	r_cons_printf ("fop = 0x%04x\n", fpxregs.fop);
	r_cons_printf ("fip = 0x%08x\n", (ut32)fpxregs.fip);
	r_cons_printf ("fcs = 0x%08x\n", (ut32)fpxregs.fcs);
	r_cons_printf ("foo = 0x%08x\n", (ut32)fpxregs.foo);
	r_cons_printf ("fos = 0x%08x\n", (ut32)fpxregs.fos);
	r_cons_printf ("mxcsr = 0x%08x\n", (ut32)fpxregs.mxcsr);
	for(i = 0; i < 8; i++) {
		ut32 *a = (ut32*)(&fpxregs.xmm_space);
		ut64 *b = (ut64 *)(&fpxregs.st_space[i * 4]);
		ut32 *c = (ut32*)&fpxregs.st_space;
		float *f = (float *)&fpxregs.st_space;
		a = a + (i * 4);
		c = c + (i * 4);
		f = f + (i * 4);
		r_cons_printf ("xmm%d = %08x %08x %08x %08x   ", i, (int)a[0],
			(int)a[1], (int)a[2], (int)a[3] );
		r_cons_printf ("st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x) | "\
			"%0.3f (0x%08x)\n", i,
			(double)*((double*)(&fpxregs.st_space[i*4])), b[0],
			f[0], c[0], f[1], c[1]);
	}
#else
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
	r_cons_printf ("---- x86-32-noxmm ----\n");
	PRINT_FPU_NOXMM (fpregs);
	for(i = 0; i < 8; i++) {
		ut64 *b = (ut64 *)(&fpregs.st_space[i*4]);
		double *d = (double*)b;
		ut32 *c = (ut32*)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		r_cons_printf ("st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x) | "\
			"%0.3f (0x%08x)\n", i, d[0], b[0], f[0], c[0], f[1], c[1]);
	}
#endif
#else
#warning print_fpu not implemented for this platform
#endif
}

int linux_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	bool showfpu = false;
	int pid = dbg->tid;
	int ret = 0;
	if (type < -1) {
		showfpu = true;
		type = -type;
	}
	switch (type) {
	case R_REG_TYPE_DRX:
#if __POWERPC__
		// no drx for powerpc
		return false;
#elif __i386__ || __x86_64__
#if !__ANDROID__
	{
		int i;
		for (i = 0; i < 8; i++) { //DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			long ret = r_debug_ptrace (dbg, PTRACE_PEEKUSER, pid,
					(void *)r_offsetof (struct user, u_debugreg[i]), 0);
			if ((i+1) * sizeof (ret) > size) {
				eprintf ("linux_reg_get: Buffer too small %d\n", size);
				break;
			}
			memcpy (buf + (i * sizeof (ret)), &ret, sizeof (ret));
		}
		struct user a;
		return sizeof (a.u_debugreg);
	}
#else
	#warning Android X86 does not support DRX
#endif
#endif
		return true;
		break;
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_MMX:
	case R_REG_TYPE_XMM:
#if __POWERPC__
		return false;
#elif __x86_64__ || __i386__
		{
		struct user_fpregs_struct fpregs;
		if (type == R_REG_TYPE_FPU) {
#if __x86_64__
			ret = r_debug_ptrace (dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (ret != 0) {
				r_sys_perror ("PTRACE_GETFPREGS");
				return false;
			}
			if (showfpu) {
				print_fpu ((void *)&fpregs);
			}
			size = R_MIN (sizeof (fpregs), size);
			memcpy (buf, &fpregs, size);
			return size;
#elif __i386__
#if !__ANDROID__
			struct user_fpxregs_struct fpxregs;
			ret = r_debug_ptrace (dbg, PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
			if (ret == 0) {
				if (showfpu) {
					print_fpu ((void *)&fpxregs);
				}
				size = R_MIN (sizeof (fpxregs), size);
				memcpy (buf, &fpxregs, size);
				return size;
			} else {
				ret = r_debug_ptrace (dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
				if (showfpu) {
					print_fpu ((void *)&fpregs);
				}
				if (ret != 0) {
					r_sys_perror ("PTRACE_GETFPREGS");
					return false;
				}
				size = R_MIN (sizeof (fpregs), size);
				memcpy (buf, &fpregs, size);
				return size;
			}
#else
			ret = r_debug_ptrace (dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (showfpu) {
				print_fpu ((void *)&fpregs);
			}
			if (ret != 0) {
				r_sys_perror ("PTRACE_GETFPREGS");
				return false;
			}
			size = R_MIN (sizeof (fpregs), size);
			memcpy (buf, &fpregs, size);
			return size;
#endif // !__ANDROID__
#endif // __i386__
		}
		}
#else
	#warning getfpregs not implemented for this platform
#endif
		break;
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		{
			R_DEBUG_REG_T regs;
			memset (&regs, 0, sizeof (regs));
			memset (buf, 0, size);
#if (__arm64__ || __aarch64__ || __s390x__) && defined(PTRACE_GETREGSET)
			struct iovec io = {
				.iov_base = &regs,
				.iov_len = sizeof (regs)
			};
			ret = r_debug_ptrace (dbg, PTRACE_GETREGSET, pid, 1, &io);
			// ret = ptrace (PTRACE_GETREGSET, pid, (void*)(size_t)(NT_PRSTATUS), NULL); // &io);
#elif __BSD__ && (__POWERPC__ || __sparc__)
			ret = r_debug_ptrace (dbg, PTRACE_GETREGS, pid, &regs, NULL);
#else
			/* linux -{arm/mips/riscv/x86/x86_64} */
			ret = r_debug_ptrace (dbg, PTRACE_GETREGS, pid, NULL, &regs);
#endif
			/*
			 * if perror here says 'no such process' and the
			 * process exists still.. is because there's a missing call
			 * to 'wait'. and the process is not yet available to accept
			 * more ptrace queries.
			 */
			if (ret != 0) {
				r_sys_perror ("PTRACE_GETREGS");
				return false;
			}
			size = R_MIN (sizeof (regs), size);
			memcpy (buf, &regs, size);
			return size;
		}
		break;
	case R_REG_TYPE_YMM:
		{
#if HAVE_YMM && __x86_64__ && defined(PTRACE_GETREGSET)
		ut32 ymm_space[128];	// full ymm registers
		struct _xstate xstate;
		struct iovec iov = {};
		iov.iov_base = &xstate;
		iov.iov_len = sizeof(struct _xstate);
		ret = r_debug_ptrace (dbg, PTRACE_GETREGSET, pid, (void*)NT_X86_XSTATE, &iov);
		if (errno == ENODEV) {
			// ignore ENODEV, it just means this CPU or kernel doesn't support XSTATE
			ret = 0;
		} else if (ret != 0) {
			r_sys_perror ("PTRACE_GETREGSET");
			return false;
		}
		// stitch together xstate.fpstate._xmm and xstate.ymmh assuming LE
		int ri,rj;
		for (ri = 0; ri < 16; ri++)	{
			for (rj=0; rj < 4; rj++)	{
#ifdef __ANDROID__
				ymm_space[ri*8+rj] = ((struct _libc_fpstate*) &xstate.fpstate)->_xmm[ri].element[rj];
#else
				ymm_space[ri*8+rj] = xstate.fpstate._xmm[ri].element[rj];
#endif
			}
			for (rj = 0; rj < 4; rj++)	{
				ymm_space[ri * 8 + (rj + 4)] = xstate.ymmh.ymmh_space[ri * 4 + rj];
			}
		}
		size = R_MIN (sizeof (ymm_space), size);
		memcpy (buf, &ymm_space, size);
		return size;
#endif
		return false;
		}
		break;
	}
	return false;
}

int linux_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	int pid = dbg->tid;

	if (type == R_REG_TYPE_DRX) {
#if !__ANDROID__ && (__i386__ || __x86_64__)
		int i;
		long *val = (long*)buf;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			if (r_debug_ptrace (dbg, PTRACE_POKEUSER, pid,
					(void *)r_offsetof (struct user, u_debugreg[i]), (r_ptrace_data_t)val[i])) {
				eprintf ("ptrace error for dr %d\n", i);
				r_sys_perror ("ptrace POKEUSER");
			}
		}
		return sizeof (R_DEBUG_REG_T);
#else
		return false;
#endif
	}
	if (type == R_REG_TYPE_GPR) {
#if __arm64__ || __aarch64__ || __s390x__
		struct iovec io = {
			.iov_base = (void*)buf,
			.iov_len = sizeof (R_DEBUG_REG_T)
		};
		int ret = r_debug_ptrace (dbg, PTRACE_SETREGSET, pid, (void*)(size_t)NT_PRSTATUS, (r_ptrace_data_t)(size_t)&io);
#elif __POWERPC__ || __sparc__
		int ret = r_debug_ptrace (dbg, PTRACE_SETREGS, pid, buf, NULL);
#else
		int ret = r_debug_ptrace (dbg, PTRACE_SETREGS, pid, 0, (void*)buf);
#endif
#if DEAD_CODE
		if (size > sizeof (R_DEBUG_REG_T)) {
			size = sizeof (R_DEBUG_REG_T);
		}
#endif
		if (ret == -1) {
			r_sys_perror ("reg_write");
			return false;
		}
		return true;
	}
	if (type == R_REG_TYPE_FPU) {
#if __i386__ || __x86_64__
		int ret = r_debug_ptrace (dbg, PTRACE_SETFPREGS, pid, 0, (void*)buf);
		return (ret != 0) ? false : true;
#endif
	}
	return false;
}

RList *linux_desc_list (int pid) {
	RList *ret = NULL;
	char path[512], file[512], buf[512];
	struct dirent *de;
	RDebugDesc *desc;
	int type, perm;
	int len, len2;
	struct stat st;
	DIR *dd = NULL;

	snprintf (path, sizeof (path), "/proc/%i/fd/", pid);
	if (!(dd = opendir (path))) {
		r_sys_perror ("opendir /proc/x/fd");
		return NULL;
	}
	ret = r_list_new ();
	if (!ret) {
		closedir (dd);
		return NULL;
	}
	ret->free = (RListFree)r_debug_desc_free;
	while ((de = (struct dirent *)readdir(dd))) {
		if (de->d_name[0] == '.') {
			continue;
		}
		len = strlen (path);
		len2 = strlen (de->d_name);
		if (len + len2 + 1 >= sizeof(file)) {
			r_list_free (ret);
			closedir (dd);
			eprintf ("Filename is too long");
			return NULL;
		}
		memcpy (file, path, len);
		memcpy (file + len, de->d_name, len2 + 1);
		buf[0] = 0;
		if (readlink (file, buf, sizeof (buf) - 1) == -1) {
			return NULL;
		}
		buf[sizeof (buf) - 1] = 0;
		type = perm = 0;
		if (stat (file, &st) != -1) {
			type  = st.st_mode & S_IFIFO  ? 'P':
#ifdef S_IFSOCK
				st.st_mode & S_IFSOCK ? 'S':
#endif
				st.st_mode & S_IFCHR  ? 'C':'-';
		}
		if (lstat(path, &st) != -1) {
			if (st.st_mode & S_IRUSR) {
				perm |= R_PERM_R;
			}
			if (st.st_mode & S_IWUSR) {
				perm |= R_PERM_W;
			}
		}
		//TODO: Offset
		desc = r_debug_desc_new (atoi (de->d_name), buf, perm, type, 0);
		if (!desc) {
			break;
		}
		r_list_append (ret, desc);
	}
	closedir (dd);
	return ret;
}

#endif
