/*! \file */
#ifndef LIBGDBR_H
#define LIBGDBR_H

#include <stdint.h>
#ifdef _MSC_VER
typedef unsigned int ssize_t;
#else
#include <unistd.h>
#endif

#include "arch.h"
#include "r_types_base.h"
#include "r_socket.h"

#define X86_64 ARCH_X86_64
#define X86_32 ARCH_X86_32
#define ARM_32 ARCH_ARM_32
#define ARM_64 ARCH_ARM_64
#define MIPS ARCH_MIPS
#define AVR ARCH_AVR
#define LM32 ARCH_LM32

#define MSG_OK 0
#define MSG_NOT_SUPPORTED -1
#define MSG_ERROR_1 -2

/*!
 * Structure that saves a gdb message
 */
typedef struct libgdbr_message_t {
	ssize_t len; /*! Len of the message */
	char *msg;      /*! Pointer to the buffer that contains the message */
	uint8_t chk;    /*! Cheksum of the current message read from the packet */
} libgdbr_message_t;

/*!
 * Structure that stores features supported
 */

typedef struct libgdbr_stub_features_t {
	ut32 pkt_sz; /* Max packet size */
	bool qXfer_btrace_read;
	bool qXfer_btrace_conf_read;
	bool qXfer_spu_read;
	bool qXfer_spu_write;
	bool qXfer_libraries_read;
	bool qXfer_libraries_svr4_read;
	bool qXfer_siginfo_read;
	bool qXfer_siginfo_write;
	bool qXfer_auxv_read;
	bool qXfer_exec_file_read;
	bool qXfer_features_read;
	bool qXfer_memory_map_read;
	bool qXfer_sdata_read;
	bool qXfer_threads_read;
	bool qXfer_traceframe_info_read;
	bool qXfer_uib_read;
	bool qXfer_fdpic_read;
	bool qXfer_osdata_read;
	bool Qbtrace_off;
	bool Qbtrace_bts;
	bool Qbtrace_pt;
	bool Qbtrace_conf_bts_size;
	bool Qbtrace_conf_pt_size;
	bool QNonStop;
	bool QCatchSyscalls;
	bool QPassSignals;
	bool QStartNoAckMode;
	bool QAgent;
	bool QAllow;
	bool QDisableRandomization;
	bool QTBuffer_size;
	bool QThreadEvents;
	bool StaticTracepoint;
	bool InstallInTrace;
	bool ConditionalBreakpoints;
	bool ConditionalTracepoints;
	bool ReverseContinue;
	bool ReverseStep;
	bool swbreak;
	bool hwbreak;
	bool fork_events;
	bool vfork__events;
	bool exec_events;
	bool vContSupported;
	bool no_resumed;
	bool augmented_libraries_svr4_read;
	bool multiprocess;
	bool TracepointSource;
	bool EnableDisableTracepoints;
	bool tracenz;
	bool BreakpointCommands;
} libgdbr_stub_features_t;

/*!
 * Structure for fstat data sent by gdb remote server
 */

typedef struct libgdbr_fstat_t {
	unsigned dev;
	unsigned ino;
	unsigned mode;
	unsigned numlinks;
	unsigned uid;
	unsigned gid;
	unsigned rdev;
	uint64_t size;
	uint64_t blksize;
	uint64_t blocks;
	unsigned atime;
	unsigned mtime;
	unsigned ctime;
} __attribute__((packed)) libgdbr_fstat_t;

/*!
 * Core "object" that saves
 * the instance of the lib
 */
typedef struct libgdbr_t {
	char *send_buff; // defines a buffer for reading and sending stuff
	ssize_t send_len;
	ssize_t send_max; // defines the maximal len for the given buffer
	char *read_buff;
	ssize_t read_max; // defines the maximal len for the given buffer

	// is already handled (i.e. already send or ...)
	RSocket *sock;
	int connected;
	int acks;
	char *data;
	ssize_t data_len;
	ssize_t data_max;
	uint8_t architecture;
	registers_t *registers;
	int last_code;
	ssize_t pid; // little endian
	ssize_t tid; // little endian
	bool attached; // Remote server attached to process or created
	libgdbr_stub_features_t stub_features;
	char *exec_file_name;
	int exec_fd;
	uint64_t exec_file_sz;
} libgdbr_t;

/*!
 * \brief Function initializes the libgdbr lib
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_init(libgdbr_t *g);

/*!
 * \brief Function initializes the architecture of the gdbsession
 * \param architecture defines the architecure used (registersize, and such)
 * \returns a failure code
 */
int gdbr_set_architecture(libgdbr_t *g, uint8_t architecture);

/*!
 * \brief frees all buffers and cleans the libgdbr instance stuff
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_cleanup(libgdbr_t *g);

#endif
