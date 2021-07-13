/* radare2 - LGPL - Copyright 2017-2021 - condret, pancake */

#ifndef R2_IO_H
#define R2_IO_H

#include "r_list.h"
#include <r_util.h>
#include "r_socket.h"
#include "r_vector.h"
#include "r_skyline.h"

#define R_IO_SEEK_SET	0
#define R_IO_SEEK_CUR	1
#define R_IO_SEEK_END	2

#define R_IO_UNDOS 64

#define r_io_map_begin(map) r_itv_begin (map->itv)
#define r_io_map_to(map) ( r_itv_end (map->itv) - 1 )
#define r_io_map_end(map) r_itv_end (map->itv)
#define r_io_map_size(map) r_itv_size (map->itv)
#define r_io_map_contain(map, addr) r_itv_contain (map->itv, addr)

#define r_io_map_set_begin(map, new_addr)	\
	do {					\
		map->itv.addr = new_addr;	\
	} while (0)
#define r_io_map_set_size(map, new_size)	\
	do {					\
		map->itv.size = new_size;	\
	} while (0)

#if HAVE_PTRACE

#if __sun
#include <sys/types.h>
#else
#if DEBUGGER && HAVE_PTRACE
#include <sys/ptrace.h>
#endif
#endif

#if (defined(__GLIBC__) && defined(__linux__))
typedef enum __ptrace_request r_ptrace_request_t;
typedef void * r_ptrace_data_t;
#define R_PTRACE_NODATA NULL
#else
#if __ANDROID__
typedef int r_ptrace_request_t;
typedef void * r_ptrace_data_t;
#define R_PTRACE_NODATA NULL
#elif __APPLE__
typedef int r_ptrace_request_t;
typedef int r_ptrace_data_t;
#elif __OpenBSD__
typedef int r_ptrace_request_t;
typedef int r_ptrace_data_t;
#define R_PTRACE_NODATA 0
#else
typedef int r_ptrace_request_t;
typedef void *r_ptrace_data_t;
#define R_PTRACE_NODATA 0
#endif
#endif
#endif

#if __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_io);

typedef struct r_io_undos_t {
	ut64 off;
	int cursor;
} RIOUndos;

typedef struct r_io_undo_t {
	int s_enable;
	int w_enable;
	/* write stuff */
	RList *w_list;
	int w_init;
	/* seek stuff */
	int idx;
	int undos; /* available undos */
	int redos; /* available redos */
	RIOUndos seek[R_IO_UNDOS];
	/*int fd[R_IO_UNDOS]; // XXX: Must be RIODesc* */
} RIOUndo;


typedef struct r_io_bank_t {
	RList *map_refs;
	char *name;
	ut32 id;
} RIOBank;

typedef struct r_io_undo_w_t {
	bool set;
	ut64 off;
	ut8 *o;   /* old data */
	ut8 *n;   /* new data */
	size_t len;  /* length */
} RIOUndoWrite;

typedef struct r_io_t {
	struct r_io_desc_t *desc; // XXX deprecate... we should use only the fd integer, not hold a weak pointer
	ut64 off;
	int bits;
	int va;	// keep it as int, value can be 0, 1 or 2
	bool ff;
	ut8 Oxff; // which printable char to use instead of 0xff for unallocated bytes
	size_t addrbytes;
	bool aslr;
	bool autofd;
	ut32 cached; // uses R_PERM_RWX
	bool cachemode; // write in cache all the read operations (EXPERIMENTAL)
	ut32 p_cache; // uses 1, 2, 4.. probably R_PERM_RWX :D
	ut32 curbank;	// id of current bank
	RIDPool *map_ids;
	RPVector maps; //from tail backwards maps with higher priority are found
	RSkyline map_skyline; // map parts that are not covered by others
	RIDStorage *files;
	RCache *buffer;
	RPVector cache;
	RSkyline cache_skyline;
	ut8 *write_mask;
	int write_mask_len;
	ut64 mask;
	RIOUndo undo;
	SdbList *plugins;
	bool nodup;
	char *runprofile;
	char *envprofile;
	char *args;
	REvent *event;
	PrintfCallback cb_printf;
	RCoreBind corebind;
	RIDStorage *banks;
	// RIOBanks *banks;
	bool want_ptrace_wrap;
#if __WINDOWS__
	struct w32dbg_wrap_instance_t *w32dbg_wrap;
#endif
#if USE_PTRACE_WRAP
	struct ptrace_wrap_instance_t *ptrace_wrap;
#endif
} RIO;

typedef struct r_io_desc_t {
	int fd;
	int perm;
	char *uri;
	char *name;
	char *referer;
	HtUP/*<ut64, RIODescCache *>*/ *cache;
	void *data;
	struct r_io_plugin_t *plugin;
	RIO *io;
} RIODesc;

// Move somewhere else?
typedef struct {
	RSocket *fd;
	RSocket *client;
	bool listener;
} RIORap;

typedef struct r_io_plugin_t {
	const char *name;
	const char *desc;
	const char *version;
	const char *author;
	const char *license;
	void *widget;
	const char *uris;
	int (*listener)(RIODesc *io);
	int (*init)(void);
	RIOUndo undo;
	bool isdbg;
	// int (*is_file_opened)(RIO *io, RIODesc *fd, const char *);
	char *(*system)(RIO *io, RIODesc *fd, const char *);
	RIODesc* (*open)(RIO *io, const char *, int perm, int mode);
	RList* /*RIODesc* */ (*open_many)(RIO *io, const char *, int perm, int mode);
	int (*read)(RIO *io, RIODesc *fd, ut8 *buf, int count);
	ut64 (*seek)(RIO *io, RIODesc *fd, ut64 offset, int whence);
	int (*write)(RIO *io, RIODesc *fd, const ut8 *buf, int count);
	int (*close)(RIODesc *desc);
	bool (*is_blockdevice)(RIODesc *desc);
	bool (*is_chardevice)(RIODesc *desc);
	int (*getpid)(RIODesc *desc);
	int (*gettid)(RIODesc *desc);
	bool (*getbase)(RIODesc *desc, ut64 *base);
	bool (*resize)(RIO *io, RIODesc *fd, ut64 size);
	int (*extend)(RIO *io, RIODesc *fd, ut64 size);
	bool (*accept)(RIO *io, RIODesc *desc, int fd);
	int (*create)(RIO *io, const char *file, int mode, int type);
	bool (*check)(RIO *io, const char *, bool many);
} RIOPlugin;

typedef struct r_io_map_t {
	int fd;
	int perm;
	ut32 id;
	ut64 ts;
	RInterval itv;
	ut64 delta; // paddr = vaddr - itv.addr + delta
	char *name;
} RIOMap;

typedef struct r_io_cache_t {
	RInterval itv;
	ut8 *data;
	ut8 *odata;
	int written;
} RIOCache;

#define R_IO_DESC_CACHE_SIZE (sizeof(ut64) * 8)
typedef struct r_io_desc_cache_t {
	ut64 cached;
	ut8 cdata[R_IO_DESC_CACHE_SIZE];
} RIODescCache;

struct r_io_bind_t;

typedef bool (*RIODescUse)(RIO *io, int fd);
typedef RIODesc *(*RIODescGet)(RIO *io, int fd);
typedef ut64(*RIODescSize)(RIODesc *desc);
typedef RIODesc *(*RIOOpen)(RIO *io, const char *uri, int flags, int mode);
typedef RIODesc *(*RIOOpenAt)(RIO *io, const  char *uri, int flags, int mode, ut64 at);
typedef bool (*RIOClose)(RIO *io, int fd);
typedef bool (*RIOReadAt)(RIO *io, ut64 addr, ut8 *buf, int len);
typedef bool (*RIOWriteAt)(RIO *io, ut64 addr, const ut8 *buf, int len);
typedef char *(*RIOSystem)(RIO *io, const char* cmd);
typedef int (*RIOFdOpen)(RIO *io, const char *uri, int flags, int mode);
typedef bool (*RIOFdClose)(RIO *io, int fd);
typedef ut64 (*RIOFdSeek)(RIO *io, int fd, ut64 addr, int whence);
typedef ut64 (*RIOFdSize)(RIO *io, int fd);
typedef bool (*RIOFdResize)(RIO *io, int fd, ut64 newsize);
typedef ut64 (*RIOP2V)(RIO *io, ut64 pa);
typedef ut64 (*RIOV2P)(RIO *io, ut64 va);
typedef int (*RIOFdRead)(RIO *io, int fd, ut8 *buf, int len);
typedef int (*RIOFdWrite)(RIO *io, int fd, const ut8 *buf, int len);
typedef int (*RIOFdReadAt)(RIO *io, int fd, ut64 addr, ut8 *buf, int len);
typedef int (*RIOFdWriteAt)(RIO *io, int fd, ut64 addr, const ut8 *buf, int len);
typedef bool (*RIOFdIsDbg)(RIO *io, int fd);
typedef const char *(*RIOFdGetName)(RIO *io, int fd);
typedef RList *(*RIOFdGetMap)(RIO *io, int fd);
typedef bool (*RIOFdRemap)(RIO *io, int fd, ut64 addr);
typedef bool (*RIOIsValidOff)(RIO *io, ut64 addr, int hasperm);
typedef RIOMap *(*RIOMapGet)(RIO *io, ut64 addr);
typedef RIOMap *(*RIOMapGetPaddr)(RIO *io, ut64 paddr);
typedef bool (*RIOAddrIsMapped)(RIO *io, ut64 addr);
typedef RIOMap *(*RIOMapAdd)(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
#if HAVE_PTRACE
typedef long (*RIOPtraceFn)(RIO *io, r_ptrace_request_t request, pid_t pid, void *addr, r_ptrace_data_t data);
typedef void *(*RIOPtraceFuncFn)(RIO *io, void *(*func)(void *), void *user);
#endif

typedef struct r_io_bind_t {
	int init;
	RIO *io;
	RIODescUse desc_use;
	RIODescGet desc_get;
	RIODescSize desc_size;
	RIOOpen open;
	RIOOpenAt open_at;
	RIOClose close;
	RIOReadAt read_at;
	RIOWriteAt write_at;
	RIOSystem system;
	RIOFdOpen fd_open;
	RIOFdClose fd_close;
	RIOFdSeek fd_seek;	//needed for esil
	RIOFdSize fd_size;
	RIOFdResize fd_resize;
	RIOFdRead fd_read;	//needed for esil
	RIOFdWrite fd_write;	//needed for esil
	RIOFdReadAt fd_read_at;
	RIOFdWriteAt fd_write_at;
	RIOFdIsDbg fd_is_dbg;
	RIOFdGetName fd_get_name;
	RIOFdGetMap fd_get_map;
	RIOFdRemap fd_remap;
	RIOIsValidOff is_valid_offset;
	RIOAddrIsMapped addr_is_mapped;
	RIOMapGet map_get_at;
	RIOMapGetPaddr map_get_paddr;
	RIOMapAdd map_add;
	RIOV2P v2p;
	RIOP2V p2v;
#if HAVE_PTRACE
	RIOPtraceFn ptrace;
	RIOPtraceFuncFn ptrace_func;
#endif
} RIOBind;

//map.c
R_API RIOMap *r_io_map_new(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
R_API void r_io_map_init(RIO *io);
R_API bool r_io_map_remap(RIO *io, ut32 id, ut64 addr);
R_API bool r_io_map_remap_fd(RIO *io, int fd, ut64 addr);
R_API ut64 r_io_map_location(RIO *io, ut64 size);
R_API bool r_io_map_exists(RIO *io, RIOMap *map);
R_API bool r_io_map_exists_for_id(RIO *io, ut32 id);
R_API RIOMap *r_io_map_get(RIO *io, ut32 id);
R_API RIOMap *r_io_map_add(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
// same as r_io_map_add but used when many maps need to be added. Call r_io_update when all maps have been added.
R_API RIOMap *r_io_map_add_batch(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
R_API RIOMap *r_io_map_get_at(RIO *io, ut64 addr);		//returns the map at vaddr with the highest priority
// update the internal state of RIO after a series of _batch operations
R_API void r_io_update(RIO *io);
R_API bool r_io_map_is_mapped(RIO* io, ut64 addr);
R_API RIOMap *r_io_map_get_paddr(RIO *io, ut64 paddr);		//returns the map at paddr with the highest priority
R_API void r_io_map_reset(RIO* io);
R_API bool r_io_map_del(RIO *io, ut32 id);
R_API bool r_io_map_del_for_fd(RIO *io, int fd);
R_API bool r_io_map_depriorize(RIO* io, ut32 id);
R_API bool r_io_map_priorize(RIO *io, ut32 id);
R_API bool r_io_map_priorize_for_fd(RIO *io, int fd);
R_API void r_io_map_cleanup(RIO *io);
R_API void r_io_map_fini(RIO *io);
R_API bool r_io_map_is_in_range(RIOMap *map, ut64 from, ut64 to);
R_API void r_io_map_set_name(RIOMap *map, const char *name);
R_API void r_io_map_del_name(RIOMap *map);
R_API RList* r_io_map_get_by_fd(RIO *io, int fd);
R_API bool r_io_map_resize(RIO *io, ut32 id, ut64 newsize);

// next free address to place a map.. maybe just unify
R_API ut64 r_io_map_next_available(RIO* io, ut64 addr, ut64 size, ut64 load_align);
R_API ut64 r_io_map_next_address(RIO* io, ut64 addr);

// p2v/v2p

R_API ut64 r_io_p2v(RIO *io, ut64 pa);
R_API ut64 r_io_v2p(RIO *io, ut64 va);

//io.c
R_API RIO *r_io_new(void);
R_API RIO *r_io_init(RIO *io);
R_API RIODesc *r_io_open_nomap(RIO *io, const char *uri, int flags, int mode);		//should return int
R_API RIODesc *r_io_open(RIO *io, const char *uri, int flags, int mode);
R_API RIODesc *r_io_open_at(RIO *io, const char *uri, int flags, int mode, ut64 at);
R_API RList *r_io_open_many(RIO *io, const char *uri, int flags, int mode);
R_API RIODesc* r_io_open_buffer(RIO *io, RBuffer *b, int flags, int mode);
R_API bool r_io_close(RIO *io);
R_API bool r_io_reopen(RIO *io, int fd, int flags, int mode);
R_API int r_io_close_all(RIO *io);
R_API int r_io_pread_at(RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_pwrite_at(RIO *io, ut64 paddr, const ut8 *buf, int len);
R_API bool r_io_vread_at_mapped(RIO* io, ut64 vaddr, ut8* buf, int len);
R_API bool r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len);
R_API bool r_io_read_at_mapped(RIO *io, ut64 addr, ut8 *buf, int len);
R_API int r_io_nread_at(RIO *io, ut64 addr, ut8 *buf, int len);
R_API void r_io_alprint(RList *ls);
R_API bool r_io_write_at(RIO *io, ut64 addr, const ut8 *buf, int len);
R_API bool r_io_read(RIO *io, ut8 *buf, int len);
R_API bool r_io_write(RIO *io, ut8 *buf, int len);
R_API ut64 r_io_size(RIO *io);
R_API bool r_io_is_listener(RIO *io);
R_API char *r_io_system(RIO *io, const char* cmd);
R_API bool r_io_resize(RIO *io, ut64 newsize);
R_API int r_io_extend_at(RIO *io, ut64 addr, ut64 size);
R_API bool r_io_set_write_mask(RIO *io, const ut8 *mask, int len);
R_API void r_io_bind(RIO *io, RIOBind *bnd);
R_API bool r_io_shift(RIO *io, ut64 start, ut64 end, st64 move);
R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence);
R_API int r_io_fini(RIO *io);
R_API void r_io_free(RIO *io);
#define r_io_bind_init(x) memset(&x,0,sizeof(x))

R_API bool r_io_plugin_init(RIO *io);
R_API bool r_io_plugin_add(RIO *io, RIOPlugin *plugin);
R_API int r_io_plugin_list(RIO *io);
R_API int r_io_plugin_list_json(RIO *io);
R_API int r_io_plugin_read(RIODesc *desc, ut8 *buf, int len);
R_API int r_io_plugin_write(RIODesc *desc, const ut8 *buf, int len);
R_API int r_io_plugin_read_at(RIODesc *desc, ut64 addr, ut8 *buf, int len);
R_API int r_io_plugin_write_at(RIODesc *desc, ut64 addr, const ut8 *buf, int len);
R_API RIOPlugin *r_io_plugin_resolve(RIO *io, const char *filename, bool many);
R_API RIOPlugin *r_io_plugin_get_default(RIO *io, const char *filename, bool many);

/* bank */
R_API void r_io_use_bank(RIO *io, RIOBank *bank);
R_API RIOBank* r_io_new_bank(const char *name);
R_API bool r_io_bank_add_map(RIO *io, RIOBank *bank, ut32 map_id);
R_API void r_io_bank_free(RIOBank *bank);
R_API void r_io_bank_rename(RIOBank *bank, const char *name);

/* banks */
R_API void r_io_banks_reset(RIO *io);
R_API bool r_io_banks_add(RIO *io, RIOBank *bank);
R_API bool r_io_banks_del(RIO *io, RIOBank *bank);
R_API char *r_io_banks_list(RIO *io, int mode);
R_API bool r_io_banks_use(RIO *io, ut32 id);
R_API RIOBank* r_io_bank_get_by_name(RIO *io, const char *name);
R_API RIOBank* r_io_bank_get_by_id(RIO *io, ut32 id);

/* undo api */
// track seeks and writes
// TODO: needs cleanup..kinda big?
R_API int r_io_undo_init(RIO *io);
R_API void r_io_undo_enable(RIO *io, int seek, int write);
/* seek undo */
R_API RIOUndos *r_io_sundo(RIO *io, ut64 offset);
R_API RIOUndos *r_io_sundo_redo(RIO *io);
R_API void r_io_sundo_push(RIO *io, ut64 off, int cursor);
R_API void r_io_sundo_reset(RIO *io);
R_API RList *r_io_sundo_list(RIO *io, int mode);
/* write undo */
R_API void r_io_wundo_new(RIO *io, ut64 off, const ut8 *data, int len);
R_API void r_io_wundo_apply_all(RIO *io, int set);
R_API int r_io_wundo_apply(RIO *io, struct r_io_undo_w_t *u, int set);
R_API void r_io_wundo_clear(RIO *io);
R_API int r_io_wundo_size(RIO *io);
R_API void r_io_wundo_list(RIO *io);
R_API int r_io_wundo_set_t(RIO *io, RIOUndoWrite *u, int set) ;
R_API void r_io_wundo_set_all(RIO *io, int set);
R_API int r_io_wundo_set(RIO *io, int n, int set);

//desc.c
R_API RIODesc *r_io_desc_new(RIO *io, RIOPlugin *plugin, const char *uri, int flags, int mode, void *data);
R_API RIODesc *r_io_desc_open(RIO *io, const char *uri, int flags, int mode);
R_API RIODesc *r_io_desc_open_plugin(RIO *io, RIOPlugin *plugin, const char *uri, int flags, int mode);
R_API bool r_io_desc_close(RIODesc *desc);
R_API int r_io_desc_read(RIODesc *desc, ut8 *buf, int count);
R_API int r_io_desc_write(RIODesc *desc, const ut8 *buf, int count);
R_API void r_io_desc_free(RIODesc *desc);
R_API bool r_io_desc_add(RIO *io, RIODesc *desc);
R_API bool r_io_desc_del(RIO *io, int fd);
R_API RIODesc *r_io_desc_get(RIO *io, int fd);
R_API RIODesc *r_io_desc_get_next(RIO *io, RIODesc *desc);
R_API RIODesc *r_io_desc_get_prev(RIO *io, RIODesc *desc);
R_API RIODesc *r_io_desc_get_highest(RIO *io);
R_API RIODesc *r_io_desc_get_lowest(RIO *io);
R_API ut64 r_io_desc_seek(RIODesc *desc, ut64 offset, int whence);
R_API bool r_io_desc_resize(RIODesc *desc, ut64 newsize);
R_API ut64 r_io_desc_size(RIODesc *desc);
R_API bool r_io_desc_is_blockdevice(RIODesc *desc);
R_API bool r_io_desc_is_chardevice(RIODesc *desc);
R_API bool r_io_desc_exchange(RIO *io, int fd, int fdx);	//this should get 2 descs
R_API bool r_io_desc_is_dbg(RIODesc *desc);
R_API int r_io_desc_get_pid(RIODesc *desc);
R_API int r_io_desc_get_tid(RIODesc *desc);
R_API bool r_io_desc_get_base(RIODesc *desc, ut64 *base);
R_API int r_io_desc_read_at(RIODesc *desc, ut64 addr, ut8 *buf, int len);
R_API int r_io_desc_write_at(RIODesc *desc, ut64 addr, const ut8 *buf, int len);

/* lifecycle */
R_IPI bool r_io_desc_init(RIO *io);
R_IPI bool r_io_desc_fini(RIO *io);

/* io/cache.c */
R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to);
R_API bool r_io_cache_at(RIO *io, ut64 addr);
R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to);
R_API void r_io_cache_init(RIO *io);
R_API void r_io_cache_fini(RIO *io);
R_API bool r_io_cache_list(RIO *io, int rad);
R_API void r_io_cache_reset(RIO *io, int set);
R_API bool r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len);
R_API bool r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len);

/* io/p_cache.c */
R_API bool r_io_desc_cache_init(RIODesc *desc);
R_API int r_io_desc_cache_write(RIODesc *desc, ut64 paddr, const ut8 *buf, int len);
R_API int r_io_desc_cache_read(RIODesc *desc, ut64 paddr, ut8 *buf, int len);
R_API bool r_io_desc_cache_commit(RIODesc *desc);
R_API void r_io_desc_cache_cleanup(RIODesc *desc);
R_API void r_io_desc_cache_fini(RIODesc *desc);
R_API void r_io_desc_cache_fini_all(RIO *io);
R_API RList *r_io_desc_cache_list(RIODesc *desc);
R_API int r_io_desc_extend(RIODesc *desc, ut64 size);

/* io/buffer.c */
R_API int r_io_buffer_read(RIO* io, ut64 addr, ut8* buf, int len);
R_API int r_io_buffer_load(RIO* io, ut64 addr, int len);
R_API void r_io_buffer_close(RIO* io);

/* io/fd.c */
R_API int r_io_fd_open(RIO *io, const char *uri, int flags, int mode);
R_API bool r_io_fd_close(RIO *io, int fd);
R_API int r_io_fd_read(RIO *io, int fd, ut8 *buf, int len);
R_API int r_io_fd_write(RIO *io, int fd, const ut8 *buf, int len);
R_API ut64 r_io_fd_seek(RIO *io, int fd, ut64 addr, int whence);
R_API ut64 r_io_fd_size(RIO *io, int fd);
R_API bool r_io_fd_resize(RIO *io, int fd, ut64 newsize);
R_API bool r_io_fd_is_blockdevice(RIO *io, int fd);
R_API bool r_io_fd_is_chardevice(RIO *io, int fd);
R_API int r_io_fd_read_at(RIO *io, int fd, ut64 addr, ut8 *buf, int len);
R_API int r_io_fd_write_at(RIO *io, int fd, ut64 addr, const ut8 *buf, int len);
R_API bool r_io_fd_is_dbg(RIO *io, int fd);
R_API int r_io_fd_get_pid(RIO *io, int fd);
R_API int r_io_fd_get_tid(RIO *io, int fd);
R_API bool r_io_fd_get_base(RIO *io, int fd, ut64 *base);
R_API const char *r_io_fd_get_name(RIO *io, int fd);
R_API int r_io_fd_get_current(RIO *io);
R_API bool r_io_use_fd(RIO *io, int fd);
R_API int r_io_fd_get_next(RIO *io, int fd);
R_API int r_io_fd_get_prev(RIO *io, int fd);
R_API int r_io_fd_get_highest(RIO *io);
R_API int r_io_fd_get_lowest(RIO *io);


#define r_io_range_new()	R_NEW0(RIORange)
#define r_io_range_free(x)	free(x)

/* io/ioutils.c */
R_API bool r_io_is_valid_offset(RIO *io, ut64 offset, int hasperm);
R_API bool r_io_addr_is_mapped(RIO *io, ut64 vaddr);
R_API bool r_io_read_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian);
R_API bool r_io_write_i(RIO* io, ut64 addr, ut64 *val, int size, bool endian);

#if HAVE_PTRACE
R_API long r_io_ptrace(RIO *io, r_ptrace_request_t request, pid_t pid, void *addr, r_ptrace_data_t data);
R_API pid_t r_io_ptrace_fork(RIO *io, void (*child_callback)(void *), void *child_callback_user);
R_API void *r_io_ptrace_func(RIO *io, void *(*func)(void *), void *user);
#endif

extern RIOPlugin r_io_plugin_procpid;
extern RIOPlugin r_io_plugin_malloc;
extern RIOPlugin r_io_plugin_sparse;
extern RIOPlugin r_io_plugin_ptrace;
extern RIOPlugin r_io_plugin_w32dbg;
extern RIOPlugin r_io_plugin_windbg;
extern RIOPlugin r_io_plugin_mach;
extern RIOPlugin r_io_plugin_debug;
extern RIOPlugin r_io_plugin_shm;
extern RIOPlugin r_io_plugin_gdb;
extern RIOPlugin r_io_plugin_rap;
extern RIOPlugin r_io_plugin_http;
extern RIOPlugin r_io_plugin_bfdbg;
extern RIOPlugin r_io_plugin_w32;
extern RIOPlugin r_io_plugin_zip;
extern RIOPlugin r_io_plugin_mmap;
extern RIOPlugin r_io_plugin_default;
extern RIOPlugin r_io_plugin_ihex;
extern RIOPlugin r_io_plugin_self;
extern RIOPlugin r_io_plugin_gzip;
extern RIOPlugin r_io_plugin_winkd;
extern RIOPlugin r_io_plugin_r2pipe;
extern RIOPlugin r_io_plugin_r2web;
extern RIOPlugin r_io_plugin_qnx;
extern RIOPlugin r_io_plugin_r2k;
extern RIOPlugin r_io_plugin_tcpslurp;
extern RIOPlugin r_io_plugin_bochs;
extern RIOPlugin r_io_plugin_null;
extern RIOPlugin r_io_plugin_ar;
extern RIOPlugin r_io_plugin_rbuf;
extern RIOPlugin r_io_plugin_winedbg;
extern RIOPlugin r_io_plugin_gprobe;
extern RIOPlugin r_io_plugin_fd;
extern RIOPlugin r_io_plugin_socket;

#if __cplusplus
}
#endif

#endif
