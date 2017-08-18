/* radare - LGPL - Copyright 2008-2016 - pancake */

#include "r_io.h"
#include "r_util.h"
#include <stdio.h>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

R_LIB_VERSION (r_io);

/* allocate 128 MB */
#define R_IO_MAX_ALLOC (1024 * 1024 * 128)

// XXX: this is buggy. must use seek+read
// the new io is buggy	//liar
#define USE_NEW_IO 0
#define DO_THE_IO_DBG 0
#define IO_IFDBG if (DO_THE_IO_DBG == 1)

R_API RIO *r_io_new() {
	RIO *io = R_NEW0 (RIO);
	if (!io) {
		return NULL;
	}
	io->buffer = r_cache_new (); // RCache is a list of ranged buffers. maybe rename?
	io->write_mask_fd = -1;
	io->cb_printf = (void *)printf;
	io->bits = (sizeof (void *) == 8)? 64: 32;
	io->ff = true;
	io->Oxff = 0xff;
	io->aslr = 0;
	io->pava = false;
	io->raised = -1;
	io->autofd = true;
	r_io_map_init (io);
	r_io_desc_init (io);
	r_io_undo_init (io);
	r_io_cache_init (io);
	r_io_plugin_init (io);
	r_io_section_init (io);
	{
		char *env = r_sys_getenv ("R_IO_MAX_ALLOC");
		if (env) {
			io->maxalloc = r_num_get (NULL, env);
			free (env);
		}
	}
	return io;
}

R_API void r_io_raise(RIO *io, int fd) {
	io->raised = fd;
}

R_API int r_io_is_listener(RIO *io) {
	if (io && io->plugin && io->plugin->listener) {
		return io->plugin->listener (io->desc);
	}
	return false;
}

R_API RBuffer *r_io_read_buf(RIO *io, ut64 addr, int len) {
	RBuffer *b = R_NEW0 (RBuffer);
	if (!b) return NULL;
	b->buf = malloc (len);
	if (!b->buf) {
		free (b);
		return NULL;
	}
	len = r_io_read_at (io, addr, b->buf, len);
	b->length = (len < 0)? 0: len;
	return b;
}

R_API int r_io_write_buf(RIO *io, struct r_buf_t *b) {
	return r_io_write_at (io, b->base, b->buf, b->length);
}

R_API RIO *r_io_free(RIO *io) {
	if (!io) {
		return NULL;
	}
	r_list_free (io->sections);
	ls_free (io->maps);
	r_list_free (io->undo.w_list);
	r_cache_free (io->buffer);
	r_list_free (io->cache);
	r_io_desc_fini (io);
	ls_free (io->plugins);
	free (io);
	return NULL;
}

/* used by uri handler plugins */
R_API int r_io_redirect(RIO *io, const char *file) {
	free (io->redirect);
	io->redirect = file? strdup (file): NULL;
	return 0;
}

R_API RIODesc *r_io_open_as(RIO *io, const char *urihandler, const char *file, int flags, int mode) {
	RIODesc *ret;
	char *uri;
	int urilen, hlen = strlen (urihandler);
	urilen = hlen + strlen (file) + 5;
	uri = malloc (urilen);
	if (!uri)
		return NULL;
	if (hlen > 0)
		snprintf (uri, urilen, "%s://%s", urihandler, file);
	else strncpy (uri, file, urilen);
	ret = r_io_open_nomap (io, uri, flags, mode);
	free (uri);
	return ret;
}

static inline RIODesc *__getioplugin(RIO *io, const char *_uri, int flags, int mode) {
	RIOPlugin *plugin;
	RIODesc *desc = NULL;
	char *uri = strdup (_uri? _uri: "");
	char *redir = NULL;
	for (;;) {
		plugin = r_io_plugin_resolve (io, uri, 0);
		if (plugin && plugin->open) {
			desc = plugin->open (io, uri, flags, mode);
			if (io->redirect) {
				redir = uri;
				uri = strdup (io->redirect);
				r_io_redirect (io, NULL);
				continue;
			}
			if (desc) {
				desc->uri = uri;
				desc->referer = redir;
				io->plugin = plugin;
			}
		}
		break;
	}
	if (!desc) {
		plugin = r_io_plugin_get_default (io, uri, 0);
		desc = (plugin && plugin->open)
			? plugin->open (io, uri, flags, mode)
			: NULL;
		if (desc) {
			desc->uri = uri;
			io->plugin = plugin;
		}
	}
	if (!desc) {
		free (uri);
		io->plugin = NULL;
	}
	return desc;
}

static inline RList *__getioplugin_many(RIO *io, const char *_uri, int flags, int mode) {
	RIOPlugin *plugin, *iop = NULL;
	RList *list_fds = NULL;
	RListIter *iter;
	RIODesc *desc;
	char *uri = strdup (_uri);
	for (;;) {
		// resolve
		plugin = r_io_plugin_resolve (io, uri, 1);
		if (plugin && plugin->open_many) {
			// open
			list_fds = plugin->open_many (io, uri, flags, mode);
			if (io->redirect) {
				free (uri);
				uri = strdup (io->redirect);
				r_io_redirect (io, NULL);
				continue;
			}
		}
		break;
	}

	if (!list_fds) {
		free (uri);
		return NULL;
	}

	r_list_foreach (list_fds, iter, desc) {
		desc->uri = strdup (uri);
	}

	io->plugin = iop;
	free (uri);
	return list_fds;
}

R_API RIODesc *r_io_open_nomap(RIO *io, const char *uri, int flags, int mode) {
	RIODesc* desc;
	RIOPlugin* plugin;
	if (!io || !io->files || !uri) {
		return NULL;
	}
	plugin = r_io_plugin_resolve (io, uri, 0);
	if (!plugin || !plugin->open) {
		return NULL;
	}
	desc = plugin->open (io, uri, flags, mode);
	if (!desc) {
		return NULL;
	}
	//for none static callbacks, those that cannot use r_io_desc_new
	if (!desc->plugin) {
		desc->plugin = plugin;
	}
	if (!desc->uri) {
		desc->uri = strdup (uri);
	}
	if (!desc->name) {
		desc->name = strdup (uri);
	}
	r_io_desc_add (io, desc);
	//set desc as current if autofd or io->desc==NULL
	if (io->autofd || !io->desc) {
		io->desc = desc;
	}
	return desc;
}

R_API RIODesc *r_io_open_at(RIO *io, const char *file, int flags, int mode, ut64 maddr) {
	RIODesc *desc;
	ut64 size;
	if (!io || !file || io->redirect) {
		return NULL;
	}
	desc = __getioplugin (io, file, flags, mode);
	if (desc) {
		r_io_desc_add (io, desc);
		size = r_io_desc_size (desc);
		if (io->autofd || !io->desc) {
			r_io_use_desc (io, desc);
		}
		r_io_map_new (io, desc->fd, mode, 0, maddr, size);
	} else {
		eprintf ("r_io_open_at: Unable to open file: %s\n", file);
	}
	return desc;
}

R_API RIODesc *r_io_open(RIO *io, const char *file, int flags, int mode) {
	return r_io_open_at (io, file, flags, mode, 0LL);
}

R_API RList *r_io_open_many(RIO *io, const char *file, int flags, int mode) {
	RIODesc *desc;
	RListIter *desc_iter = NULL;
	int fd;
	RList *list_fds;
	if (!io || !file || io->redirect)
		return NULL;
	list_fds = __getioplugin_many (io, file, flags, mode);

	if (!list_fds)
		return NULL;

	r_list_foreach (list_fds, desc_iter, desc) {
		fd = -1;
		if (desc) fd = desc->fd;
		if (fd >= 0) r_io_desc_add (io, desc);
	}
	return list_fds;
}

R_API int r_io_reopen(RIO *io, RIODesc *desc, int flags, int mode) {
	RIODesc *n = NULL;
	SdbListIter *iter;
	RIOMap *map;
	if (desc && desc->uri && io && io->files && (desc == r_io_desc_get (io, desc->fd))) {
		n = __getioplugin (io, desc->uri, flags, mode);
		if (!n) {
			return false;
		}
		r_io_section_rm_all (io, desc->fd);
		if (io->maps) {
			ls_foreach (io->maps, iter, map) {
				if (map->fd == desc->fd) {
					map->fd = n->fd;
					map->flags &= n->flags;
				}
			}
		}
		if (desc->plugin && desc->plugin->close)
			desc->plugin->close (desc); //free desc->data
		free (desc->name);
		free (desc->uri);
		*desc = *n;
		free (n);
		return true;
	}
	return false;
}

R_API int r_io_use_desc(RIO *io, RIODesc *d) {
	if (io && d && d->plugin) {
		io->desc = d;
		io->plugin = d->plugin;
		return true;
	}
	return false;
}

R_API int r_io_get_fd(RIO *io) {
	if (!io || !io->desc) {
		return -1;
	}
	return io->desc->fd;
}

R_API bool r_io_use_fd(RIO* io, int fd) {
	RIODesc* desc;
	if (!io || !io->desc) {
		if (!(desc = r_io_desc_get (io, fd))) {
			return false;
		}
		io->desc = desc;
		return true;
	}
	if (io->desc->fd != fd) {
		//update io->desc if fd is not the same
		if (!(desc = r_io_desc_get (io, fd))) {
			return false;
		}
		r_io_use_desc (io, desc);
	}
	return true;
}

static bool readcache = false;

R_API int r_io_read_internal(RIO *io, ut8 *buf, int len) {
	int bytes_read = 0;
	const char *source = NULL;
	if (io->desc) {
		source = io->desc->plugin->name;
		bytes_read = r_io_desc_read (io->desc, buf, len);
#if 1
		if (readcache) {
			if (bytes_read > 0) {
				readcache = false;
				bytes_read = r_io_cache_write (io, io->off, buf, len);
				readcache = true;
			}
		}
#endif
	} else if (!io->desc) {
		if (io->files) {
			eprintf ("Something really bad has happened, and r2 is going to die soon. sorry! :-(\n");
		}
		source = "FAILED";
		bytes_read = 0;
	} else {
		source = "File";
		bytes_read = read (io->desc->fd, buf, len);
	}
	IO_IFDBG {
		if (io->desc) eprintf ("Data source: %s\n", io->desc->name);
		eprintf ("Asked for %d bytes, provided %d from %s\n",
			len, bytes_read, source);
	}
	return bytes_read;
}

R_API int r_io_read(RIO *io, ut8 *buf, int len) {
	int ret;
	if (!io || !io->desc || !buf || io->off == UT64_MAX) {
		return -1;
	}
	/* IGNORE check section permissions */
	if (io->enforce_rwx & R_IO_READ) {
		if (!(r_io_section_get_rwx (io, io->off) & R_IO_READ)) {
			return -1;
		}
	}
	/* io->off is in maddr, but r_io_read_at works in vaddr
	 * FIXME: in some cases, r_io_seek sets io->off in vaddr */
	ut64 vaddr = r_io_section_maddr_to_vaddr(io, io->off);
	vaddr = (vaddr == UT64_MAX) ? io->off : vaddr;
	ret = r_io_read_at (io, vaddr, buf, len);
	if (ret > 0) io->off += ret;
	return ret;
}

R_API int r_io_pread_at(RIO *io, ut64 paddr, ut8 *buf, int len) {
	int ret = 0;
	if (!io || !buf || len < 1) {
		return 0;
	}
	if (io->ff) {
		memset (buf, 0xff, len);
	}
	//check pointers and permissions
	if (!io->desc || !(io->desc->flags & R_IO_READ) || !len) {
		return 0;
	}
	r_io_desc_seek (io->desc, paddr, R_IO_SEEK_SET);
	ret = r_io_desc_read (io->desc, buf, len);
	if (ret < 1) {
		return 0;
	}
	if (io->p_cache) {
		r_io_desc_cache_read (io->desc, paddr, buf, len);
	}
	return ret;
}

R_API int r_io_vread_at(RIO *io, ut64 vaddr, ut8 *buf, int len) {
	ut64 paddr = 0;
	if (!io || !buf) {
		return 0;
	}
	if (len < 1) {
		return 0;
	}
	if (!r_io_is_valid_offset (io, vaddr, 0)) {
		if (io->ff) {
			memset (buf, 0xff, len);
		}
		return len;
	}
	if (!io->maps) {
		return r_io_pread_at (io, vaddr, buf, len);
	}
	if (io->debug) {
		paddr = vaddr;
	} else {
		ut64 maddr = r_io_section_vaddr_to_maddr (io, vaddr);
		paddr = r_io_map_select (io, maddr != UT64_MAX? maddr : vaddr);
		if (paddr == UT64_MAX) {
			paddr = vaddr;
		}
	}
	return r_io_pread_at (io, paddr, buf, len);
}

//the API differs with SIOL in that returns a bool instead of amount read
R_API int r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	int ret;
	if (!io || !buf || len < 1) {
		return 0;
	}
	if (io->va) {
		ret = r_io_vread_at (io, addr, buf, len);
	} else {
		ret = r_io_pread_at (io, addr, buf, len);
	}
	if (io->cached_read) {
		r_io_cache_read (io, addr, buf, len);
	}
	return ret;

}

R_API ut64 r_io_read_i(RIO *io, ut64 addr, int sz) {
	ut64 ret = 0LL;
	ut8 buf[8];
	sz = R_DIM (sz, 1, 8);
	if (sz != r_io_read_at (io, addr, buf, sz))
		return UT64_MAX;
	memcpy ((ut8 *)&ret, buf, sz);
	return ret;
}

/* Same as r_io_read_at, but not consume bytes */
R_API int r_io_peek_at(RIO *io, const ut64 addr, ut8 *buf, const int sz) {
	int ret = -1, tmp_ret = -1;
	ret = r_io_seek (io, addr, R_IO_SEEK_SET);
	if (ret != -1) {
		ret = r_io_read (io, buf, sz);
	}
	if (ret != -1) {
		tmp_ret = r_io_seek (io, addr, R_IO_SEEK_SET);
	}
	if (tmp_ret == -1) ret = tmp_ret;
	return ret;
}

// TODO. this is a physical resize
R_API bool r_io_resize(RIO *io, ut64 newsize) {
	if (io->plugin) {
		if (io->plugin->resize && io->desc) {
			bool res = io->plugin->resize (io, io->desc, newsize);
			if (res) {
				r_io_map_truncate_update (io, io->desc->fd, newsize);
			}
			return res;
		}
		return false;
	}
	return true;
}

R_API int r_io_extend(RIO *io, ut64 extend) {
	ut64 addr = io->off, size = r_io_size (io);
	ut8 *buf;
	if (!extend) {
		return false;
	}
	if (io->plugin && io->plugin->extend) {
		return io->plugin->extend (io, io->desc, extend);
	}
	if (!UT64_ADD_OVFCHK (size, extend)) {
		if (!r_io_resize (io, size + extend)) {
			return false;
		}
	} else {
		return false;
	}

	bool ret = true;
	if (addr < size) {
		buf = malloc (R_MAX (size - addr, extend));
		if (!buf) {
			return false;
		}
		// move [addr, size) to [addr+extend, size+extend)
		if (r_io_read_at (io, addr, buf, size - addr) != size - addr ||
				r_io_write_at (io, addr + extend, buf, size - addr) != size - addr ||
				// zero out [addr, addr+extend)
				(memset (buf, 0, extend),
				 r_io_write_at (io, addr, buf, extend) != extend)) {
			ret = false;
		}
	} else {
		buf = calloc (1, extend);
		if (!buf) {
			return false;
		}
		if (r_io_write_at (io, addr, buf, extend) != extend) {
			ret = false;
		}
	}
	free (buf);
	return ret;
}

R_API int r_io_extend_at(RIO *io, ut64 addr, ut64 size) {
	if (!size) return false;
	(void) r_io_seek (io, addr, R_IO_SEEK_SET);
	return r_io_extend (io, size);
}

R_API int r_io_set_write_mask(RIO *io, const ut8 *buf, int len) {
	if (len > 0) {
		io->write_mask_fd = io->desc->fd;
		io->write_mask_buf = (ut8 *)malloc (len);
		if (io->write_mask_buf) {
			memcpy (io->write_mask_buf, buf, len);
			io->write_mask_len = len;
			return true;
		}
	}
	io->write_mask_fd = -1;
	return false;
}

R_API int r_io_write(RIO *io, const ut8 *buf, int len) {
	ut64 maddr = io->off;
	int i, ret = -1, orig_len = 0;
	ut8 *data = NULL, *orig_bytes = NULL;

	/* io->off is in maddr, but r_io_peek_at works in vaddr
	 * FIXME: in some cases, r_io_seek sets io->off in vaddr */
	ut64 vaddr = r_io_section_maddr_to_vaddr(io, maddr);

	/* check section permissions */
	if (io->enforce_rwx & R_IO_WRITE) {
		if (!(r_io_section_get_rwx (io, io->off) & R_IO_WRITE)) {
			ret = -1;
			goto cleanup;
		}
	}

	orig_bytes = malloc (len);
	if (!orig_bytes) {
		eprintf ("Cannot allocate %d bytes", len);
		ret = -1;
		goto cleanup;
	}

	orig_len = r_io_peek_at (io, vaddr, orig_bytes, len);

	if (io->cached) {
		ret = r_io_cache_write (io, io->off, buf, len);
		if (ret == len) {
			if (orig_len > 0 && io->cb_core_post_write) {
				io->cb_core_post_write (io->user, maddr, orig_bytes, orig_len);
			}
			goto cleanup;
		}
		if (ret > 0) {
			len -= ret;
			buf += ret;
		}
	}

	/* TODO: implement IO cache here. to avoid dupping work on vm for example */

	/* apply write binary mask */
	if (io->write_mask_fd != -1) {
		data = (len > 0)? malloc (len): NULL;
		if (!data) {
			eprintf ("malloc failed in write_mask_fd");
			ret = -1;
			goto cleanup;
		}
		// memset (data, io->Oxff, len);
		r_io_peek_at (io, vaddr, data, len);
		for (i = 0; i < len; i++) {
			data[i] = buf[i] &
				io->write_mask_buf[i % io->write_mask_len];
		}
		buf = data;
	}

	// this makes a double sub, so we restore the io->off
	{
		ut64 addr = io->off;
		r_io_map_select (io, io->off);
		io->off = addr;
	}
	{
		RIOMap *map = r_io_map_get (io, io->off);
		if (map) {
			io->off -= map->from;
		}
	}

	if (io->desc) {
		ret = r_io_desc_write (io->desc, buf, len);
		if (ret == UT64_MAX) {
			eprintf ("r_io_write: io handler with no write callback\n");
			ret = -1;
		}
	}
	if (ret == -1) {
		if (io->cached != 2) {
			eprintf ("r_io_write: cannot write %d bytes "
				"at 0x%" PFMT64x " (file=%s, fd=%d)\n",
				len, io->off,
				io->desc? io->desc->uri: "unknown",
				io->desc? io->desc->fd: -1);
			eprintf ("hint: try oo+ or e io.cache=true\n");
			r_io_cache_invalidate (io, io->off, io->off + 1);
		}
	} else {
		if (readcache) {
			//r_io_cache_invalidate (io, io->off, io->off + len);
			r_io_cache_write (io, io->off, buf, len);
		}
		if (io->desc) {
			r_io_map_write_update (io, io->desc->fd, io->off, ret);
			io->off += ret;
		}
	}

	if (ret > 0 && orig_len > 0 && io->cb_core_post_write) {
		io->cb_core_post_write (io->user, maddr, orig_bytes, orig_len);
	}

cleanup:
	free (data);
	free (orig_bytes);

	return ret;
}

R_API int r_io_vwrite_at(RIO *io, ut64 vaddr, const ut8 *buf, int len) {
	ut64 paddr = 0;
	if (!io || !buf) {
		return false;
	}
	if (len < 1) {
		return true;
	}
	if (!io->maps) {
		return r_io_pwrite_at (io, vaddr, buf, len);
	}
	if (io->debug) {
		paddr = vaddr;
	} else {
		ut64 maddr = r_io_section_vaddr_to_maddr (io, vaddr);
		paddr = r_io_map_select (io, maddr != UT64_MAX? maddr : vaddr);
		if (paddr == UT64_MAX) {
			paddr = vaddr;
		}
	}
	return r_io_pwrite_at (io, paddr, buf, len);
}

R_API int r_io_write_at(RIO *io, ut64 addr, const ut8 *buf, int len) {
	int i, ret = 0;
	ut8 *mybuf = (ut8*)buf;
	if (!io || !buf || len < 1) {
		return 0;
	}
	if (io->write_mask_buf) {
		mybuf = r_mem_dup ((void*)buf, len);
		for (i = 0; i < len; i++) {
			//this sucks
			mybuf[i] &= io->write_mask_buf[i % io->write_mask_len];
		}
	}
	if (io->cached) {
		ret = r_io_cache_write (io, addr, mybuf, len);
	} else if (io->va) {
		ret = r_io_vwrite_at (io, addr, mybuf, len);
	} else {
		ret = r_io_pwrite_at (io, addr, mybuf, len);
	}
	if (buf != mybuf) {
		free (mybuf);
	}
	return ret;
}

R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence) {
	// TODO: review the offset/vaddr/paddr/maddr thing here
	// now, io-seek always works with vaddr, because it depends on read/write ops that use it
	int posix_whence = SEEK_SET;
	ut64 ret = UT64_MAX;
	if (!io) {
		return ret;
	}
	if (io->buffer_enabled) {
		io->off = offset;
		return offset;
	}
	switch (whence) {
	case R_IO_SEEK_SET:
		posix_whence = SEEK_SET;
		break;
	case R_IO_SEEK_CUR:
		posix_whence = SEEK_CUR;
		break;
	case R_IO_SEEK_END:
		posix_whence = SEEK_END;
		break;
	}
	if (!io->debug) {
		if (io->va && !r_list_empty (io->sections)) {
			ut64 o = r_io_section_vaddr_to_maddr_try (io, offset);
			if (o != UT64_MAX) {
				offset = o;
			}
		}
	}
	// if resolution fails... just return as invalid address
	if (offset == UT64_MAX) {
		return UT64_MAX;
	}
	if (io->desc) {
		ut64 paddr = 0;
		(void)r_search_map (io, offset, &paddr);
		ret = r_io_desc_seek (io->desc, paddr, whence);
		if (ret == UT64_MAX) {
			ret = (ut64)lseek (io->desc->fd, offset, posix_whence);
		}
	}
	if (whence == R_IO_SEEK_SET) {
		io->off = offset;
	}
	return ret;
}

R_API ut64 r_io_fd_size(RIO *io, int fd) {
	RIODesc *desc = r_io_desc_get (io, fd);
	return r_io_desc_size (desc);
}

R_API bool r_io_fd_is_blockdevice(RIO *io, int fd) {
	RIODesc *desc = r_io_desc_get (io, fd);
	return r_io_desc_is_blockdevice (desc);
}

R_API ut64 r_io_size(RIO *io) {
	return io? r_io_desc_size (io->desc): 0LL;
}

R_API int r_io_system(RIO *io, const char *cmd) {
	int ret = -1;
	if (io->plugin && io->plugin->system) {
		ret = io->plugin->system (io, io->desc, cmd);
	}
	return ret;
}

R_API int r_io_plugin_close(RIO *io, RIODesc *desc) {
	if (io->plugin && io->plugin->close) {
		int ret = io->plugin->close (desc);
		if (desc == io->desc) {
			io->desc = NULL;
		}
		return ret;
	}
	return -1;
}

R_API bool r_io_close(RIO *io, int fd) {
	RIODesc* desc = r_io_desc_get (io, fd);
	if (!desc || !desc->plugin || !desc->plugin->close) {
		return false;
	}
	if (desc->plugin->close (desc)) {
		return false;
	}
	// remove entry from sdb-instance and free the desc-struct
	r_io_desc_del (io, fd);
	// remove all dead maps
#if 0
	r_io_map_cleanup (io);
	r_io_section_cleanup (io);
#endif
	return true;
}

R_API int r_io_close_all(RIO *io) {
	// LOT OF MEMLEAKS HERE
	if (!io) {
		return 0;
	}
	r_cache_free (io->buffer);
	io->buffer = r_cache_new (); // RCache is a list of ranged buffers. maybe rename?
	io->write_mask_fd = -1;
	io->ff = 1;
	io->raised = -1;
	io->autofd = true;
	r_io_map_del (io, -1);
	r_io_desc_del (io, -1);
	r_io_section_rm_all (io, -1);
	r_io_undo_init (io);
	r_io_cache_reset (io, 0);
	//	r_io_plugin_init (io);
	return 1;
}


static RIO* bind_get_io (RIOBind* iob) {
	return iob? iob->io: NULL;
}

R_API int r_io_bind(RIO *io, RIOBind *bnd) {
	if (!io || !bnd) {
		return false;
	}
	bnd->io = io;
	bnd->init = true;
	bnd->get_io = bind_get_io;
	bnd->desc_use = r_io_use_fd;
	bnd->desc_get = r_io_desc_get;
	bnd->desc_size = r_io_desc_size;
	bnd->open = r_io_open_nomap;
	bnd->open_at = r_io_open_at;
	bnd->close = r_io_close;
	bnd->read_at = r_io_read_at;
	bnd->write_at = r_io_write_at;
	bnd->system = r_io_system;
	bnd->is_valid_offset = r_io_is_valid_offset;
	bnd->section_vget = r_io_section_vget;
	bnd->section_add = r_io_section_add;

	bnd->section_set_arch = r_io_section_set_archbits;
	bnd->section_set_arch_bin_id = r_io_section_set_archbits_bin_id;

	return true;
}

R_API int r_io_accept(RIO *io, int fd) {
	if (r_io_is_listener (io) && io->plugin && io->plugin->accept) {
		return io->plugin->accept (io, io->desc, fd);
	}
	return false;
}

/* moves bytes up (+) or down (-) within the specified range */
R_API int r_io_shift(RIO *io, ut64 start, ut64 end, st64 move) {
	ut8 *buf;
	ut64 chunksize = 0x10000;
	ut64 rest, src, shiftsize = r_num_abs (move);
	if (!shiftsize || (end - start) <= shiftsize) return false;
	rest = (end - start) - shiftsize;

	if (!(buf = malloc (chunksize))) {
		return false;
	}
	if (move > 0) {
		src = end - shiftsize;
	} else {
		src = start + shiftsize;
	}
	while (rest > 0) {
		if (chunksize > rest) {
			chunksize = rest;
		}
		if (move > 0) {
			src -= chunksize;
		}
		r_io_read_at (io, src, buf, chunksize);
		r_io_write_at (io, src + move, buf, chunksize);
		if (move < 0) {
			src += chunksize;
		}
		rest -= chunksize;
	}
	free (buf);
	return true;
}

R_API int r_io_create(RIO *io, const char *file, int mode, int type) {
	if (io->plugin && io->plugin->create) {
		return io->plugin->create (io, file, mode, type);
	}
	if (type == 'd' || type == 1) {
		return r_sys_mkdir (file);
	}
	return r_sandbox_creat (file, mode);
}

R_API void r_io_sort_maps(RIO *io) {
	ls_sort (io->maps, (RListComparator)r_io_map_sort);
}

// check if reading at offset or writting to offset is reasonable
R_API bool r_io_is_valid_offset(RIO *io, ut64 offset, int hasperm) {
	if (!io) {
		eprintf ("r_io_is_valid_offset: io is NULL\n");
		r_sys_backtrace ();
		return false;
	}
	bool io_sectonly = io->sectonly;
	bool io_va = io->va;
	if (!io->files) {
		eprintf ("r_io_is_valid_offset: io->files is NULL\n");
		r_sys_backtrace ();
		return false;
	}
	if (!io->desc) {
		eprintf ("r_io_is_valid_offset: io->desc is NULL\n");
		r_sys_backtrace ();
		return false;
	}
	if (r_list_empty (io->sections)) {
		if ((r_io_map_exists_for_offset (io, offset))) {
			return true;
		}
	}
	if (!io_va) {
		if ((r_io_map_exists_for_offset (io, offset))) {
			return true;
		}
		return (offset < r_io_size (io));
	}
	if (io->debug) {
		// TODO check debug maps here
		return true;
	}
	if (io_sectonly) {
		if (r_list_empty (io->sections)) {
			return true;
		}
		return r_io_section_exists_for_vaddr (io, offset, hasperm);
	}
	if (!io_va && r_io_map_exists_for_offset (io, offset)) {
		return true;
	}
	return r_io_map_exists_for_offset (io, offset) ||
		   r_io_section_exists_for_vaddr (io, offset, hasperm);
}


R_API int r_io_pwrite_at(RIO* io, ut64 paddr, const ut8* buf, int len) {
	//check pointers and permissions
	int ret;
	if (!io || !buf || !io->desc ||
	   (!io->p_cache && !(io->desc->flags & R_IO_WRITE)) || len < 1) {
		return 0;
	}
	if (io->p_cache) {
		return r_io_desc_cache_write (io->desc, paddr, buf, len);
	}
	r_io_desc_seek (io->desc, paddr, R_IO_SEEK_SET);
	io->off = paddr;
	ret = r_io_desc_write (io->desc, buf, len);
	return ret < 1? 0 : ret;
}
