/* radare - LGPL - Copyright 2008-2014 - pancake */

#include "r_io.h"
#include "r_util.h"
#include <stdio.h>

R_LIB_VERSION (r_io);

#define DO_THE_IO_DBG 0
#define IO_IFDBG if (DO_THE_IO_DBG == 1)

static ut8 * r_io_desc_read (RIO *io, RIODesc * desc, ut64 *out_sz);
static RIO * r_io_bind_get_io(RIOBind *bnd);

static RIO * MASTER_IO = NULL;
R_API RIO *r_io_new() {
	RIO *io = R_NEW (RIO);
	if (!io) return NULL;
	io->buffer = r_cache_new (); // TODO: use RBuffer here
	io->buffer_enabled = 0;
	io->zeromap = R_FALSE; // if true, then 0 is mapped with contents of file
	io->fd = NULL;
	io->write_mask_fd = -1;
	io->redirect = NULL;
	io->printf = (void*) printf;
	io->bits = (sizeof(void*) == 8)? 64: 32;
	io->va = -1;
	io->plugin = NULL;
	io->raised = -1;
	io->off = 0;
	r_io_map_init (io);
	r_io_desc_init (io);
	r_io_undo_init (io);
	r_io_cache_init (io);
	r_io_plugin_init (io);
	r_io_section_init (io);
	return io;
}



R_API void r_io_raise(RIO *io, int fd) {
	io->raised = fd;
}

R_API int r_io_is_listener(RIO *io) {
	if (io && io->plugin && io->plugin->listener)
		return io->plugin->listener (io->fd);
	return R_FALSE;
}

R_API RBuffer *r_io_read_buf(RIO *io, ut64 addr, int len) {
	RBuffer *b = R_NEW (RBuffer);
	b->buf = malloc (len);
	len = r_io_read_at (io, addr, b->buf, len);
	b->length = (len<0)?0:len;
	return b;
}

R_API int r_io_write_buf(RIO *io, struct r_buf_t *b) {
	return r_io_write_at (io, b->base, b->buf, b->length);
}

R_API RIO *r_io_free(RIO *io) {
	struct list_head *pos, *n;
	if (!io) return NULL;
	/* TODO: properly free inner nfo */
	/* TODO: memory leaks */
	list_for_each_safe (pos, n, &io->io_list) {
		struct r_io_list_t *il = list_entry (pos, struct r_io_list_t, list);
		R_FREE (il->plugin);
		list_del (pos);
		R_FREE (il);
	}
	r_list_free (io->sections);
	r_list_free (io->maps);
	r_list_free (io->undo.w_list);
	r_cache_free (io->buffer);
	r_list_free (io->cache);
	r_io_desc_fini (io);
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
	urilen = hlen + strlen (file)+5;
	uri = malloc (urilen);
	if (uri == NULL)
		return NULL;
	if (hlen>0) snprintf (uri, urilen, "%s://%s", urihandler, file);
	else strncpy (uri, file, urilen);
	ret = r_io_open (io, uri, flags, mode);
	free (uri);
	return ret;
}

static inline RIODesc *__getioplugin(RIO *io, const char *_uri, int flags, int mode) {
	RIOPlugin *plugin;
	RIODesc *desc = NULL;
	char *uri = strdup (_uri);
	for (;;) {
		plugin = r_io_plugin_resolve (io, uri, 0);
		if (plugin && plugin->open) {
			desc = plugin->open (io, uri, flags, mode);
			if (io->redirect) {
				free (uri);
				uri = strdup (io->redirect);
				r_io_redirect (io, NULL);
				continue;
			}
			if (desc) {
				r_io_desc_add (io, desc);
				if (desc->fd != -1)
					r_io_plugin_open (io, desc->fd, plugin);
				if (desc != io->fd) {
					r_io_set_fd (io, desc);
				}
			}
		}
		break;
	}
	if (!desc) {
		plugin = r_io_plugin_get_default (io, uri, 0);
		desc = plugin ? plugin->open (io, uri, flags, mode) : NULL;
		if (desc) {
			r_io_desc_add (io, desc);
			if (desc->fd != -1)
				r_io_plugin_open (io, desc->fd, plugin);
			if (desc != io->fd) {
				r_io_set_fd (io, desc);
			}
		}
	}
	io->plugin = NULL;
	free (uri);
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

	if (!list_fds) return NULL;

	r_list_foreach (list_fds, iter, desc) {
		if (desc) r_io_desc_add (io, desc);
	}

	io->plugin = iop;
	free (uri);
	return list_fds;
}

static int __io_posix_open (RIO *io, const char *file, int flags, int mode) {
	int fd;
	if (r_file_is_directory (file))
		return -1;
#if __WINDOWS__
	if (flags & R_IO_WRITE) {
		fd = r_sandbox_open (file, O_BINARY | 1, 0);
		if (fd == -1)
			r_sandbox_creat (file, O_BINARY);
		fd = r_sandbox_open (file, O_BINARY | 1, 0);
	} else fd = r_sandbox_open (file, O_BINARY, 0);
#else
	fd = r_sandbox_open (file, (flags&R_IO_WRITE)?
			(O_RDWR|O_CREAT): O_RDONLY, mode);
#endif
	return fd;
}

R_API RIODesc *r_io_open(RIO *io, const char *file, int flags, int mode) {
	RIODesc *desc = __getioplugin (io, file, flags, mode);
	IO_IFDBG {
		if (desc && desc->plugin)
			eprintf ("Opened file: %s with %s\n", file, desc->plugin->name);
	}
	if (io->redirect)
		return NULL;
	/*if (desc) {
		fd = desc->fd;
	} else {
		fd = __io_posix_open (io, file, flags, mode);
		if (fd>=0){
			desc = r_io_desc_new (io->plugin,
				fd, file, flags, mode, NULL);
			IO_IFDBG {
				if (desc)
					eprintf ("Opened file: %s locallly\n", file);
			}
		}

	}*/
	if (desc) {
		r_io_desc_add (io, desc);
		r_io_set_fd (io, desc);
	} else 	eprintf ("Unable to open file: %s\n", file);

	return desc;
}

R_API RList *r_io_open_many(RIO *io, const char *file, int flags, int mode) {
	RIODesc *desc;
	RListIter *desc_iter = NULL;
	int fd;
	RList *list_fds = __getioplugin_many (io, file, flags, mode);

	if (!list_fds) return NULL;
	if (io->redirect) return NULL;

	r_list_foreach (list_fds, desc_iter, desc) {
		fd = -1;
		if (desc) fd = desc->fd;
		if (fd >= 0) r_io_desc_add (io, desc);
	}
	return list_fds;
}

R_API int r_io_set_fd(RIO *io, RIODesc *fd) {
	if (fd != NULL) {
		io->fd = fd;
		io->plugin = fd->plugin;
		return R_TRUE;
	}
	return R_FALSE;
}

static int r_io_update_desc (RIO *io, int fd) {
	RIODesc *desc = r_io_desc_get (io, fd);
	if (!desc)
		return R_FALSE;
	io->fd = desc;
	io->plugin = desc->plugin;
	return R_TRUE;
}

R_API int r_io_set_fdn(RIO *io, int fd) {
	if (fd != -1 && !(io->fd && fd == io->fd->fd))
		return r_io_update_desc (io, fd);
	else if (!io->fd && fd != -1)
		return r_io_update_desc (io, fd);
	return R_FALSE;
}

static inline int r_io_read_internal(RIO *io, ut8 *buf, int len) {
	int bytes_read = 0;
	const char *read_from = NULL;
	if (io->buffer_enabled){
		read_from = "buffer";
		bytes_read = r_io_buffer_read (io, io->off, buf, len);
	}
	if (io->fd && io->fd->plugin && io->fd->plugin->read){
		read_from = io->fd->plugin->name;
		bytes_read = io->fd->plugin->read (io, io->fd, buf, len);
	}
	else if (!io->fd) {
		eprintf ("Something really bad has happened, and r2 is going to die soon. sorry! :-(\n");
		read_from = "FAILED";
		bytes_read = 0;
	} else {
		read_from = "File";
		bytes_read = read (io->fd->fd, buf, len);
	}
	IO_IFDBG {
		if (io->fd) eprintf ("Data source: %s\n", io->fd->name);
		eprintf ("Asked for %d bytes, provided %d from %s\n", len, bytes_read, read_from);
	}
	return bytes_read;
}

R_API int r_io_read(RIO *io, ut8 *buf, int len) {
	int ret;
	if (io==NULL || io->fd == NULL)
		return -1;
	/* IGNORE check section permissions
	if (io->enforce_rwx && !(r_io_section_get_rwx (io, io->off) & R_IO_READ))
		return -1;
	 */
	ret = r_io_read_at (io, io->off, buf, len);
	if (ret>0) io->off += ret;
	return ret;
}

// XXX: this is buggy. must use seek+read
#define USE_CACHE 1
R_API int r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	ut64 paddr, last, last2;
	int ms, ret, l, olen = len, w = 0;

	io->off = addr;
	memset (buf, 0xff, len); // probably unnecessary

	if (io->buffer_enabled)
		return r_io_buffer_read (io, addr, buf, len);
	while (len>0) {
		last = r_io_section_next (io, addr+w);
		last2 = r_io_map_next (io, addr+w); // XXX: must use physical address
		if (last == (addr+w)) last = last2;
		//else if (last2<last) last = last2;
		l = (len > (last-addr+w))? (last-addr+w): len;
		if (l<1) l = len;
		{
			paddr = r_io_map_select (io, addr); // XXX
			paddr = w? r_io_section_vaddr_to_offset (io, addr+w): addr;
			r_io_map_select (io, addr); // XXX
			if (len>0 && l>len) l = len;
			addr = paddr-w;
			if (r_io_seek (io, paddr, R_IO_SEEK_SET)==UT64_MAX) {
				memset (buf+w, 0xff, l);
			}
		}
#if 0
		if (io->zeromap)
			if (!r_io_map_get (io, addr+w)) {
				if (addr==0||r_io_section_getv (io, addr+w)) {
					memset (buf+w, 0xff, l);
eprintf ("RETRERET\n");
					return -1;
				}
			}
#endif
		// XXX is this necessary?
		ms = r_io_map_select (io, addr+w);
		ret = r_io_read_internal (io, buf+w, l);
		if (ret<1) {
			memset (buf+w, 0xff, l); // reading out of file
			ret = 1;
		} else if (ret<l) {
			l = ret;
		}
#if USE_CACHE
		if (io->cached) {
			r_io_cache_read (io, addr+w, buf+w, len); //-w);
		} else if (r_list_length (io->maps) >1) {
			if (!io->debug && ms>0) {
				//eprintf ("FAIL MS=%d l=%d d=%d\n", ms, l, d);
				/* check if address is vaddred in sections */
				ut64 o = r_io_section_offset_to_vaddr (io, addr+w);
				if (o == UT64_MAX) {
					ut64 o = r_io_section_vaddr_to_offset (io, addr+w);
					if (o == UT64_MAX)
						memset (buf+w, 0xff, l);
				}
				break;
			}
		}
#endif
		w += l;
		len -= l;
	}
	return olen;
}

R_API ut64 r_io_read_i(RIO *io, ut64 addr, int sz, int endian) {
	ut64 ret = 0LL;
	ut8 buf[8];
	sz = R_DIM (sz, 1, 8);
	if (sz != r_io_read_at (io, addr, buf, sz))
		return UT64_MAX;
	r_mem_copyendian ((ut8*)&ret, buf, sz, endian);
	return ret;
}

R_API int r_io_resize(RIO *io, ut64 newsize) {
	if (io->plugin && io->plugin->resize)
		return io->plugin->resize (io, io->fd, newsize);
	else if (io->plugin) return R_FALSE;
	else ftruncate (io->fd->fd, newsize);
	return R_TRUE;
}

R_API int r_io_extend(RIO *io, ut64 size) {
	ut64 curr_off = io->off;
	ut64 cur_size = r_io_size (io), tmp_size = cur_size-size;
	ut8 *buffer = NULL;

	if (!size) return R_FALSE;

	if (io->plugin && io->plugin->extend)
		return io->plugin->extend (io, io->fd, size);

	if (!r_io_resize (io, size+cur_size)) return R_FALSE;

	if (cur_size < size) {
		tmp_size = size - cur_size;
	}

	buffer = malloc (tmp_size);
	// shift the bytes over by size
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	r_io_read (io, buffer, tmp_size);
	// move/write the bytes
	r_io_seek (io, curr_off+size, R_IO_SEEK_SET);
	r_io_write (io, buffer, tmp_size);
	// zero out new bytes
	if (cur_size < size) {
		free (buffer);
		buffer = malloc (size);
	}
	memset (buffer, 0, size);
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	r_io_write (io, buffer, size);
	// reset the cursor
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	free (buffer);
	return R_TRUE;
}

R_API int r_io_extend_at(RIO *io, ut64 addr, ut64 size) {

	if (!size) return R_FALSE;
	r_io_seek (io, addr, R_IO_SEEK_SET);
	return 	r_io_extend (io, size);
}

R_API int r_io_set_write_mask(RIO *io, const ut8 *buf, int len) {
	int ret = R_FALSE;
	if (len>0) {
		io->write_mask_fd = io->fd->fd;
		io->write_mask_buf = (ut8 *)malloc (len);
		memcpy (io->write_mask_buf, buf, len);
		io->write_mask_len = len;
		ret = R_TRUE;
	} else io->write_mask_fd = -1;
	return ret;
}

R_API int r_io_write(struct r_io_t *io, const ut8 *buf, int len) {
	int i, ret = -1;
	ut8 *data = NULL;

	/* check section permissions */
	if (io->enforce_rwx && !(r_io_section_get_rwx (io, io->off) & R_IO_WRITE))
		return -1;

	if (io->cached) {
		ret = r_io_cache_write (io, io->off, buf, len);
		if (ret == len)
			return len;
		if (ret > 0) {
			len -= ret;
			buf += ret;
		}
	}

	/* TODO: implement IO cache here. to avoid dupping work on vm for example */

	/* apply write binary mask */
	if (io->write_mask_fd != -1) {
		data = malloc (len);
		r_io_seek (io, io->off, R_IO_SEEK_SET);
		r_io_read (io, data, len);
		r_io_seek (io, io->off, R_IO_SEEK_SET);
		for (i=0; i<len; i++)
			data[i] = buf[i] & \
				io->write_mask_buf[i%io->write_mask_len];
		buf = data;
	}

	r_io_map_select (io, io->off);

	if (io->plugin) {
		if (io->plugin->write)
			ret = io->plugin->write (io, io->fd, buf, len);
		else eprintf ("r_io_write: io handler with no write callback\n");
	} else {
		ret = write (io->fd->fd, buf, len);
	}
	if (ret == -1)
		eprintf ("r_io_write: cannot write on fd %d\n", io->fd->fd);
	else
		io->off += ret;
	if (data)
		free (data);
	return ret;
}

R_API int r_io_write_at(RIO *io, ut64 addr, const ut8 *buf, int len) {
	if (r_io_seek (io, addr, R_IO_SEEK_SET) == UT64_MAX)
		return -1;
	return r_io_write (io, buf, len);
}

R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence) {
	int posix_whence = SEEK_SET;
	ut64 ret = UT64_MAX;
	if (io->buffer_enabled) {
		io->off = offset;
		return offset;
	}
	switch (whence) {
	case R_IO_SEEK_SET:
		posix_whence = SEEK_SET;
		ret = offset;
		break;
	case R_IO_SEEK_CUR:
//		offset += io->off;
		posix_whence = SEEK_CUR;
		ret = offset+io->off;
		break;
	case R_IO_SEEK_END:
		//offset = UT64_MAX; // XXX: depending on io bits?
		ret = UT64_MAX;
		posix_whence = SEEK_END;
		break;
	}
	if (io == NULL)
		return ret;
	// XXX: list_empty trick must be done in r_io_set_va();
	//eprintf ("-(seek)-> 0x%08llx\n", offset);
	if (!io->debug && io->va && !r_list_empty (io->sections)) {
		ut64 o = r_io_section_vaddr_to_offset (io, offset);
		if (o != UT64_MAX)
			offset = o;
	//	eprintf ("-(vadd)-> 0x%08llx\n", offset);
	}
	// if resolution fails... just return as invalid address
	if (offset==UT64_MAX)
		return UT64_MAX;
	if (io->fd != NULL) {
		if (io->plugin && io->plugin->lseek)
			ret = io->plugin->lseek (io, io->fd, offset, whence);
		// XXX can be problematic on w32..so no 64 bit offset?
		else ret = (ut64)lseek (io->fd->fd, offset, posix_whence);
		if (ret != UT64_MAX) {
			if (whence == R_IO_SEEK_SET)
				io->off = offset; // FIX linux-arm-32-bs at 0x10000
			else io->off = ret;
			// XXX this can be tricky.. better not to use this .. must be deprecated
			// r_io_sundo_push (io);
			ret = (!io->debug && io->va && !r_list_empty (io->sections))?
				r_io_section_offset_to_vaddr (io, io->off) : io->off;
		} //else eprintf ("r_io_seek: cannot seek to %"PFMT64x"\n", offset);
	} //else { eprintf ("r_io_seek: null fd\n"); }
	return ret;
}

R_API ut64 r_io_fd_size(RIO *io, int fd){
	RIODesc *desc = r_io_desc_get (io, fd);
	return r_io_desc_size (io, desc);
}

R_API ut64 r_io_size(RIO *io) {
	int iova;
	ut64 size, here;
	if (!io) return 0LL;
	if (r_io_is_listener (io))
		return UT64_MAX;
	iova = io->va;
	io->va = 0;
	here = r_io_seek (io, 0, R_IO_SEEK_CUR);
	size = r_io_seek (io, 0, R_IO_SEEK_END);
	io->va = iova;
	r_io_seek (io, here, R_IO_SEEK_SET);
	return size;
}

R_API int r_io_system(RIO *io, const char *cmd) {
	int ret = -1;
	if (io->plugin && io->plugin->system)
		ret = io->plugin->system (io, io->fd, cmd);
	return ret;
}

R_API int r_io_close(RIO *io, RIODesc *fd) {
	if (io == NULL || fd == NULL)
		return -1;
	int nfd = fd->fd;
	if (r_io_set_fd (io, fd)) {
		RIODesc *desc = r_io_desc_get (io, fd->fd);
		if (desc) {
			r_io_map_del (io, fd->fd);
			r_io_plugin_close (io, fd->fd, io->plugin);
			if (io->plugin && io->plugin->close)
				return io->plugin->close (desc);
			r_io_desc_del (io, desc->fd);
		}
	}
	io->fd = NULL; // unset current fd
	return close (nfd);
}

ut64 r_io_desc_seek (RIO *io, RIODesc *desc, ut64 offset, int whence) {
	RIOPlugin *plugin = desc ? desc->plugin : NULL;
	if (!plugin) return UT64_MAX;
	return plugin->lseek (io, desc, 0, SEEK_SET);
}

R_API int r_io_bind(RIO *io, RIOBind *bnd) {
	bnd->io = io;
	bnd->init = R_TRUE;
	bnd->get_io = r_io_bind_get_io;
	bnd->read_at = r_io_read_at;
	bnd->write_at = r_io_write_at;
	bnd->size = r_io_size;
	bnd->seek = r_io_seek;

	bnd->desc_open = r_io_open;
	bnd->desc_close = r_io_close;
	bnd->desc_read = r_io_desc_read;
	bnd->desc_size = r_io_desc_size;
	bnd->desc_seek = r_io_desc_seek;
	bnd->desc_get_by_fd = r_io_desc_get;
	return R_TRUE;
}

R_API int r_io_accept(RIO *io, int fd) {
	if (r_io_is_listener (io) && io->plugin && io->plugin->accept)
		return io->plugin->accept (io, io->fd, fd);
	return R_FALSE;
}

/* moves bytes up (+) or down (-) within the specified range */
R_API int r_io_shift(RIO *io, ut64 start, ut64 end, st64 move) {
	ut8 *buf;
	ut64 chunksize = 0x10000;
	ut64 rest, src, shiftsize = r_num_abs (move);
	if (!shiftsize || (end-start) <= shiftsize) return R_FALSE;
	rest = (end-start) - shiftsize;

	if (!(buf = malloc (chunksize))) return R_FALSE;

	if (move>0) src = end-shiftsize;
	else src = start+shiftsize;

	while (rest>0) {
		if (chunksize>rest) chunksize=rest;
		if (move>0) src -= chunksize;

		r_io_read_at (io, src, buf, chunksize);
		r_io_write_at (io, src+move, buf, chunksize);

		if (move<0) src += chunksize;
		rest -= chunksize;
	}
	free (buf);
	return R_TRUE;
}

R_API int r_io_create (RIO *io, const char *file, int mode, int type) {
	if (io->plugin && io->plugin->create)
		return io->plugin->create (io, file, mode, type);
	if (type == 'd'|| type == 1)
		return r_sys_mkdir (file);
	return r_sandbox_creat (file, mode)? R_FALSE: R_TRUE;
}

R_API void r_io_sort_maps (RIO *io) {
	r_list_sort (io->maps, (RListComparator) r_io_map_sort);
}

static ut8 * r_io_desc_read (RIO *io, RIODesc * desc, ut64 *out_sz) {
	ut8 *buf_bytes = NULL;
	ut64 off = io->off;
	RIOPlugin *plugin = desc ? desc->plugin : NULL;

	*out_sz = r_io_desc_size (io, desc);

	if (*out_sz == UT64_MAX) return buf_bytes;

	buf_bytes = malloc (*out_sz);

	if (!buf_bytes || !desc->plugin->read (io, desc, buf_bytes, *out_sz)) {
		free (buf_bytes);
		io->off = off;
		return R_FALSE;
	}
	io->off = off;
	return buf_bytes;
}

static RIO * r_io_bind_get_io(RIOBind *bnd) {
	return bnd ? bnd->io : NULL;
}
