/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_io.h>
// TODO: to be deprecated.. this is slow and boring

R_API void r_io_desc_init(RIO *io) {
	io->files= r_list_new ();
	io->files->free = (RListFree)r_io_desc_free;
}

R_API void r_io_desc_fini(RIO *io) {
	r_list_free (io->files);
}

R_API ut64 r_io_desc_size(RIO *io, RIODesc *desc){
	RIODesc *old = NULL;
    	ut64 sz = -1;
	if (desc && io->desc != desc){
		old = io->desc;
		r_io_use_desc (io, desc);
	}
	if (desc) sz = r_io_size(io);
	if (old) r_io_use_desc (io, old);
	return sz;
}

R_API RIODesc *r_io_desc_new(RIOPlugin *plugin, int fd, const char *name, int flags, int mode, void *data) {
	RETURN_IO_DESC_NEW (plugin, fd, name, flags, mode, data);
}
#if 0
	int i;
	RIODesc *desc = R_NEW (RIODesc);
	if (!desc) return NULL;
	if (fd==-1) eprintf ("WARNING: r_io_desc_new with fd = -1\n");
	desc->state = R_IO_DESC_TYPE_OPENED;
	desc->name = strdup (name);
	if (desc->name == NULL) {
		free (desc);
		return NULL;
	}
	desc->plugin = plugin;
	desc->flags = flags;
	if (fd == -2) {
		ut8 *p = (ut8 *)&(desc->fd);
		desc->fd = ((int) ((size_t) desc) & 0xffffff);
		desc->fd = p[0];
		for (i=1; i<sizeof (desc->fd); i++)
			desc->fd ^= p[i];
	} else desc->fd = fd;
	desc->data = data;
	return desc;
#endif

R_API void r_io_desc_free(RIODesc *desc) {
	if (!desc) return;
	if (desc->io) {
		RIO* io = (RIO*)desc->io;
		desc->io = NULL;
		r_io_close (io, desc);
	}
	if (desc->plugin && desc->plugin->close)
		desc->plugin->close (desc);
	if (desc->name) {
		free (desc->name);
		desc->name = NULL;
	}
	memset (desc, 0, sizeof (RIODesc));
	//	free (desc); double free orw at
}

R_API int r_io_desc_add(RIO *io, RIODesc *desc) {
	RIODesc *foo = r_io_desc_get (io, desc->fd);
	if (!foo){
		desc->io = io;
		r_list_append (io->files, desc);
	}
	return foo? 1: 0;
}

R_API int r_io_desc_del(RIO *io, int fd) {
	RListIter *iter;
	RIODesc *d;
	/* No _safe loop necessary because we return immediately after the delete. */
	r_list_foreach (io->files, iter, d) {
		if (d->fd == fd) {
			r_list_delete (io->files, iter);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API RIODesc *r_io_desc_get(RIO *io, int fd) {
	RListIter *iter;
	RIODesc *d;
	if (fd<0)
		return NULL;
	r_list_foreach (io->files, iter, d) {
		if (d && d->fd == fd)
			return d;
	}
	return NULL;
}

R_API ut64 r_io_desc_seek (RIO *io, RIODesc *desc, ut64 offset) {
	RIOPlugin *plugin = desc ? desc->plugin : NULL;
	if (!plugin) return (ut64)lseek (desc->fd, offset, SEEK_SET);
	return plugin->lseek (io, desc, offset, SEEK_SET);
}

#if 0
// XXX: This must be deprecated in order to promote the cast of dataptr to ut32
R_API int r_io_desc_generate(struct r_io_t *io) {
	int fd;
	do fd = 0xf000 + rand ()%0xfff;
	while (r_io_desc_get(io, fd));
	return fd;
}
#endif
