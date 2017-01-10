#include <r_io.h>
#include <sdb.h>
#include <string.h>

R_API int r_io_desc_init (RIO *io)
{
	if (!io || io->files)
		return false;
	io->files = sdb_new0 ();
	return true;
}

//shall be used by plugins for creating descs
R_API RIODesc *r_io_desc_new (RIOPlugin *plugin, int fd, char *uri, int flags, int mode, void *data)	//XXX kill mode
{
	RIODesc *desc = NULL;
	if (!plugin || !uri)
		return NULL;
	desc = R_NEW0 (RIODesc);
	desc->plugin = plugin;
	desc->fd = fd;
	desc->data = data;
	desc->flags = flags;
	desc->uri = strdup (uri);			//because the uri-arg may live on the stack
	return desc;
}

R_API void r_io_desc_free (RIODesc *desc)
{
	if (desc) {
		free (desc->uri);
		free (desc->referer);
//		free (desc->plugin);
	}
	free (desc);
}

R_API int r_io_desc_add (RIO *io, RIODesc *desc)
{
	char s[64];
	if (!io || !io->files || !desc)
		return false;
	sdb_itoa ((ut64)desc->fd, s, 10);
	if (sdb_num_exists (io->files, s))		//check if fd already exists in db
		return false;
	sdb_num_set (io->files, s, (ut64)desc, 0);
	return sdb_num_exists (io->files, s);		//check if storage worked
}

R_API int r_io_desc_del (RIO *io, int fd)
{
	char s[64];
	if (!io || !io->files)
		return false;
	sdb_itoa ((ut64)fd, s, 10);
	r_io_desc_free ((RIODesc *)sdb_num_get (io->files, s, NULL));
	if ((ut64)io->desc == sdb_num_get (io->files, s, NULL))
		io->desc = NULL;					//prevent evil segfaults
	return sdb_unset (io->files, s, 0);
}

R_API RIODesc *r_io_desc_get (RIO *io, int fd)
{
	char s[64];
	if (!io || !io->files)
		return NULL;
	sdb_itoa ((ut64)fd, s, 10);
	return (RIODesc *)sdb_num_get (io->files, s, NULL);
}

R_API int r_io_desc_use (RIO *io, int fd)
{
	RIODesc *desc;
	if (!(desc = r_io_desc_get (io, fd)))
		return false;
	io->desc = desc;
	return true;
}

R_API ut64 r_io_desc_seek (RIODesc *desc, ut64 offset, int whence)
{
	if (!desc || !desc->plugin || !desc->plugin->lseek)
		return (ut64)-1;
	return desc->plugin->lseek (desc->io, desc, offset, whence);
}

R_API ut64 r_io_desc_size (RIODesc *desc)
{
	ut64 off, ret;
	if (!desc || !desc->plugin || !desc->plugin->lseek)
		return 0LL;
	off = desc->plugin->lseek (desc->io, desc, 0LL, R_IO_SEEK_CUR);
	ret = desc->plugin->lseek (desc->io, desc, 0LL, R_IO_SEEK_END);
	desc->plugin->lseek (desc->io, desc, off, R_IO_SEEK_CUR);			//what to do if that seek fails?
	return ret;
}

int desc_fini_cb (void *user, const char *fd, const char *cdesc)
{
//	RIO *io = (RIO *)user;							//unused
	RIODesc *desc = (RIODesc *)(size_t)sdb_atoi (cdesc);
	if (!desc)
		return true;
	if (desc->plugin && desc->plugin->close)
		desc->plugin->close (desc);
	r_io_desc_free (desc);
	return true;
}

//closes all descs and frees all descs and io->files
R_API int r_io_desc_fini (RIO *io)
{
	int ret;
	if (!io || !io->files)
		return false;
	ret = sdb_foreach (io->files, desc_fini_cb, io);
	sdb_free (io->files);
	io->files = NULL;
	io->desc = NULL;							//no map-cleanup here, to keep it modular useable
	return ret;
}
