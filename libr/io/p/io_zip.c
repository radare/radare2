/* radare - LGPL - Copyright 2012-2016 - pancake
   io_zip.c rewrite: Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com>
 */

// TODO: wrap with r_sandbox api

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_cons.h>
#include <zip.h>


typedef enum {
	R_IO_PARENT_ZIP = 0x0001,
	R_IO_CHILD_FILE = 0x0002,
	R_IO_NEW_FILE = 0x0004,
	R_IO_EXISTING_FILE = 0x0008,
	R_IO_MODIFIED_FILE = 0x0010,
	R_IO_DELETED_FILE = 0x0020,
} R_IO_ZIP_ARCHIVE_TYPE;

typedef struct r_io_zip_uri_const_t {
	const char *name;
	ut32 len;
} RIOZipConstURI;

static RIOZipConstURI ZIP_URIS[] = {
	{"zip://", 6},
	{"apk://", 6},
	{"ipa://", 6},
	{"jar://", 6},
	{NULL, 0}
};

static RIOZipConstURI ZIP_ALL_URIS[] = {
	{"zipall://", 9},
	{"apkall://", 9},
	{"ipaall://", 9},
	{"jarall://", 9},
	{NULL, 0}
};

typedef struct r_io_zfo_t {
	char * name;
	char * archivename;
	int mode;
	int rw;
	int fd;
	int opened;
	ut64 entry;
	int flags;
	ut8 modified;
	RBuffer *b;
	char *password;
	ut8 encryption_value;
	RIO * io_backref;
} RIOZipFileObj;

static int r_io_zip_has_uri_substr(const char *file) {
	return (file && strstr (file, "://"));
}

static int r_io_zip_check_uri_many(const char *file) {
	int i;
	if (r_io_zip_has_uri_substr (file)) {
		for (i = 0; ZIP_ALL_URIS[i].name != NULL; i++) {
			if (!strncmp (file, ZIP_ALL_URIS[i].name, ZIP_ALL_URIS[i].len) && file[ZIP_ALL_URIS[i].len]) {
				return true;
			}
		}
	}
	return false;
}

static int r_io_zip_check_uri(const char *file) {
	int i;
	if (r_io_zip_has_uri_substr (file)) {
		for (i = 0; ZIP_URIS[i].name != NULL; i++) {
			if (!strncmp (file, ZIP_URIS[i].name, ZIP_URIS[i].len) && file[ZIP_URIS[i].len]) {
				return true;
			}
		}
	}
	return false;
}

static bool r_io_zip_plugin_open(RIO *io, const char *file, bool many) {
	if (io && file) {
		if (many) {
			return r_io_zip_check_uri_many (file);
		}
		return r_io_zip_check_uri (file);
	}
	return false;
}

struct zip *r_io_zip_open_archive(const char *archivename, ut32 flags, int mode, int rw) {
	struct zip * zipArch = NULL;
	int zip_errorp;
	if (!archivename) {
		return NULL;
	}
	if ((zipArch = zip_open (archivename, flags, &zip_errorp))) {
		return zipArch;
	}
	if (zip_errorp == ZIP_ER_INVAL) {
		eprintf ("ZIP File Error: Invalid file name (NULL).\n");
	} else if (zip_errorp == ZIP_ER_OPEN) {
		eprintf ("ZIP File Error: File could not be opened file name.\n");
	} else if (zip_errorp == ZIP_ER_NOENT) {
		eprintf ("ZIP File Error: File does not exist.\n");
	} else if (zip_errorp == ZIP_ER_READ) {
		eprintf ("ZIP File Error: Read error occurred.\n");
	} else if (zip_errorp == ZIP_ER_NOZIP) {
		eprintf ("ZIP File Error: File is not a valid ZIP archive.\n");
	} else if (zip_errorp == ZIP_ER_INCONS) {
		eprintf ("ZIP File Error: ZIP file had some inconsistencies archive.\n");
	} else {
		eprintf ("ZIP File Error: Something bad happened, get your debug on.\n");
	}
	return NULL;
}

static int r_io_zip_slurp_file(RIOZipFileObj *zfo) {
	struct zip_file *zFile = NULL;
	struct zip *zipArch;
	struct zip_stat sb;
	bool res = false;
	if (!zfo) {
		return res;
	}
	zipArch = r_io_zip_open_archive (
		zfo->archivename, zfo->flags,
		zfo->mode, zfo->rw);

	if (zipArch && zfo && zfo->entry != -1) {
		zFile = zip_fopen_index (zipArch, zfo->entry, 0);
		if (!zfo->b) {
			zfo->b = r_buf_new ();
		}
		zip_stat_init (&sb);
		if (zFile && zfo->b && !zip_stat_index (zipArch, zfo->entry, 0, &sb)) {
			ut8 *buf = malloc (sb.size);
			memset (buf, 0, sb.size);
			if (buf) {
				zip_fread (zFile, buf, sb.size);
				r_buf_set_bytes (zfo->b, buf, sb.size);
				res = true;
				zfo->opened = true;
				free (buf);
			}
		}
		zip_fclose (zFile);
	}
	zip_close (zipArch);
	return res;
}

RList * r_io_zip_get_files(char *archivename, ut32 flags, int mode, int rw) {
	struct zip *zipArch = r_io_zip_open_archive (archivename, flags, mode, rw);
	ut64 num_entries = 0, i = 0;
	RList *files = NULL;
	struct zip_stat sb;
	char *name;
	if (zipArch) {
		files = r_list_newf (free);
		if (!files) {
			zip_close (zipArch);
			return NULL;
		}
		num_entries = zip_get_num_files (zipArch);
		for (i = 0; i < num_entries; i++) {
			zip_stat_init (&sb);
			zip_stat_index (zipArch, i, 0, &sb);
			if ((name = strdup (sb.name))) {
				r_list_append (files, name);
			}
		}
	}
	zip_close (zipArch);
	return files;
}

int r_io_zip_flush_file(RIOZipFileObj *zfo) {
	int res = false;
	struct zip * zipArch;

	if (!zfo) return res;

	zipArch = r_io_zip_open_archive (
		zfo->archivename, zfo->flags, zfo->mode, zfo->rw);
	if (!zipArch)
		return res;

	struct zip_source *s = zip_source_buffer (zipArch, zfo->b->buf, zfo->b->length, 0);
	if (s && zfo->entry != -1) {
		if (zip_replace(zipArch, zfo->entry, s) == 0) {
			res = true;
		}
	} else if (s && zfo->name) {
		if (zip_add (zipArch, zfo->name, s) == 0) {
			zfo->entry = zip_name_locate (zipArch, zfo->name, 0);
			res = true;
		}
	}
	// s (zip_source) is freed when the archive is closed, i think - dso
	zip_close (zipArch);
	if (s) zip_source_free (s);
	return res;
}

static void r_io_zip_free_zipfileobj(RIOZipFileObj *zfo) {
	if (!zfo) return;
	if (zfo->modified) {
		r_io_zip_flush_file (zfo);
	}
	free (zfo->name);
	free (zfo->password);
	r_buf_free (zfo->b);
	free (zfo);
}

RIOZipFileObj *r_io_zip_create_new_file(const char *archivename, const char *filename, struct zip_stat *sb, ut32 flags, int mode, int rw) {
	RIOZipFileObj *zfo = R_NEW0 (RIOZipFileObj);
	if (zfo) {
		zfo->b = r_buf_new ();
		zfo->archivename = strdup (archivename);
		zfo->name = strdup (sb? sb->name: filename);
		zfo->entry = !sb ? -1 : sb->index;
		zfo->fd = r_num_rand (0xFFFF); // XXX: Use r_io_fd api
		zfo->flags = flags;
		zfo->mode = mode;
		zfo->rw = rw;
	}
	return zfo;
}

/* The file can be a file in the archive or ::[num].  */
RIOZipFileObj* r_io_zip_alloc_zipfileobj(const char *archivename, const char *filename, ut32 flags, int mode, int rw) {
	RIOZipFileObj *zfo = NULL;
	ut64 i, num_entries;
	struct zip_stat sb;
	struct zip *zipArch = r_io_zip_open_archive (archivename, flags, mode, rw);
	if (!zipArch) return NULL;
	num_entries = zip_get_num_files (zipArch);

	for (i = 0; i < num_entries; i++) {
		zip_stat_init (&sb);
		zip_stat_index (zipArch, i, 0, &sb);
		if (sb.name != NULL) {
			if (strcmp (sb.name, filename) == 0) {
				zfo = r_io_zip_create_new_file (
					archivename, filename, &sb,
					flags, mode, rw);
				r_io_zip_slurp_file (zfo);
				break;
			}
		}
	}
	if (!zfo) {
		zfo = r_io_zip_create_new_file (archivename,
			filename, NULL, flags, mode, rw);
	}
	zip_close (zipArch);
	return zfo;
}

// Below this line are the r_io_zip plugin APIs
static RList *r_io_zip_open_many(RIO *io, const char *file, int rw, int mode) {
	RList *list_fds = NULL;
	RListIter *iter;
	RList *filenames = NULL;
	RIODesc *res = NULL;
	RIOZipFileObj *zfo = NULL;
	char *filename_in_zipfile, *zip_filename = NULL, *zip_uri;

	if (!r_io_zip_plugin_open (io, file, true)) {
		return NULL;
	}

	zip_uri = strdup (file);
	if (!zip_uri) return NULL;
	// 1) Tokenize to the '//' and find the base file directory ('/')
	zip_filename = strstr(zip_uri, "//");
	if (zip_filename && zip_filename[2]) {
		if (zip_filename[0] && zip_filename[0] == '/' &&
			zip_filename[1] && zip_filename[1] == '/' ) {
			*zip_filename++ = 0;
		}
		*zip_filename++ = 0;
	} else {
		free (zip_uri);
		return NULL;
	}

	filenames = r_io_zip_get_files(zip_filename, 0, mode, rw );

	if (!filenames) {
		free (zip_uri);
		return NULL;
	}

	list_fds = r_list_new ();
	r_list_foreach (filenames, iter, filename_in_zipfile) {
		size_t v = strlen (filename_in_zipfile);

		if (filename_in_zipfile[v-1] == '/') continue;

		zfo = r_io_zip_alloc_zipfileobj (zip_filename,
			filename_in_zipfile, ZIP_CREATE, mode, rw);


		if (zfo && zfo->entry == -1)
			eprintf ("Warning: File did not exist, creating a new one.\n");

		if (zfo) {
			zfo->io_backref = io;
			res = r_io_desc_new (io, &r_io_plugin_zip,
				zfo->name, rw, mode, zfo);
		}
		r_list_append (list_fds, res);
	}

	free(zip_uri);
	r_list_free (filenames);
	return list_fds;
}

char * r_io_zip_get_by_file_idx(const char * archivename, const char *idx, ut32 flags, int mode, int rw) {
	char *filename = NULL;
	ut64 i, num_entries;
	ut32 file_idx = -1;
	struct zip_stat sb;
	struct zip * zipArch = r_io_zip_open_archive (archivename, flags, mode, rw);
	if (!idx || !zipArch) {
		zip_close (zipArch);
		return filename;
	}
	num_entries = zip_get_num_files (zipArch);
	file_idx = atoi (idx);
	if ((file_idx == 0 && idx[0] != '0') || (file_idx >= num_entries)) {
		zip_close (zipArch);
		return filename;
	}
	for (i = 0; i < num_entries; i++) {
		zip_stat_init (&sb);
		zip_stat_index (zipArch, i, 0, &sb );
		if (file_idx == i) {
			filename = strdup (sb.name);
			break;
		}
	}
	zip_close (zipArch);
	return filename;
}

static RIODesc *r_io_zip_open(RIO *io, const char *file, int rw, int mode) {
	RIODesc *res = NULL;
	char *pikaboo;
	RIOZipFileObj *zfo = NULL;
	char *zip_uri = NULL, *zip_filename = NULL, *filename_in_zipfile = NULL;
	bool allocated = false;

	if (!r_io_zip_plugin_open (io, file, false)) {
		return NULL;
	}
	zip_uri = strdup (file);
	if (!zip_uri) return NULL;
	pikaboo = strstr (zip_uri, "://");
	if (pikaboo) {
		allocated = false;
		zip_filename = strstr (pikaboo + 3, "//");
		// 1) Tokenize to the '//' and find the base file directory ('/')
		if (!zip_filename) {
			if (!strncmp (zip_uri, "apk://", 6)) {
				zip_filename = r_str_newf ("//%s//classes.dex", pikaboo + 3);
				allocated = true;
			} else if (!strncmp (zip_uri, "ipa://", 6)) {
				RList *files = NULL;
				RListIter *iter;
				char *name;
				zip_filename = pikaboo + 3;
				files = r_io_zip_get_files (zip_filename, 0, mode, rw );

				if (files) {
					r_list_foreach (files, iter, name) {
						/* Find matching file */
						char *bin_name = strstr (name, ".app/");
						if (bin_name) {
							const char *slash = r_str_rchr (name, bin_name, '/');
							if (slash) {
								bin_name = r_str_ndup (slash + 1, (bin_name - slash) -1);
								char *chkstr = r_str_newf ("Payload/%s.app/%s", bin_name);
								if (!strcmp (name, chkstr)) {
									zip_filename = r_str_newf ("//%s", chkstr);
									allocated = true;
									free (chkstr);
									free (bin_name);
									break;
								}
								free (chkstr);
								free (bin_name);
							}
						}
					}
					r_list_free(files);
				}
			} else {
				zip_filename = pikaboo + 1;
			}
		}
	}
	if (zip_filename && zip_filename[1] && zip_filename[2]) {
		if (zip_filename[0] && zip_filename[0] == '/' &&
			zip_filename[1] && zip_filename[1] == '/' ) {
			*zip_filename++ = 0;
		}
		*zip_filename++ = 0;

		// check for // for file in the archive
		if ( (filename_in_zipfile = strstr (zip_filename, "//")) && filename_in_zipfile[2]) {
			// null terminating uri to filename here.
			*filename_in_zipfile++ = 0;
			*filename_in_zipfile++ = 0;
			filename_in_zipfile = strdup (filename_in_zipfile);
		// check for :: index
		} else if ((filename_in_zipfile = strstr (zip_filename, "::")) &&
			 		filename_in_zipfile[2]) {
			// null terminating uri to filename here.
			*filename_in_zipfile++ = 0;
			*filename_in_zipfile++ = 0;
			filename_in_zipfile = r_io_zip_get_by_file_idx (
				zip_filename, filename_in_zipfile,
				ZIP_CREATE, mode, rw);
		} else {
			filename_in_zipfile = r_str_newf ("%s", zip_filename);
			if (allocated) {
				free (zip_filename);
			}
			zip_filename = strdup (pikaboo + 3);
			allocated = true;
			if (!strcmp (zip_filename, filename_in_zipfile)) {
				//R_FREE (zip_filename);
				R_FREE (filename_in_zipfile);
			}
		}
	}

	if (!zip_filename) {// && !filename_in_zipfile) {
		//free (zip_uri);
		eprintf ("usage: zip:///path/to/archive//filepath\n"
			"usage: zip:///path/to/archive::[number]\n"
			"Archive was not found.\n");
		//return res;
	}

	// Failed to find the file name the archive.
	if (!filename_in_zipfile) {
		RList *files = NULL;
		RListIter *iter;
		char *name;
		//eprintf("usage: zip:///path/to/archive//filepath\n");
		files = r_io_zip_get_files (zip_filename, 0, mode, rw);
		if (files) {
			ut32 i = 0;
			r_list_foreach (files, iter, name) {
				io->cb_printf ("%d %s\n", i, name);
				i++;
			}
			r_list_free (files);
		}
		goto done;
	}
	//eprintf("After parsing the given uri: %s\n", file);
	//eprintf("Zip filename the given uri: %s\n", zip_filename);
	//eprintf("File in the zip: %s\n", filename_in_zipfile);
	zfo = r_io_zip_alloc_zipfileobj (zip_filename,
		filename_in_zipfile, ZIP_CREATE, mode, rw);

	if (zfo) {
		if (zfo->entry == -1) {
			eprintf ("Warning: File did not exist, creating a new one.\n");
		}
		zfo->io_backref = io;
		res = r_io_desc_new (io, &r_io_plugin_zip,
			zfo->name, rw, mode, zfo);
	}

	if (!res) {
		eprintf ("Failed to open the archive %s and file %s\n",
			zip_filename, filename_in_zipfile);
		//free (zfo); zfo is already freed by r_io_desc_new	//WTF
		r_io_desc_free (res);
		res = NULL;
	}
done:
	free (filename_in_zipfile);
	free (zip_uri);
	if (allocated) {
		free (zip_filename);
	}
	return res;
}

static ut64 r_io_zip_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOZipFileObj *zfo;
	ut64 seek_val = 0;

	if (!fd || !fd->data) {
		return -1;
	}

	zfo = fd->data;
	seek_val = zfo->b->cur;

	switch (whence) {
	case SEEK_SET:
		seek_val = (zfo->b->length < offset) ?
			zfo->b->length : offset;
		zfo->b->cur = io->off = seek_val;
		return seek_val;
	case SEEK_CUR:
		seek_val = (zfo->b->length < (offset + zfo->b->cur)) ?
			zfo->b->length : offset + zfo->b->cur;
		zfo->b->cur = io->off = seek_val;
		return seek_val;
	case SEEK_END:
		seek_val = zfo->b->length;
		zfo->b->cur = io->off = seek_val;
		return seek_val;
	}
	return seek_val;
}

static int r_io_zip_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOZipFileObj *zfo = NULL;
	if (!fd || !fd->data || !buf)
		return -1;
	zfo = fd->data;
	if (zfo->b->length < io->off)
		io->off = zfo->b->length;
	return r_buf_read_at (zfo->b, io->off, buf, count);
}

static int r_io_zip_realloc_buf(RIOZipFileObj *zfo, int count) {
	int res = false;
	if (count >= 0 && zfo->b->cur + count > zfo->b->length) {
		RBuffer *buffer = r_buf_new ();
		if (!buffer) {
			return false;
		}
		buffer->buf = malloc (zfo->b->cur + count );
		if (!buffer->buf) {
			r_buf_free (buffer);
			return false;
		}
		buffer->length = zfo->b->cur + count;
		memcpy (buffer->buf, zfo->b->buf, zfo->b->length);
		memset (buffer->buf + zfo->b->length, 0, count);
		buffer->cur = zfo->b->cur;
		r_buf_free (zfo->b);
		zfo->b = buffer;
		res = true;
	}
	return res;
}

static bool r_io_zip_truncate_buf(RIOZipFileObj *zfo, int size) {
	if (zfo->b->length < size) {
		return r_io_zip_realloc_buf (zfo, size - zfo->b->length);
	}
	if (size > 0) {
		ut8 *buf = malloc (size);
		if (!buf) {
			return false;
		}
		memcpy (buf, zfo->b->buf, size);
		free (zfo->b->buf);
		zfo->b->buf = buf;
		zfo->b->length = size;
	} else {
		memset (zfo->b->buf, 0, zfo->b->length);
		zfo->b->length = 0;
	}
	return true;
}

static bool r_io_zip_resize(RIO *io, RIODesc *fd, ut64 size) {
	RIOZipFileObj *zfo;
	if (!fd || !fd->data) {
		return false;
	}
	zfo = fd->data;
	if (r_io_zip_truncate_buf (zfo, size)) {
		zfo->modified = 1;
		r_io_zip_flush_file (zfo);
		return true;
	}
	return false;
}

static int r_io_zip_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOZipFileObj *zfo;
	int ret = 0;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	zfo = fd->data;
	if (!(zfo->flags & R_IO_WRITE)) {
		return -1;
	}
	if (zfo->b->cur + count >= zfo->b->length) {
		r_io_zip_realloc_buf (zfo, count);
	}
	if (zfo->b->length < io->off) {
		io->off = zfo->b->length;
	}
	zfo->modified = 1;
	ret = r_buf_write_at (zfo->b, io->off, buf, count);
	// XXX - Implement a flush of some sort, but until then, lets
	// just write through
	r_io_zip_flush_file (zfo);
	return ret;
}

static int r_io_zip_close(RIODesc *fd) {
	RIOZipFileObj *zfo;
	if (!fd || !fd->data) {
		return -1;
	}
	zfo = fd->data;
	r_io_zip_free_zipfileobj (zfo);
	zfo = fd->data = NULL;
	return 0;
}

RIOPlugin r_io_plugin_zip = {
	.name = "zip",
	.desc = "Open zip files [apk|ipa|zip|zipall]://[file//path]",
	.license = "BSD",
	.open = r_io_zip_open,
	.open_many = r_io_zip_open_many,
	.write = r_io_zip_write,
	.read = r_io_zip_read,
	.close = r_io_zip_close,
	.lseek = r_io_zip_lseek,
	.check = r_io_zip_plugin_open,
	.resize = r_io_zip_resize,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_zip,
	.version = R2_VERSION
};
#endif
