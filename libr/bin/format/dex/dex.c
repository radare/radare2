/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_types.h>
#include <r_util.h>
#include "dex.h"

char* r_bin_dex_get_version(struct r_bin_dex_obj_t* bin) {
	// TODO: ripe!!! pas
	char *version = malloc (8);
	memset (version, 0, 8);
	memcpy (version, bin->b->buf+4, 3);
	return version;
}

#define FAIL(x) { eprintf(x); goto fail; }
struct r_bin_dex_obj_t* r_bin_dex_new_buf(RBuffer *buf) {
	struct r_bin_dex_obj_t *bin = R_NEW0 (struct r_bin_dex_obj_t);
	if (!bin) {
		goto fail;
	}
	bin->size = buf->length;
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		goto fail;
	}
	// XXX: this is not endian safe
	// XXX: no need to dup all data!! just pointers to the bin->b
	// XXX: return value not checked
	/* header */
	//r_buf_read_at (bin->b, 0, (ut8*)&bin->header, sizeof (struct dex_header_t));
	bin->header = (*(struct dex_header_t*)bin->b->buf);

	/* strings */
//eprintf ("strings size: %d\n", bin->header.strings_size);
	#define STRINGS_SIZE ((bin->header.strings_size+1)*sizeof(ut32))
	bin->strings = (ut32 *) calloc (bin->header.strings_size +1, sizeof (ut32));
	if (!bin->strings) {
		goto fail;
	}

	//bin->strings = bin->b->buf + bin->header.strings_offset;
	int left;
	bin->strings = r_buf_get_at (bin->b, bin->header.strings_offset, &left);
	if (left< STRINGS_SIZE) {
		FAIL ("Strings buffer is too small");
	}

#if 0
	r_buf_read_at (bin->b, bin->header.strings_offset, (ut8*)bin->strings,
			bin->header.strings_size * sizeof (ut32));
#endif
	/* classes */
	bin->classes = (struct dex_class_t *) malloc (bin->header.class_size *
			sizeof (struct dex_class_t) + 1);
	r_buf_read_at (bin->b, bin->header.class_offset, (ut8*)bin->classes,
			bin->header.class_size * sizeof (struct dex_class_t));
//{ ut8 *b = (ut8*)&bin->methods; eprintf ("CLASS %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]); }
	/* methods */
	bin->methods = (struct dex_method_t *) calloc (bin->header.method_size *
			sizeof (struct dex_method_t) + 1, 1);
	r_buf_read_at (bin->b, bin->header.method_offset, (ut8*)bin->methods,
			bin->header.method_size * sizeof (struct dex_method_t));
	/* types */
	bin->types = (struct dex_type_t *) calloc (bin->header.types_size *
			sizeof (struct dex_type_t) + 1, 1);
	r_buf_read_at (bin->b, bin->header.types_offset, (ut8*)bin->types,
			bin->header.types_size * sizeof (struct dex_type_t));
	/* fields */
	bin->fields = (struct dex_field_t *) calloc (bin->header.fields_size *
			sizeof (struct dex_field_t) + 1, 1);
	r_buf_read_at (bin->b, bin->header.fields_offset, (ut8*)bin->fields,
			bin->header.fields_size * sizeof (struct dex_field_t));
	return bin;
fail:
	if (bin) {
		r_buf_free (bin->b);
		free (bin);
	}
	return NULL;
}

// Move to r_util ??
int dex_read_uleb128 (const ut8 *ptr) {
	int cur, result = *(ptr++);

	if (result > 0x7f) {
		cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	return result;
}

#define LEB_MAX_SIZE 6
int dex_uleb128_len (const ut8 *ptr) {
	int i=1, result = *(ptr++);

	while (result > 0x7f && i <= LEB_MAX_SIZE) {
		result = *(ptr++);
		i++;
	}
	return i;
}

#define SIG_EXTEND(X,Y) X = (X << Y) >> Y
int dex_read_sleb128 (const char *ptr) {
	int cur, result = *(ptr++);

	if (result <= 0x7f) {
		SIG_EXTEND (result, 25);
	} else {
		cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur <= 0x7f) {
			SIG_EXTEND (result, 18);
		} else {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur <= 0x7f) {
				SIG_EXTEND (result, 11);
			} else {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur <= 0x7f) {
					SIG_EXTEND (result, 4);
				} else {
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	return result;
}
