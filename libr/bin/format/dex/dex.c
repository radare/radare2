/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_types.h>
#include <r_util.h>
#include "dex.h"

char* r_bin_dex_get_version(struct r_bin_dex_obj_t* bin) {
	if (bin) {
		char *version = malloc (8);
		memset (version, 0, 8);
		memcpy (version, bin->b->buf + 4, 3);
		return version;
	}
	return NULL;
}

#define FAIL(x) { eprintf(x"\n"); goto fail; }
struct r_bin_dex_obj_t* r_bin_dex_new_buf(RBuffer *buf) {
	struct r_bin_dex_obj_t *bin = R_NEW0 (struct r_bin_dex_obj_t);
	int i;
	ut8 *bufptr;
	struct dex_header_t *dexhdr;
	if (!bin) {
		goto fail;
	}
	bin->size = buf->length;
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)) {
		goto fail;
	}
	/* header */
	if (bin->size < sizeof(struct dex_header_t))
		goto fail;
	bufptr = bin->b->buf;
	dexhdr = &bin->header;

	memcpy (&dexhdr->magic, bufptr, 8);
	dexhdr->checksum = r_read_le32 (bufptr + 8);
	memcpy (&dexhdr->signature, bufptr + 12, 20);
	dexhdr->size = r_read_le32 (bufptr + 32);
	dexhdr->header_size = r_read_le32 (bufptr + 36);
	dexhdr->endian = r_read_le32 (bufptr + 40);
	dexhdr->linksection_size = r_read_le32 (bufptr + 44);
	dexhdr->linksection_offset = r_read_le32 (bufptr + 48);
	dexhdr->map_offset = r_read_le32 (bufptr + 52);
	dexhdr->strings_size = r_read_le32 (bufptr + 56);
	dexhdr->strings_offset = r_read_le32 (bufptr + 60);
	dexhdr->types_size = r_read_le32 (bufptr + 64);
	dexhdr->types_offset = r_read_le32 (bufptr + 68);
	dexhdr->prototypes_size = r_read_le32 (bufptr + 72);
	dexhdr->prototypes_offset = r_read_le32 (bufptr + 76);
	dexhdr->fields_size = r_read_le32 (bufptr + 80);
	dexhdr->fields_offset = r_read_le32 (bufptr + 84);
	dexhdr->method_size = r_read_le32 (bufptr + 88);
	dexhdr->method_offset = r_read_le32 (bufptr + 92);
	dexhdr->class_size = r_read_le32 (bufptr + 96);
	dexhdr->class_offset = r_read_le32 (bufptr + 100);
	dexhdr->data_size = r_read_le32 (bufptr + 104);
	dexhdr->data_offset = r_read_le32 (bufptr + 108);

	/* strings */
//eprintf ("strings size: %d\n", dexhdr->strings_size);
	#define STRINGS_SIZE ((dexhdr->strings_size+1)*sizeof(ut32))
	bin->strings = (ut32 *) calloc (dexhdr->strings_size + 1, sizeof (ut32));
	if (!bin->strings) {
		goto fail;
	}
	if (dexhdr->strings_size > bin->size) {
		free (bin->strings);
		goto fail;
	}
	for (i = 0; i < dexhdr->strings_size; i++) {
		ut64 offset = dexhdr->strings_offset + i * sizeof (ut32);
		bin->strings[i] = r_read_le32 (bufptr + offset);
	}
	/* classes */
	int classes_size = dexhdr->class_size * sizeof (struct dex_class_t);
	if (dexhdr->class_offset + classes_size >= bin->size) {
		classes_size = bin->size - dexhdr->class_offset;
	}
	if (classes_size<0) {
		classes_size = 0;
	}
	dexhdr->class_size = classes_size / sizeof (struct dex_class_t);
	bin->classes = (struct dex_class_t *) malloc (classes_size);
	for (i = 0; i < dexhdr->class_size; i++) {
		ut64 offset = dexhdr->class_offset + i * sizeof (struct dex_class_t);
		bin->classes[i].class_id = r_read_le32 (bufptr + offset + 0);
		bin->classes[i].access_flags = r_read_le32 (bufptr + offset + 4);
		bin->classes[i].super_class = r_read_le32 (bufptr + offset + 8);
		bin->classes[i].interfaces_offset = r_read_le32 (bufptr + offset + 12);
		bin->classes[i].source_file = r_read_le32 (bufptr + offset + 16);
		bin->classes[i].anotations_offset = r_read_le32 (bufptr + offset + 20);
		bin->classes[i].class_data_offset = r_read_le32 (bufptr + offset + 24);
		bin->classes[i].static_values_offset = r_read_le32 (bufptr + offset + 28);
	}
//{ ut8 *b = (ut8*)&bin->methods; eprintf ("CLASS %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]); }

	/* methods */
	int methods_size = dexhdr->method_size * sizeof (struct dex_method_t);
	if (dexhdr->method_offset + methods_size >= bin->size) {
		methods_size = bin->size - dexhdr->method_offset;
	}
	if (methods_size < 0) {
		methods_size = 0;
	}
	dexhdr->method_size = methods_size / sizeof (struct dex_method_t);
	bin->methods = (struct dex_method_t *) calloc (methods_size, 1);
	for (i = 0; i < dexhdr->method_size; i++) {
		ut64 offset = dexhdr->method_offset + i * sizeof (struct dex_method_t);
		bin->methods[i].class_id = r_read_le16 (bufptr + offset + 0);
		bin->methods[i].proto_id = r_read_le16 (bufptr + offset + 2);
		bin->methods[i].name_id = r_read_le32 (bufptr + offset + 4);
	}

	/* types */
	int types_size = dexhdr->types_size * sizeof (struct dex_type_t);
	if (dexhdr->types_offset + types_size >= bin->size) {
		types_size = bin->size - dexhdr->types_offset;
	}
	if (types_size < 0) {
		types_size = 0;
	}
	dexhdr->types_size = types_size / sizeof (struct dex_type_t);
	bin->types = (struct dex_type_t *) calloc (types_size, 1);
	for (i = 0; i < dexhdr->types_size; i++) {
		ut64 offset = dexhdr->types_offset + i * sizeof (struct dex_type_t);
		bin->types[i].descriptor_id = r_read_le32 (bufptr + offset);
	}

	/* fields */
	int fields_size = dexhdr->fields_size * sizeof (struct dex_field_t);
	if (dexhdr->fields_offset + fields_size >= bin->size) {
		fields_size = bin->size - dexhdr->fields_offset;
	}
	if (fields_size<0) {
		fields_size = 0;
	}
	dexhdr->fields_size = fields_size / sizeof (struct dex_field_t);
	bin->fields = (struct dex_field_t *) calloc (fields_size, 1);
	for (i = 0; i < dexhdr->fields_size; i++) {
		ut64 offset = dexhdr->fields_offset + i * sizeof (struct dex_field_t);
		bin->fields[i].class_id = r_read_le16 (bufptr + offset + 0);
		bin->fields[i].type_id = r_read_le16 (bufptr + offset + 2);
		bin->fields[i].name_id = r_read_le32 (bufptr + offset + 4);
	}
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
	ut8 len = dex_uleb128_len (ptr);
	const ut8 *in = ptr + len - 1;
	ut32 result = 0;
	ut8 shift = 0;
	ut8 byte;

	while(shift < 29 && len > 0) {
		byte = *(in--);
		result |= (byte & 0x7f << shift);
		if (byte > 0x7f)
			break;
		shift += 7;
		len--;
	}
	return result;
}

#define LEB_MAX_SIZE 6
int dex_uleb128_len (const ut8 *ptr) {
	int i = 1, result = *(ptr++);
	while (result > 0x7f && i <= LEB_MAX_SIZE) {
		result = *(ptr++);
		i++;
	}
	return i;
}

#define SIG_EXTEND(X,Y) X = (X << Y) >> Y
int dex_read_sleb128 (const char *ptr) {
	int cur, result;
	ut8 len = dex_uleb128_len (ptr);
	ptr += len - 1;
	result = *(ptr--);

	if (result <= 0x7f) {
		SIG_EXTEND (result, 25);
	} else {
		cur = *(ptr--);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur <= 0x7f) {
			SIG_EXTEND (result, 18);
		} else {
			cur = *(ptr--);
			result |= (cur & 0x7f) << 14;
			if (cur <= 0x7f) {
				SIG_EXTEND (result, 11);
			} else {
				cur = *(ptr--);
				result |= (cur & 0x7f) << 21;
				if (cur <= 0x7f) {
					SIG_EXTEND (result, 4);
				} else {
					cur = *(ptr--);
					result |= cur << 28;
				}
			}
		}
	}
	return result;
}
