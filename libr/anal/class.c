/* radare - LGPL - Copyright 2018 - thestr4ng3r */

#include <r_anal.h>
#include <r_vector.h>
#include "../include/r_anal.h"

#define CLASSES_FLAGSPACE "classes"

static char *sanitize_id(const char *id) {
	if (!id || !*id) {
		return NULL;
	}
	size_t len = strlen (id);
	char *ret = malloc (len + 1);
	if (!ret) {
		return NULL;
	}
	char *cur = ret;
	while (len > 0) {
		char c = *id;
		if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')
			&& c != '_' && c != ':') {
			c = '_';
		}
		*cur = c;
		id++;
		cur++;
		len--;
	}
	*cur = '\0';
	return ret;
}

static const char *key_classes = "classes";

static char *key_class(const char *name) {
	return sdb_fmt ("class.%s", name);
}

static char *key_attr_types(const char *name) {
	return sdb_fmt ("attrtypes.%s", name);
}

static char *key_attr_type_attrs(const char *class_name, const char *attr_type) {
	return sdb_fmt ("attr.%s.%s", class_name, attr_type);
}

static char *key_attr_content(const char *class_name, const char *attr_type, const char *attr_id) {
	return sdb_fmt ("attr.%s.%s.%s", class_name, attr_type, attr_id);
}

static char *key_attr_content_specific(const char *class_name, const char *attr_type, const char *attr_id) {
	return sdb_fmt ("attr.%s.%s.%s.specific", class_name, attr_type, attr_id);
}

typedef enum {
	R_ANAL_CLASS_ATTR_TYPE_METHOD,
	R_ANAL_CLASS_ATTR_TYPE_VTABLE,
	R_ANAL_CLASS_ATTR_TYPE_BASE
} RAnalClassAttrType;

static const char *attr_type_id(RAnalClassAttrType attr_type) {
	switch (attr_type) {
	case R_ANAL_CLASS_ATTR_TYPE_METHOD:
		return "method";
	case R_ANAL_CLASS_ATTR_TYPE_VTABLE:
		return "vtable";
	case R_ANAL_CLASS_ATTR_TYPE_BASE:
		return "base";
	default:
		return NULL;
	}
}


R_API void r_anal_class_create(RAnal *anal, const char *name) {
	char *name_sanitized = sanitize_id (name);
	if (!name_sanitized) {
		return;
	}
	sdb_array_add (anal->sdb_classes, key_classes, name_sanitized, 0);
	char *key = key_class (name_sanitized);
	free (name_sanitized);
	if (!sdb_exists (anal->sdb_classes, key)) {
		sdb_set (anal->sdb_classes, key, "c", 0);
	}
}

static void r_anal_class_base_delete_class(RAnal *anal, const char *class_name);
static void r_anal_class_method_delete_class(RAnal *anal, const char *class_name);
static void r_anal_class_vtable_delete_class(RAnal *anal, const char *class_name);

R_API void r_anal_class_delete(RAnal *anal, const char *name) {
	char *class_name_sanitized = sanitize_id (name);
	if (!class_name_sanitized) {
		return;
	}

	r_anal_class_base_delete_class (anal, class_name_sanitized);
	r_anal_class_method_delete_class (anal, class_name_sanitized);
	r_anal_class_vtable_delete_class (anal, class_name_sanitized);

	if (!sdb_array_remove (anal->sdb_classes, key_classes, class_name_sanitized, 0)) {
		free (class_name_sanitized);
		return;
	}

	char *key = key_attr_types (class_name_sanitized);
	char *attr_type_array = sdb_get (anal->sdb_classes, key, 0);

	sdb_array_remove (anal->sdb_classes, key_classes, class_name_sanitized, 0);

	char *attr_type;
	sdb_aforeach (attr_type, attr_type_array) {
		key = key_attr_type_attrs (class_name_sanitized, attr_type);
		char *attr_id_array = sdb_get (anal->sdb_classes, key, 0);
		sdb_remove (anal->sdb_classes, key, 0);
		if (attr_id_array) {
			char *attr_id;
			sdb_aforeach (attr_id, attr_id_array) {
				key = key_attr_content (class_name_sanitized, attr_type, attr_id);
				sdb_remove (anal->sdb_classes, key, 0);
				key = key_attr_content_specific (class_name_sanitized, attr_type, attr_id);
				sdb_remove (anal->sdb_classes, key, 0);
				sdb_aforeach_next (attr_id);
			}
			free (attr_id_array);
		}
		sdb_aforeach_next (attr_type);
	}
	free (attr_type_array);

	sdb_remove (anal->sdb_classes, key_class (class_name_sanitized), 0);
	sdb_remove (anal->sdb_classes, key_attr_types (class_name_sanitized), 0);

	free (class_name_sanitized);
}

R_API bool r_anal_class_exists(RAnal *anal, const char *name) {
	char *class_name_sanitized = sanitize_id (name);
	if (!class_name_sanitized) {
		return false;
	}
	bool r = sdb_exists (anal->sdb_classes, key_class (class_name_sanitized));
	free (class_name_sanitized);
	return r;
}

static void r_anal_class_base_rename_class(RAnal *anal, const char *class_name_old, const char *class_name_new);
static void r_anal_class_method_rename_class(RAnal *anal, const char *old_class_name, const char *new_class_name);
static void r_anal_class_vtable_rename_class(RAnal *anal, const char *old_class_name, const char *new_class_name);

static void rename_key(RAnal *anal, const char *key_old, const char *key_new) {
	char *content = sdb_get (anal->sdb_classes, key_old, 0);
	if (!content) {
		return;
	}
	sdb_remove (anal->sdb_classes, key_old, 0);
	sdb_set (anal->sdb_classes, key_new, content, 0);
	free (content);
}

R_API RAnalClassErr r_anal_class_rename(RAnal *anal, const char *old_name, const char *new_name) {
	if (r_anal_class_exists (anal, new_name)) {
		return R_ANAL_CLASS_ERR_CLASH;
	}

	char *old_name_sanitized = sanitize_id (old_name);
	if (!old_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *new_name_sanitized = sanitize_id (new_name);
	if (!new_name_sanitized) {
		free (old_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = R_ANAL_CLASS_ERR_SUCCESS;

	r_anal_class_base_rename_class (anal, old_name, new_name);
	r_anal_class_method_rename_class (anal, old_name, new_name);
	r_anal_class_vtable_rename_class (anal, old_name, new_name);

	if (!sdb_array_remove (anal->sdb_classes, key_classes, old_name_sanitized, 0)) {
		err = R_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
		goto beach;
	}
	sdb_array_add (anal->sdb_classes, key_classes, new_name_sanitized, 0);

	char *attr_types = sdb_get (anal->sdb_classes, key_attr_types (old_name_sanitized), 0);
	char *attr_type_cur;
	sdb_aforeach (attr_type_cur, attr_types) {
		char *attr_ids = sdb_get (anal->sdb_classes, key_attr_type_attrs (old_name, attr_type_cur), 0);
		char *attr_id_cur;
		sdb_aforeach (attr_id_cur, attr_ids) {
			rename_key (anal,
					key_attr_content (old_name, attr_type_cur, attr_id_cur),
					key_attr_content (new_name, attr_type_cur, attr_id_cur));
			sdb_aforeach_next (attr_id_cur);
		}
		free (attr_ids);
		rename_key (anal,
				key_attr_type_attrs (old_name, attr_type_cur),
				key_attr_type_attrs (new_name, attr_type_cur));
		sdb_aforeach_next (attr_type_cur);
	}
	free (attr_types);

	rename_key (anal, key_attr_types (old_name_sanitized), key_attr_types (new_name_sanitized));
	rename_key (anal, key_class (old_name_sanitized), key_class (new_name_sanitized));

beach:
	free (old_name_sanitized);
	free (new_name_sanitized);
	return err;
}

// all ids must be sanitized
static char *r_anal_class_get_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, bool specific) {
	const char *attr_type_str = attr_type_id (attr_type);
	char *key = specific
			? key_attr_content_specific (class_name, attr_type_str, attr_id)
			: key_attr_content (class_name, attr_type_str, attr_id);
	char *ret = sdb_get (anal->sdb_classes, key, 0);
	return ret;
}

// ids will be sanitized automatically
static char *r_anal_class_get_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, bool specific) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return false;
	}
	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return false;
	}

	char *ret = r_anal_class_get_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized, specific);

	free (class_name_sanitized);
	free (attr_id_sanitized);

	return ret;
}

// all ids must be sanitized
static RAnalClassErr r_anal_class_set_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	const char *attr_type_str = attr_type_id (attr_type);

	if (!sdb_exists (anal->sdb_classes, key_class (class_name))) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
	}

	sdb_array_add (anal->sdb_classes, key_attr_types (class_name), attr_type_str, 0);
	sdb_array_add (anal->sdb_classes, key_attr_type_attrs (class_name, attr_type_str), attr_id, 0);
	sdb_set (anal->sdb_classes, key_attr_content (class_name, attr_type_str, attr_id), content, 0);

	return R_ANAL_CLASS_ERR_SUCCESS;
}

// ids will be sanitized automatically
static RAnalClassErr r_anal_class_set_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = r_anal_class_set_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized, content);

	free (class_name_sanitized);
	free (attr_id_sanitized);

	return err;
}

static RAnalClassErr r_anal_class_delete_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id) {
	const char *attr_type_str = attr_type_id (attr_type);

	char *key = key_attr_content (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb_classes, key, 0);
	key = key_attr_content_specific (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb_classes, key, 0);

	key = key_attr_type_attrs (class_name, attr_type_str);
	sdb_array_remove (anal->sdb_classes, key, attr_id, 0);
	if (!sdb_exists (anal->sdb_classes, key)) {
		sdb_array_remove (anal->sdb_classes, key_attr_types (class_name), attr_type_str, 0);
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static RAnalClassErr r_anal_class_delete_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = r_anal_class_delete_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized);

	free (class_name_sanitized);
	free (attr_id_sanitized);
	return err;
}

static RAnalClassErr r_anal_class_rename_attr_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	const char *attr_type_str = attr_type_id (attr_type);
	char *key = key_attr_type_attrs (class_name, attr_type_str);

	if (sdb_array_contains (anal->sdb_classes, key, attr_id_new, 0)) {
		return R_ANAL_CLASS_ERR_CLASH;
	}

	if (!sdb_array_remove (anal->sdb_classes, key, attr_id_old, 0)) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	sdb_array_add (anal->sdb_classes, key, attr_id_new, 0);

	key = key_attr_content (class_name, attr_type_str, attr_id_old);
	char *content = sdb_get (anal->sdb_classes, key, 0);
	if (content) {
		sdb_remove (anal->sdb_classes, key, 0);
		key = key_attr_content (class_name, attr_type_str, attr_id_new);
		sdb_set (anal->sdb_classes, key, content, 0);
		free (content);
	}

	key = key_attr_content_specific (class_name, attr_type_str, attr_id_old);
	content = sdb_get (anal->sdb_classes, key, 0);
	if (content) {
		sdb_remove (anal->sdb_classes, key, 0);
		key = key_attr_content_specific (class_name, attr_type_str, attr_id_new);
		sdb_set (anal->sdb_classes, key, content, 0);
		free (content);
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static RAnalClassErr r_anal_class_rename_attr(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *attr_id_old_sanitized = sanitize_id (attr_id_old);
	if (!attr_id_old_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *attr_id_new_sanitized = sanitize_id (attr_id_new);
	if (!attr_id_new_sanitized) {
		free (class_name_sanitized);
		free (attr_id_old_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	RAnalClassErr ret = r_anal_class_rename_attr_raw (anal, class_name_sanitized, attr_type, attr_id_old_sanitized, attr_id_new_sanitized);
	free (class_name_sanitized);
	free (attr_id_old_sanitized);
	free (attr_id_new_sanitized);
	return ret;
}

static void r_anal_class_unique_attr_id_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, char *out, size_t out_size) {
	ut64 id = 0;
	char *key = key_attr_type_attrs (class_name, attr_type_id (attr_type));
	do {
		snprintf (out, out_size, "%"PFMT64u, id);
		id++;
	} while (sdb_array_contains (anal->sdb_classes, key, out, 0));
}

static char *flagname_attr(const char *attr_type, const char *class_name, const char *attr_id) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return NULL;
	}
	char *attr_id_sanitized = sanitize_id (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return NULL;
	}
	char *r = sdb_fmt ("%s.%s.%s", attr_type, class_name, attr_id);
	free (class_name_sanitized);
	free (attr_id_sanitized);
	return r;
}

static void r_anal_class_set_flag(RAnal *anal, const char *name, ut64 addr) {
	if (!name || !anal->flb.set || !anal->flb.push_fs || !anal->flb.pop_fs) {
		return;
	}
	anal->flb.push_fs (anal->flb.f, CLASSES_FLAGSPACE);
	anal->flb.set (anal->flb.f, name, addr, 0);
	anal->flb.pop_fs (anal->flb.f);
}

static void r_anal_class_unset_flag(RAnal *anal, const char *name) {
	if (!name || !anal->flb.unset_name || !anal->flb.push_fs || !anal->flb.pop_fs) {
		return;
	}
	anal->flb.push_fs (anal->flb.f, CLASSES_FLAGSPACE);
	anal->flb.unset_name (anal->flb.f, name);
	anal->flb.pop_fs (anal->flb.f);
}

static void r_anal_class_rename_flag(RAnal *anal, const char *old_name, const char *new_name) {
	if (!old_name || !new_name || !anal->flb.set || !anal->flb.get || !anal->flb.push_fs || !anal->flb.pop_fs || !anal->flb.unset_name) {
		return;
	}
	anal->flb.push_fs (anal->flb.f, CLASSES_FLAGSPACE);
	RFlagItem *flag = anal->flb.get (anal->flb.f, old_name);
	if (!flag) {
		anal->flb.pop_fs (anal->flb.f);
		return;
	}
	ut64 addr = flag->offset;
	anal->flb.unset (anal->flb.f, flag);
	anal->flb.set (anal->flb.f, new_name, addr, 0);
	anal->flb.pop_fs (anal->flb.f);
}

static RAnalClassErr r_anal_class_add_attr_unique_raw(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char attr_id[16];
	r_anal_class_unique_attr_id_raw (anal, class_name, attr_type, attr_id, sizeof(attr_id));

	RAnalClassErr err = r_anal_class_set_attr (anal, class_name, attr_type, attr_id, content);
	if (err != R_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}

	if (attr_id_out) {
		r_str_ncpy (attr_id_out, attr_id, attr_id_out_size);
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static RAnalClassErr r_anal_class_add_attr_unique(RAnal *anal, const char *class_name, RAnalClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	RAnalClassErr err = r_anal_class_add_attr_unique_raw (anal, class_name_sanitized, attr_type, content, attr_id_out, attr_id_out_size);

	free (class_name_sanitized);
	return err;
}


// ---- METHODS ----
// Format: addr,vtable_offset

static char *flagname_method(const char *class_name, const char *meth_name) {
	return flagname_attr ("method", class_name, meth_name);
}

R_API void r_anal_class_method_fini(RAnalMethod *meth) {
	free (meth->name);
}

// if the method exists: store it in *meth and return R_ANAL_CLASS_ERR_SUCCESS
// else return the error, contents of *meth are undefined
R_API RAnalClassErr r_anal_class_method_get(RAnal *anal, const char *class_name, const char *meth_name, RAnalMethod *meth) {
	char *content = r_anal_class_get_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name, false);
	if (!content) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	meth->addr = r_num_math (NULL, cur);

	cur = next;
	if (!cur) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, NULL);

	meth->vtable_offset = atoi (cur);

	free (content);

	meth->name = sanitize_id (meth_name);
	if (!meth->name) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_method_fini_proxy(void *e, void *user) {
	(void)user;
	RAnalMethod *meth = e;
	r_anal_class_method_fini (meth);
}

R_API RVector/*<RAnalMethod>*/ *r_anal_class_method_get_all(RAnal *anal, const char *class_name) {
	RVector *vec = r_vector_new (sizeof(RAnalMethod), r_anal_class_method_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		r_vector_free (vec);
		return NULL;
	}
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (class_name_sanitized, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	free (class_name_sanitized);

	r_vector_reserve (vec, (size_t) sdb_alen (array));
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalMethod meth;
		if (r_anal_class_method_get (anal, class_name, cur, &meth) == R_ANAL_CLASS_ERR_SUCCESS) {
			r_vector_push (vec, &meth);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

R_API RAnalClassErr r_anal_class_method_set(RAnal *anal, const char *class_name, RAnalMethod *meth) {
	char *content = sdb_fmt ("%"PFMT64u"%c%d", meth->addr, SDB_RS, meth->vtable_offset);
	RAnalClassErr err = r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth->name, content);
	if (err != R_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}
	r_anal_class_set_flag (anal, flagname_method (class_name, meth->name), meth->addr);
	return R_ANAL_CLASS_ERR_SUCCESS;
}

R_API RAnalClassErr r_anal_class_method_rename(RAnal *anal, const char *class_name, const char *old_meth_name, const char *new_meth_name) {
	RAnalClassErr err = r_anal_class_rename_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_METHOD, old_meth_name, new_meth_name);
	if (err != R_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}
	r_anal_class_rename_flag (anal,
			flagname_method (class_name, old_meth_name),
			flagname_method (class_name, new_meth_name));
	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_method_rename_class(RAnal *anal, const char *old_class_name, const char *new_class_name) {
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (old_class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		r_anal_class_rename_flag (anal,
				flagname_method (old_class_name, cur),
				flagname_method (new_class_name, cur));
		sdb_aforeach_next (cur);
	}
	free (array);
}

static void r_anal_class_method_delete_class(RAnal *anal, const char *class_name) {
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		r_anal_class_unset_flag (anal, flagname_method (class_name, cur));
		sdb_aforeach_next (cur);
	}
	free (array);
}

R_API RAnalClassErr r_anal_class_method_delete(RAnal *anal, const char *class_name, const char *meth_name) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *meth_name_sanitized = sanitize_id (meth_name);
	if (!meth_name_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	RAnalClassErr err = r_anal_class_delete_attr_raw (anal, class_name_sanitized, R_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name_sanitized);
	if (err == R_ANAL_CLASS_ERR_SUCCESS) {
		r_anal_class_unset_flag (anal, flagname_method (class_name_sanitized, meth_name_sanitized));
	}
	free (class_name_sanitized);
	free (meth_name_sanitized);
	return err;
}


// ---- BASE ----

R_API void r_anal_class_base_fini(RAnalBaseClass *base) {
	free (base->id);
	free (base->class_name);
}

R_API RAnalClassErr r_anal_class_base_get(RAnal *anal, const char *class_name, const char *base_id, RAnalBaseClass *base) {
	char *content = r_anal_class_get_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, base_id, false);
	if (!content) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	base->class_name = strdup (cur);
	if (!base->class_name) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	cur = next;
	if (!cur) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, NULL);

	base->offset = r_num_math (NULL, cur);

	free (content);

	base->id = sanitize_id (base_id);
	if (!base->id) {
		free (base->class_name);
		return R_ANAL_CLASS_ERR_OTHER;
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_base_fini_proxy(void *e, void *user) {
	(void)user;
	RAnalBaseClass *base = e;
	r_anal_class_base_fini (base);
}

R_API RVector/*<RAnalBaseClass>*/ *r_anal_class_base_get_all(RAnal *anal, const char *class_name) {
	RVector *vec = r_vector_new (sizeof(RAnalBaseClass), r_anal_class_base_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		r_vector_free (vec);
		return NULL;
	}
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (class_name_sanitized, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_BASE)), 0);
	free (class_name_sanitized);

	r_vector_reserve (vec, (size_t) sdb_alen (array));
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalBaseClass base;
		if (r_anal_class_base_get (anal, class_name, cur, &base) == R_ANAL_CLASS_ERR_SUCCESS) {
			r_vector_push (vec, &base);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

static RAnalClassErr r_anal_class_base_set_raw(RAnal *anal, const char *class_name, RAnalBaseClass *base, const char *base_class_name_sanitized) {
	char *content = sdb_fmt ("%s" SDB_SS "%"PFMT64u, base_class_name_sanitized, base->offset);
	RAnalClassErr err;
	if (base->id) {
		err = r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, base->id, content);
	} else {
		base->id = malloc(16);
		if (base->id) {
			err = r_anal_class_add_attr_unique (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, content, base->id, 16);
		} else {
			err = R_ANAL_CLASS_ERR_OTHER;
		}
	}
	return err;
}

R_API RAnalClassErr r_anal_class_base_set(RAnal *anal, const char *class_name, RAnalBaseClass *base) {
	char *base_class_name_sanitized = sanitize_id (base->class_name);
	if (!base_class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	if (!sdb_exists (anal->sdb_classes, key_class (base_class_name_sanitized))) {
		free (base_class_name_sanitized);
		return R_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
	}
	RAnalClassErr err = r_anal_class_base_set_raw (anal, class_name, base, base_class_name_sanitized);
	free (base_class_name_sanitized);
	return err;
}

R_API RAnalClassErr r_anal_class_base_delete(RAnal *anal, const char *class_name, const char *base_id) {
	return r_anal_class_delete_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_BASE, base_id);
}

static void r_anal_class_base_delete_class(RAnal *anal, const char *class_name) {
	char *classes = sdb_get (anal->sdb_classes, key_classes, 0);
	char *class_cur;
	sdb_aforeach (class_cur, classes) {
		RVector *bases = r_anal_class_base_get_all (anal, class_cur);
		RAnalBaseClass *base;
		r_vector_foreach (bases, base) {
			if (strcmp (base->class_name, class_name) == 0) {
				r_anal_class_base_delete (anal, class_cur, base->id);
			}
		}
		r_vector_free (bases);
		sdb_aforeach_next (class_cur);
	}
	free (classes);
}

static void r_anal_class_base_rename_class(RAnal *anal, const char *class_name_old, const char *class_name_new) {
	char *classes = sdb_get (anal->sdb_classes, key_classes, 0);
	char *class_cur;
	sdb_aforeach (class_cur, classes) {
		RVector *bases = r_anal_class_base_get_all (anal, class_cur);
		RAnalBaseClass *base;
		r_vector_foreach (bases, base) {
			if (strcmp (base->class_name, class_name_old) == 0) {
				if (base->class_name) {
					r_anal_class_base_set_raw (anal, class_cur, base, class_name_new);
				}
			}
		}
		r_vector_free (bases);
		sdb_aforeach_next (class_cur);
	}
	free (classes);
}

// ---- VTABLE ----

static char *flagname_vtable(const char *class_name, const char *vtable_id) {
	return flagname_attr ("vtable", class_name, vtable_id);
}

R_API void r_anal_class_vtable_fini(RAnalVTable *vtable) {
	free (vtable->id);
}

R_API RAnalClassErr r_anal_class_vtable_get(RAnal *anal, const char *class_name, const char *vtable_id, RAnalVTable *vtable) {
	char *content = r_anal_class_get_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable_id, false);
	if (!content) {
		return R_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	vtable->addr = r_num_math (NULL, cur);

	cur = next;
	if (!cur) {
		free (content);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, NULL);

	vtable->offset = r_num_math (NULL, cur);

	free (content);

	vtable->id = sanitize_id (vtable_id);
	if (!vtable->id) {
		return R_ANAL_CLASS_ERR_OTHER;
	}

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_vtable_fini_proxy(void *e, void *user) {
	(void)user;
	RAnalVTable *vtable = e;
	r_anal_class_vtable_fini (vtable);
}

R_API RVector/*<RAnalVTable>*/ *r_anal_class_vtable_get_all(RAnal *anal, const char *class_name) {
	RVector *vec = r_vector_new (sizeof(RAnalVTable), r_anal_class_vtable_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		r_vector_free (vec);
		return NULL;
	}
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (class_name_sanitized, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_VTABLE)), 0);
	free (class_name_sanitized);

	r_vector_reserve (vec, (size_t) sdb_alen (array));
	char *cur;
	sdb_aforeach (cur, array) {
		RAnalVTable vtable;
		if (r_anal_class_vtable_get (anal, class_name, cur, &vtable) == R_ANAL_CLASS_ERR_SUCCESS) {
			r_vector_push (vec, &vtable);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

R_API RAnalClassErr r_anal_class_vtable_set(RAnal *anal, const char *class_name, RAnalVTable *vtable) {
	char *content = sdb_fmt ("0x%"PFMT64x SDB_SS "%"PFMT64u, vtable->addr, vtable->offset);
	if (vtable->id) {
		return r_anal_class_set_attr (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable->id, content);
	}
	vtable->id = malloc(16);
	if (!vtable->id) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	RAnalClassErr err = r_anal_class_add_attr_unique (anal, class_name, R_ANAL_CLASS_ATTR_TYPE_VTABLE, content, vtable->id, 16);
	if (err != R_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}

	r_anal_class_set_flag (anal, flagname_vtable (class_name, vtable->id), vtable->addr);

	return R_ANAL_CLASS_ERR_SUCCESS;
}

static void r_anal_class_vtable_rename_class(RAnal *anal, const char *old_class_name, const char *new_class_name) {
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (old_class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_VTABLE)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		r_anal_class_rename_flag (anal,
				flagname_vtable (old_class_name, cur),
				flagname_vtable (new_class_name, cur));
		sdb_aforeach_next (cur);
	}
	free (array);
}

static void r_anal_class_vtable_delete_class(RAnal *anal, const char *class_name) {
	char *array = sdb_get (anal->sdb_classes, key_attr_type_attrs (class_name, attr_type_id (R_ANAL_CLASS_ATTR_TYPE_VTABLE)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		r_anal_class_unset_flag (anal, flagname_vtable (class_name, cur));
		sdb_aforeach_next (cur);
	}
	free (array);
}

R_API RAnalClassErr r_anal_class_vtable_delete(RAnal *anal, const char *class_name, const char *vtable_id) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return R_ANAL_CLASS_ERR_OTHER;
	}
	char *vtable_id_sanitized = sanitize_id (vtable_id);
	if (!vtable_id_sanitized) {
		free (class_name_sanitized);
		return R_ANAL_CLASS_ERR_OTHER;
	}
	RAnalClassErr err = r_anal_class_delete_attr_raw (anal, class_name_sanitized, R_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable_id_sanitized);
	if (err == R_ANAL_CLASS_ERR_SUCCESS) {
		r_anal_class_unset_flag (anal, flagname_vtable (class_name_sanitized, vtable_id_sanitized));
	}
	free (class_name_sanitized);
	free (vtable_id_sanitized);
	return err;
}


// ---- PRINT ----


static void r_anal_class_print(RAnal *anal, const char *class_name, bool lng) {
	r_cons_print (class_name);

	RVector *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *base;
		bool first = true;
		r_vector_foreach (bases, base) {
			if (first) {
				r_cons_print (": ");
				first = false;
			} else {
				r_cons_print (", ");
			}
			r_cons_print (base->class_name);
		}
		r_vector_free (bases);
	}

	r_cons_print ("\n");


	if (lng) {
		RVector *vtables = r_anal_class_vtable_get_all (anal, class_name);
		if (vtables) {
			RAnalVTable *vtable;
			r_vector_foreach (vtables, vtable) {
				r_cons_printf ("  (vtable at 0x%"PFMT64x, vtable->addr);
				if (vtable->offset > 0) {
					r_cons_printf (" in class at +0x%"PFMT64x")\n", vtable->offset);
				} else {
					r_cons_print (")\n");
				}
			}
			r_vector_free (vtables);
		}

		RVector *methods = r_anal_class_method_get_all (anal, class_name);
		if (methods) {
			RAnalMethod *meth;
			r_vector_foreach (methods, meth) {
				r_cons_printf ("  %s @ 0x%"PFMT64x, meth->name, meth->addr);
				if (meth->vtable_offset >= 0) {
					r_cons_printf (" (vtable + 0x%"PFMT64x")\n", (ut64)meth->vtable_offset);
				} else {
					r_cons_print ("\n");
				}
			}
			r_vector_free (methods);
		}
	}
}

static void r_anal_class_print_cmd(RAnal *anal, const char *class_name) {
	RVector *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *base;
		r_vector_foreach (bases, base) {
			r_cons_printf ("aCb %s %s %"PFMT64u"\n", class_name, base->class_name, base->offset);
		}
		r_vector_free (bases);
	}

	RVector *vtables = r_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RAnalVTable *vtable;
		r_vector_foreach (vtables, vtable) {
			r_cons_printf ("aCv %s 0x%"PFMT64x" %"PFMT64u"\n", class_name, vtable->addr, vtable->offset);
		}
		r_vector_free (vtables);
	}

	RVector *methods = r_anal_class_method_get_all (anal, class_name);
	if (methods) {
		RAnalMethod *meth;
		r_vector_foreach (methods, meth) {
			r_cons_printf ("aCm %s %s 0x%"PFMT64x" %"PFMT64d"\n", class_name, meth->name, meth->addr, meth->vtable_offset);
		}
		r_vector_free (methods);
	}
}

static void r_anal_class_json(RAnal *anal, PJ *j, const char *class_name) {
	pj_o (j);
	pj_ks (j, "name", class_name);

	pj_k (j, "bases");
	pj_a (j);
	RVector *bases = r_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RAnalBaseClass *base;
		r_vector_foreach (bases, base) {
			pj_o (j);
			pj_ks (j, "id", base->id);
			pj_ks (j, "name", base->class_name);
			pj_kn (j, "offset", base->offset);
			pj_end (j);
		}
		r_vector_free (bases);
	}
	pj_end (j);

	pj_k (j, "vtables");
	pj_a (j);
	RVector *vtables = r_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RAnalVTable *vtable;
		r_vector_foreach (vtables, vtable) {
			pj_o (j);
			pj_ks (j, "id", vtable->id);
			pj_kn (j, "addr", vtable->addr);
			pj_kn (j, "offset", vtable->offset);
		}
	}
	pj_end (j);

	pj_k (j, "methods");
	pj_a (j);
	RVector *methods = r_anal_class_method_get_all (anal, class_name);
	if (methods) {
		RAnalMethod *meth;
		r_vector_foreach (methods, meth) {
			pj_o (j);
			pj_ks (j, "name", meth->name);
			pj_kn (j, "addr", meth->addr);
			if (meth->vtable_offset >= 0) {
				pj_kn (j, "vtable_offset", (ut64)meth->vtable_offset);
			}
			pj_end (j);
		}
		r_vector_free (methods);
	}
	pj_end (j);

	pj_end (j);
}

static void r_anal_class_list_json(RAnal *anal) {
	PJ *j = pj_new ();
	if (!j) {
		return;
	}
	pj_a (j);

	char *classes_array = sdb_get (anal->sdb_classes, key_classes, 0);
	char *class_name;
	sdb_aforeach (class_name, classes_array) {
		r_anal_class_json (anal, j, class_name);
		sdb_aforeach_next (class_name);
	}
	free (classes_array);

	pj_end (j);
	pj_drain (j);
}

R_API void r_anal_class_list(RAnal *anal, int mode) {
	if (mode == 'j') {
		r_anal_class_list_json (anal);
		return;
	}

	char *classes_array = sdb_get (anal->sdb_classes, key_classes, 0);
	char *class_name;
	if (mode == '*') {
		char *classes_array_dup = strdup (classes_array);
		sdb_aforeach (class_name, classes_array_dup) {
			r_cons_printf ("aC %s\n", class_name);
			sdb_aforeach_next (class_name);
		}
		free (classes_array_dup);
	}

	sdb_aforeach (class_name, classes_array) {
		if (mode == '*') {
			r_anal_class_print_cmd(anal, class_name);
		} else {
			r_anal_class_print (anal, class_name, mode == 'l');
		}
		sdb_aforeach_next (class_name);
	}
	free (classes_array);
}

R_API void r_anal_class_list_bases(RAnal *anal, const char *class_name) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return;
	}
	if (!sdb_exists (anal->sdb_classes, key_class (class_name_sanitized))) {
		return;
	}
	r_cons_printf ("%s:\n", class_name_sanitized);
	free (class_name_sanitized);

	RVector *bases = r_anal_class_base_get_all (anal, class_name);
	RAnalBaseClass *base;
	r_vector_foreach (bases, base) {
		r_cons_printf ("  %4s %s @ +0x%"PFMT64x"\n", base->id, base->class_name, base->offset);
	}
	r_vector_free (bases);
}

R_API void r_anal_class_list_vtables(RAnal *anal, const char *class_name) {
	char *class_name_sanitized = sanitize_id (class_name);
	if (!class_name_sanitized) {
		return;
	}
	if (!sdb_exists (anal->sdb_classes, key_class (class_name_sanitized))) {
		return;
	}
	r_cons_printf ("%s:\n", class_name_sanitized);
	free (class_name_sanitized);

	RVector *vtables = r_anal_class_vtable_get_all (anal, class_name);
	RAnalVTable *vtable;
	r_vector_foreach (vtables, vtable) {
		r_cons_printf ("  %4s vtable 0x%"PFMT64x" @ +0x%"PFMT64x"\n", vtable->id, vtable->addr, vtable->offset);
	}
	r_vector_free (vtables);
}