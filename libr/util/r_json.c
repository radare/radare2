#include <r_util.h>
#include <r_types.h>
#include <r_util.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "r_asn1_internal.h"

void r_json_var_free (RJSVar* var) {
	int i;
	if (!var) {
		return;
	}

	switch (var->type) {
	case R_JS_STRING:
		free ((char*) var->string.s);
		break;
	case R_JS_ARRAY:
		for (i = 0; i < var->array.l; i++) {
			r_json_var_free (var->array.a[i]);
		}
		free (var->array.a);
		break;
	case R_JS_OBJECT:
		for (i = 0; i < var->object.l; i++) {
			r_json_var_free (var->object.a[i]);
			free ((char*) var->object.n[i]);
		}
		free ((char**) var->object.n);
		free (var->object.a);
		break;
	default:
		break;
	}
	free (var);
}

RJSVar* r_json_object_new () {
	RJSVar* var = R_NEW0 (RJSVar);
	var->type = R_JS_OBJECT;
	return var;
}

RJSVar* r_json_array_new (int len) {
	if (len < 0) {
		return NULL;
	}
	RJSVar* var = R_NEW0 (RJSVar);
	if (len) {
		var->array.a = R_NEWS0 (RJSVar*, len);
		var->array.l = len;
	} else {
		var->array.a = NULL;
		var->array.l = 0;
	}
	var->type = R_JS_ARRAY;
	return var;
}

RJSVar* r_json_string_new (const char* name) {
	RJSVar* var = R_NEW0 (RJSVar);
	var->type = R_JS_STRING;
	var->string.s = strdup (name);
	var->string.l = strlen (name) + 1;
	return var;
}

RJSVar* r_json_number_new (int value) {
	RJSVar* var = R_NEW0 (RJSVar);
	var->type = R_JS_NUMBERS;
	var->number = value;
	return var;
}

RJSVar* r_json_boolean_new (bool value) {
	RJSVar* var = R_NEW0 (RJSVar);
	var->type = R_JS_BOOLEAN;
	var->boolean = value;
	return var;
}

RJSVar* r_json_null_new () {
	RJSVar* var = R_NEW0 (RJSVar);
	var->type = R_JS_NULL;
	return var;
}

void r_json_object_add (RJSVar* object, const char* name, RJSVar* value) {
	ut32 len;
	RJSVar** v;
	char** c;
	if (!object || !name || !value) {
		return;
	}
	len = object->object.l + 1;
	if (len <= 0) {
		return;
	}
	v = (RJSVar**) realloc (object->object.a, len * sizeof (RJSVar*));
	if (!v) {
		return;
	}
	c = (char**) realloc (object->object.n, len * sizeof (char*));
	if (!c) {
		return;
	}
	v[len - 1] = value;
	c[len - 1] = strdup (name);
	object->object.l = len;
	object->object.a = v;
	object->object.n = (const char**) c;
}

void r_json_array_add (RJSVar* array, RJSVar* value) {
	ut32 len;
	RJSVar** v;
	if (!array || !value) {
		return;
	}
	len = array->array.l + 1;
	if (len <= 0) {
		return;
	}
	v = (RJSVar**) realloc (array->array.a, len * sizeof (RJSVar*));
	if (!v) {
		return;
	}
	v[len - 1] = value;
	array->array.l = len;
	array->array.a = v;
}

RJSVar* r_json_object_get (RJSVar* object, const char* name) {
	if (!object || !name) {
		return NULL;
	}
	ut32 i;
	for (i = 0; i < object->object.l; i++) {
		if (!strcmp (name, object->object.n[i])) {
			return object->object.a[i];
		}
	}
	return NULL;
}

RJSVar* r_json_array_get (RJSVar* array, int index) {
	if (!array || index <= 0 || index >= array->array.l) {
		return NULL;
	}
	return array->array.a[index];
}

char* r_json_var_string (RJSVar* var, bool expanded) {
	char *c = NULL;
	ut32 i, len = 0;
	if (!var) {
		if (expanded) {
			len = sizeof (R_JSON_NULL);
			c = (char*) malloc (len);
			memcpy (c, R_JSON_NULL, len);
		}
		return c;
	}
	switch (var->type) {
	case R_JS_NULL:
		if (expanded) {
			len = sizeof (R_JSON_NULL);
			c = (char*) malloc (len);
			memcpy (c, R_JSON_NULL, len);
		}
		break;
	case R_JS_NUMBERS:
		len = snprintf (NULL, 0, "%d", var->number) + 1;
		c = (char*) malloc (len);
		snprintf (c, len, "%d", var->number);
		break;
	case R_JS_BOOLEAN:
		len = var->boolean ? sizeof (R_JSON_TRUE) : sizeof (R_JSON_FALSE);
		c = (char*) malloc (len);
		snprintf (c, len, "%s", var->boolean ? R_JSON_TRUE : R_JSON_FALSE);
		break;
	case R_JS_STRING:
		len = var->string.l + 2;
		c = (char*) malloc (len);
		memcpy (c + 1, var->string.s, var->string.l);
		c[0] = '"';
		c[len - 2] = '"';
		c[len - 1] = 0;
		break;
	case R_JS_ARRAY:
		if (var->array.l) {
			len = 3;
			char* p, *e;
			char** t = R_NEWS0 (char*, var->array.l);
			if (!t) {
				c = (char*) malloc (sizeof (R_JSON_EMPTY_ARR));
				memcpy (c, R_JSON_EMPTY_ARR, sizeof (R_JSON_EMPTY_ARR));
				break;
			}
			for (i = 0; i < var->array.l; i++) {
				t[i] = r_json_var_string (var->array.a[i], expanded);
				if (!t[i]) continue;
				len += strlen (t[i]) + 1;
			}
			c = (char*) calloc (len, 1);
			p = c + 1;
			e = p + len;
			for (i = 0; i < var->array.l; i++) {
				if (!t[i]) continue;
				p += snprintf (p, e - p, "%s,", t[i]);
				free (t[i]);
			}
			c[0] = '[';
			if (p == c + 1)
				p++;
			c[len - (e - p)] = ']';
			c[len - 1] = 0;
			free (t);
		} else {
			c = (char*) malloc (sizeof (R_JSON_EMPTY_ARR));
			memcpy (c, R_JSON_EMPTY_ARR, sizeof (R_JSON_EMPTY_ARR));
		}
		break;
	case R_JS_OBJECT:
		if (var->object.l) {
			char* p, *e;
			char** t = R_NEWS0 (char*, var->object.l);
			if (!t) {
				c = (char*) malloc (sizeof (R_JSON_EMPTY_OBJ));
				memcpy (c, R_JSON_EMPTY_OBJ, sizeof (R_JSON_EMPTY_OBJ));
				break;
			}
			len = 3;
			for (i = 0; i < var->object.l; i++) {
				t[i] = r_json_var_string (var->object.a[i], expanded);
				if (!t[i]) continue;
				fflush (stdout);
				len += strlen (t[i]) + strlen (var->object.n[i]) + 4;
			}
			c = (char*) malloc (len);
			p = c + 1;
			e = p + len;
			for (i = 0; i < var->object.l; i++) {
				if (!t[i]) continue;
				p += snprintf (p, e - p, "\"%s\":%s,", var->object.n[i], t[i]);
				free (t[i]);
			}
			c[0] = '{';
			if (p == c + 1)
				p++;
			c[len - (e - p)] = '}';
			c[len - 1] = 0;
			free (t);
		} else {
			c = (char*) malloc (sizeof (R_JSON_EMPTY_OBJ));
			memcpy (c, R_JSON_EMPTY_OBJ, sizeof (R_JSON_EMPTY_OBJ));
		}
		break;
	}
	return c;
}

char* r_json_stringify (RJSVar* var, bool expanded) {
	char* s = NULL;
	if (!var || (var->type != R_JS_OBJECT && var->type != R_JS_ARRAY)) {
		return NULL;
	}
	s = r_json_var_string (var, expanded);
	return s;
}