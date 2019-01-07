/* radare - LGPL - Copyright 2013-2018 - pancake */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>

R_API RStrBuf *r_strbuf_new(const char *str) {
	RStrBuf *s = R_NEW0 (RStrBuf);
	if (str) {
		r_strbuf_set (s, str);
	}
	return s;
}

R_API bool r_strbuf_equals(RStrBuf *sa, RStrBuf *sb) {
	if (!sa || !sb || sa->len != sb->len) { // faster comparisons
		return false;
	}
	return strcmp (r_strbuf_get (sa), r_strbuf_get (sb)) == 0;
}

R_API int r_strbuf_length(RStrBuf *sb) {
	r_return_val_if_fail (sb, 0);
	return sb->len;
}

R_API void r_strbuf_init(RStrBuf *sb) {
	r_return_if_fail (sb);
	memset (sb, 0, sizeof (RStrBuf));
}

R_API bool r_strbuf_setbin(RStrBuf *sb, const ut8 *s, int l) {
	r_return_val_if_fail (sb && s, false);
	r_return_val_if_fail (l >= 0, false);

	if (l >= sizeof (sb->buf)) {
		char *ptr = sb->ptr;
		int newlen = R_ALIGN_NEXT (l + 1, 128UL);
		bool allocated = true;
		if (!sb->ptr) {
			ptr = malloc (newlen);
		} else if ((l + 1) > sb->ptrlen) {
			ptr = realloc (sb->ptr, newlen);
		} else {
			allocated = false;
		}
		if (allocated) {
			if (!ptr) {
				return false;
			}
			sb->ptrlen = newlen;
			sb->ptr = ptr;
		}
		memcpy (ptr, s, l);
		*(ptr + l) = 0;
	} else {
		R_FREE (sb->ptr);
		memcpy (sb->buf, s, l);
		sb->buf[l] = 0;
	}
	sb->len = l;
	return true;
}

R_API bool r_strbuf_set(RStrBuf *sb, const char *s) {
	r_return_val_if_fail (sb, false);

	if (!s) {
		r_strbuf_init (sb);
		return true;
	}
	return r_strbuf_setbin (sb, (const ut8*)s, strlen (s));
}

R_API bool r_strbuf_setf(RStrBuf *sb, const char *fmt, ...) {
	bool ret;
	va_list ap;

	r_return_val_if_fail (sb && fmt, false);

	va_start (ap, fmt);
	ret = r_strbuf_vsetf (sb, fmt, ap);
	va_end (ap);
	return ret;
}

R_API bool r_strbuf_vsetf(RStrBuf *sb, const char *fmt, va_list ap) {
	int rc;
	bool ret;
	va_list ap2;
	char string[1024];

	r_return_val_if_fail (sb && fmt, false);

	va_copy (ap2, ap);
	rc = vsnprintf (string, sizeof (string), fmt, ap);
	if (rc >= sizeof (string)) {
		char *p = malloc (rc + 1);
		if (!p) {
			ret = false;
			goto done;
		}
		rc = vsnprintf (p, rc + 1, fmt, ap2);
		ret = r_strbuf_setbin (sb, p, rc);
		free (p);
	} else if (rc >= 0) {
		ret = r_strbuf_setbin (sb, string, rc);
	} else {
		ret = false;
	}
done:
	va_end (ap2);
	return ret;
}

R_API bool r_strbuf_append(RStrBuf *sb, const char *s) {
	r_return_val_if_fail (sb && s, false);

	int l = strlen (s);
	return r_strbuf_append_n (sb, s, l);
}

R_API bool r_strbuf_append_n(RStrBuf *sb, const char *s, int l) {
	r_return_val_if_fail (sb, false);
	r_return_val_if_fail (s && l >= 0, false);

	// fast path if no chars to append
	if (l == 0) {
		return true;
	}

	if ((sb->len + l + 1) <= sizeof (sb->buf)) {
		memcpy (sb->buf + sb->len, s, l);
		sb->buf[sb->len + l] = 0;
		R_FREE (sb->ptr);
	} else {
		int newlen = R_ALIGN_NEXT (sb->len + l + 128, 128UL);
		char *p = sb->ptr;
		bool allocated = true;
		if (!sb->ptr) {
			p = malloc (newlen);
			if (p && sb->len > 0) {
				memcpy (p, sb->buf, sb->len);
			}
		} else if ((sb->len + l + 1) > sb->ptrlen) {
			p = realloc (sb->ptr, newlen);
		} else {
			allocated = false;
		}
		if (allocated) {
			if (!p) {
				return false;
			}
			sb->ptr = p;
			sb->ptrlen = newlen;
		}
		memcpy (p + sb->len, s, l);
		*(p + sb->len + l) = 0;
	}
	sb->len += l;
	return true;
}

R_API bool r_strbuf_appendf(RStrBuf *sb, const char *fmt, ...) {
	va_list ap;

	r_return_val_if_fail (sb && fmt, -1);

	va_start (ap, fmt);
	bool ret = r_strbuf_vappendf (sb, fmt, ap);
	va_end (ap);
	return ret;
}

R_API bool r_strbuf_vappendf(RStrBuf *sb, const char *fmt, va_list ap) {
	int ret;
	va_list ap2;
	char string[1024];

	r_return_val_if_fail (sb && fmt, -1);

	va_copy (ap2, ap);
	ret = vsnprintf (string, sizeof (string), fmt, ap);
	if (ret >= sizeof (string)) {
		char *p = malloc (ret + 1);
		if (!p) {
			va_end (ap2);
			return false;
		}
		*p = 0;
		ret = vsnprintf (p, ret + 1, fmt, ap2);
		ret = r_strbuf_append_n (sb, p, ret);
		free (p);
	} else if (ret >= 0) {
		ret = r_strbuf_append_n (sb, string, ret);
	} else {
		ret = false;
	}
	va_end (ap2);
	return ret;
}

R_API char *r_strbuf_get(RStrBuf *sb) {
	r_return_val_if_fail (sb, NULL);
	return sb->ptr ? sb->ptr : sb->buf;
}

R_API ut8 *r_strbuf_getbin(RStrBuf *sb, int *len) {
	r_return_val_if_fail (sb, NULL);
	if (len) {
		*len = sb->len;
	}
	return (ut8 *)(sb->ptr ? sb->ptr : sb->buf);
}

R_API char *r_strbuf_drain(RStrBuf *sb) {
	r_return_val_if_fail (sb, NULL);
	char *ret = sb->ptr ? sb->ptr : strdup (sb->buf);
	free (sb);
	return ret;
}

R_API void r_strbuf_free(RStrBuf *sb) {
	r_strbuf_fini (sb);
	free (sb);
}

R_API void r_strbuf_fini(RStrBuf *sb) {
	if (sb) {
		R_FREE (sb->ptr);
	}
}
