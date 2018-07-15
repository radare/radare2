/* radare - LGPL - Copyright 2010-2015 - pancake */

#include <r_search.h>

static int ignoreMask(const ut8 *bm, int len) {
	int i;
	for (i=0; i<len; i++) {
		if (bm[i] != 0xff)
			return 0;
	}
	return 1;
}

R_API RSearchKeyword* r_search_keyword_new(const ut8 *kwbuf, int kwlen, const ut8 *bmbuf, int bmlen, const char *data) {
	RSearchKeyword *kw;
	if (kwlen < 1 || bmlen < 0)
		return NULL;
	kw = R_NEW0 (RSearchKeyword);
	if (!kw) return NULL;
	kw->type = R_SEARCH_KEYWORD_TYPE_BINARY;
	kw->data = (void *) data;
	kw->keyword_length = kwlen;
	if (!(kw->bin_keyword = malloc (kwlen))) {
		r_search_keyword_free (kw);
		return NULL;
	}
	memcpy (kw->bin_keyword, kwbuf, kwlen);
	if (bmbuf && bmlen > 0 && !ignoreMask (bmbuf, bmlen)) {
		if (!(kw->bin_binmask = malloc (bmlen))) {
			r_search_keyword_free (kw);
			return NULL;
		}
		memcpy (kw->bin_binmask, bmbuf, bmlen);
		kw->binmask_length = bmlen;
	} else {
		kw->bin_binmask = NULL;
		kw->binmask_length = 0;
	}
	return kw;
}

R_API void r_search_keyword_free (RSearchKeyword *kw) {
	if (!kw) {
		return;
	}
	free (kw->bin_binmask);
	free (kw->bin_keyword);
	free (kw);
}

R_API RSearchKeyword* r_search_keyword_new_str(const char *kwbuf, const char *bmstr, const char *data, int ignore_case) {
	RSearchKeyword *kw;
	ut8 *bmbuf = NULL;
	int bmlen = 0;

	if (bmstr) {
		if (!(bmbuf = malloc (strlen (bmstr)+1))) {
			return NULL;
		}
		bmlen = r_hex_str2bin (bmstr, bmbuf);
		if (bmlen < 1) {
			free (bmbuf);
			bmbuf = NULL;
		}
	}
	kw = r_search_keyword_new ((ut8 *)kwbuf, strlen (kwbuf), bmbuf, bmlen, data);
	if (kw) {
		kw->icase = ignore_case;
		kw->type = R_SEARCH_KEYWORD_TYPE_STRING;
	}
	free (bmbuf);
	return kw;
}

R_API RSearchKeyword* r_search_keyword_new_wide(const char *kwbuf, const char *bmstr, const char *data, int ignore_case) {
	RSearchKeyword *kw;
	int len;
	const char *p2;
	char *p, *str;
	ut8 *bmbuf = NULL;
	int bmlen = 0;

	if (bmstr) {
		if (!(bmbuf = malloc (strlen (bmstr)+1))) {
			return NULL;
		}
		bmlen = r_hex_str2bin (bmstr, bmbuf);
		if (bmlen < 1) {
			free(bmbuf);
			bmbuf = NULL;
		}
	}

	len = strlen(kwbuf);
	if (!(str = malloc ((len + 1) * 2))) {
		free(bmbuf);
		return NULL;
	}
	for (p2=kwbuf, p=str; *p2; p+=2, p2++) {
		if (ignore_case)
			p[0] = tolower((const unsigned char)*p2);
		else
			p[0] = *p2;
		p[1] = 0;
	}

	kw = r_search_keyword_new ((ut8 *)str, len*2, bmbuf, bmlen, data);
	free(str);
	if (kw) {
		kw->icase = ignore_case;
	}
	free(bmbuf);
	return kw;
}

R_API RSearchKeyword* r_search_keyword_new_hex(const char *kwstr, const char *bmstr, const char *data) {
	RSearchKeyword *kw;
	ut8 *kwbuf, *bmbuf;
	int kwlen, bmlen = 0;

	if (!kwstr) {
		return NULL;
	}

	if (!(kwbuf = malloc (strlen (kwstr)+1))) {
		return NULL;
	}
	kwlen = r_hex_str2bin (kwstr, kwbuf);
	if (kwlen < 1) {
		free (kwbuf);
		return NULL;
	}

	bmbuf = NULL;
	if (bmstr && *bmstr) {
		if (!(bmbuf = malloc (strlen (bmstr)+1))) {
			free (kwbuf);
			return NULL;
		}
		bmlen = r_hex_str2bin (bmstr, bmbuf);
		if (bmlen < 1) {
			bmlen = -bmlen;
			free (bmbuf);
			free (kwbuf);
			return NULL;
		}
	}

	kw = r_search_keyword_new (kwbuf, kwlen, bmbuf, bmlen, data);
	free (kwbuf);
	free (bmbuf);
	return kw;
}

R_API RSearchKeyword* r_search_keyword_new_hexmask(const char *kwstr, const char *data) {
	RSearchKeyword *ks = NULL;
	ut8 *kw, *bm;
	if (kwstr != NULL) {
		int len = strlen (kwstr);
		if ((kw = malloc (len + 4)) && (bm = malloc (len + 4))) {
			len = r_hex_str2binmask (kwstr, (ut8*)kw, (ut8*)bm);
			if (len<0)
				len = -len -1;
			if (len>0)
				ks = r_search_keyword_new (kw, len, bm, len, data);
		}
		free (kw);
		free (bm);
	}
	return ks;
}

/* Validate a regexp in the canonical format /<regexp>/<options> */
R_API RSearchKeyword *r_search_keyword_new_regexp (const char *str, const char *data) {
	RSearchKeyword *kw;
	int i = 0, start, length;

	while (isspace((const unsigned char)str[i]))
		i++;

	if (str[i++] != '/')
		return NULL;

	/* Find the fist non backslash-escaped slash */
	for (start = i; str[i]; i++) {
		if (str[i] == '/' && str[i-1] != '\\')
			break;
	}

	if (str[i++] != '/')
		return NULL;

	length = i - start - 1;
	if ((length > 128) || (length < 1))
		return NULL;

	kw = R_NEW0(RSearchKeyword);
	if (!kw)
		return NULL;

	if (!(kw->bin_keyword = malloc (length+1))) {
		r_search_keyword_free (kw);
		return NULL;
	}

	kw->bin_keyword[length]=0;
	memcpy(kw->bin_keyword, str + start, length);
	kw->keyword_length = length;
	kw->type = R_SEARCH_KEYWORD_TYPE_STRING;
	kw->data = (void *) data;

	/* Parse the options */
	for (; str[i]; i++) {
		switch (str[i]) {
			case 'i':
				kw->icase = true;
				break;
			default:
				r_search_keyword_free (kw);
				return NULL;
		}
	}

	return kw;
}
