/* radare - LGPL - Copyright 2013 - pancake */
/* ansi 256 color extension for r_cons */
/* https://en.wikipedia.org/wiki/ANSI_color */

#include <r_cons.h>

static void unrgb(int color, int *r, int *g, int *b);

static int gs (int rgb) {
	return 232 + (double)rgb/(255/24.1);
}

static int rgb(int r, int g, int b) {
	const double k = (256.0/6.0);
	int grey = 0;
	if (r > 0 && r < 255 && r == g && r == b) grey = 1;
	if (grey > 0) {
		return 232 + (int)r*3/33.0;
	} else {
		r = R_DIM (r/k, 0, 6);
		g = R_DIM (g/k, 0, 6);
		b = R_DIM (b/k, 0, 6);
		return 16 + (r*36) + (g*6) + b;
	}
}

static void unrgb(int color, int *r, int *g, int *b) {
	if (color > 16 && color < 232) {
		for (int rc = 0; rc < 256; rc+=51) {
			for (int gc = 0; gc < 256; gc+=51) {
				for (int bc = 0; bc < 256; bc+=51) {
					int i = rgb(rc, gc, bc);
					if(color == i) {
						*r = rc; *g = gc; *b = bc;
						return;
					}
				}
			}
		}
	} else if(color > 231 && color < 256) {
		*r = *g = *b = (int)(color - 232)*33.0/3;
		return;
	}
	// const double k = (256.0/6.0);
	// int R, G, B;
	// color -= 16;
	// B = (color/1) & 7; if (b) *b = (B*k); color -= B;
	// G = (color/6) & 7; if (g) *g = (G*k); color -= G;
	// R = (color/36)& 7; if (r) *r = (R*k); color -= R;
}

static inline void rgbinit(int r, int g, int b) {
#if __UNIX__
	r_cons_printf ("\x1b]4;%d;rgb:%2.2x/%2.2x/%2.2x\x1b\\",
			16 + (r * 36) + (g * 6) + b,
			(r ? (r * 40 + 55) : 0),
			(g ? (g * 40 + 55) : 0),
			(b ? (b * 40 + 55) : 0));
#endif
}

R_API void r_cons_rgb_init (void) {
	int r, g, b;
	for (r = 0; r < 6; r++)
		for (g = 0; g < 6; g++)
			for (b = 0; b < 6; b++)
				rgbinit (r, g, b);
}

R_API int r_cons_rgb_parse (const char *p, ut8 *r, ut8 *g, ut8 *b, int *is_bg) {
	const char *q = 0;
	int isbg = 0, bold=127;
	//const double k = (256/6);
	if (!p) return 0;
	if (*p==0x1b) p++;
	if (*p!='[') return 0;
	switch (p[1]) {
	case '1': bold=255; p+=2; break;
	case '3': isbg=0; break;
	case '4': isbg=1; break;
	}
#define SETRGB(x,y,z) if(r)*r=(x);if(g)*g=(y);if(b)*b=(z)
	if (bold != 255 && strchr (p, ';')) {
		if (p[4]=='5')  {
			int x, y, z;
			int n = atoi (p+6);
			unrgb (n, &x, &y, &z);
			SETRGB (x,y,z);
		} else {
			/* truecolor */
			p += 6;
			/* complex rgb */
			if (r) *r = atoi (p);
			q = strchr (p, ';');
			if (!q) return 0;
			if (g) *g = atoi (q+1);
			q = strchr (q+1, ';');
			if (!q) return 0;
			if (b) *b = atoi (q+1);
		}
		return 1;
	} else {
		/* plain ansi */
		if (is_bg) *is_bg = isbg;
		switch (p[2]) {
		case '0': SETRGB (0,0,0); break;
		case '1': SETRGB (bold,0,0); break;
		case '2': SETRGB (0,bold,0); break;
		case '3': SETRGB (bold,bold,0); break;
		case '4': SETRGB (0,0,bold); break;
		case '5': SETRGB (bold,0,bold); break;
		case '6': SETRGB (0,bold,bold); break;
		case '7': SETRGB (bold,bold,bold); break;
		}
	}
	return 1;
}

R_API char *r_cons_rgb_str (char *outstr, ut8 r, ut8 g, ut8 b, int is_bg) {
	int k, fgbg = is_bg? 48: 38;
	k = (r == g && g == b)?  gs (r): rgb (r, g, b);
	//k = rgb (r, g, b);
	if (!outstr) outstr = malloc (32);

	switch (r_cons_singleton()->truecolor) {
	case 1: // 256 color palette
		sprintf (outstr, "\x1b[%d;5;%dm", fgbg, k);
		break;
	case 2: // 16M - xterm only
		sprintf (outstr, "\x1b[%d;2;%d;%d;%dm", fgbg,
			r&0xff, g&0xff, b&0xff);
		break;
	case 0: // ansi 16 colors
	default:
		{
		int k = (r+g+b)/3;
		r = (r>k)?1:0;
		g = (g>k)?1:0;
		b = (b>k)?1:0;
		k = (r?1:0) + (g? (b?6:2): (b?4:0));
		sprintf (outstr, "\x1b[%dm", 30+k);
		}
		break;
	}
	return outstr;
}

R_API void r_cons_rgb (ut8 r, ut8 g, ut8 b, int is_bg) {
#if __WINDOWS__
	#warning r_cons_rgb not yet supported on windows
#else
	char outstr[64];
	r_cons_strcat (r_cons_rgb_str (outstr, r, g, b, is_bg));
#endif
}

R_API void r_cons_rgb_fgbg (ut8 r, ut8 g, ut8 b, ut8 R, ut8 G, ut8 B) {
	r_cons_rgb (r, g, b, 0);
	r_cons_rgb (R, G, B, 1);
}
