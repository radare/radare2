/* radare - LGPL - Copyright 2010-2015 - pancake */

#include <r_egg.h>

#define CTX egg->context
char *nested[32] = {0};
char *nestede[32] = {0};
int nestedi[32] = {0};

static inline int is_var(char *x) {
    return (x[0]=='.'||((x[0]=='*'||x[0]=='&')&&x[1]=='.'));
}

static inline int is_space(char c) {
    return (c==' '||c=='\t'||c=='\n'||c=='\r');
}

static const char *skipspaces(const char *s) {
    while (is_space (*s))
        s++;
    return s;
}

/* chop word by space/tab/.. */
/* NOTE: ensure string does not starts with spaces */
static char *trim(char *s) {
    char *o;
    for (o=s; *o; o++)
        if (is_space (*o))
            *o = 0;
    return s;
}

static void rcc_pushstr(REgg *egg, char *str, int filter);
static void rcc_context(REgg *egg, int delta);
static struct {
    char *name;
    char *body;
    //int fastcall; /* TODO: NOT YET USED */
} inlines[256];
static int ninlines = 0;

static struct {
    char *name;
    char *arg;
    //int sysnum; /* TODO: NOT YET USED */
} syscalls[256];

static struct {
    char *name;
    char *content;
} aliases[256];

enum {
    NORMAL = 0,
    ALIAS,
    INCLUDE,
    DATA,
    INLINE,
    NAKED,
    SYSCALL,
    SYSCALLBODY,
    GOTO,
    LAST
};

// XXX : globals are ugly
static int pushargs = 0;
static int nalias = 0;
static int nsyscalls = 0;
static char *syscallbody = NULL;
static char *includefile = NULL;
static char *setenviron = NULL;
static int commentmode = 0;
static int varsize = 'l';
static int varxs = 0;
static int lastctxdelta = 0;
static int nargs = 0;
static int docall = 1; /* do call or inline it ? */ // BOOL
static int nfunctions = 0;
static int nbrackets = 0;
static int slurpin = 0;
static int slurp = 0;
static int line = 1;
static char elem[1024];
static int attsyntax = 0;
static int elem_n = 0;
static char *callname = NULL;
static char *endframe = NULL;
static char *ctxpush[32];
static char *file = "stdin";
static char *dstvar = NULL;
static char *dstval = NULL;
static char *includedir = NULL;
static int ndstval = 0;
static int skipline = 0; // BOOL
static int quoteline = 0;
static int quotelinevar = 0;
static int stackframe = 0;
static int stackfixed = 0;
static int oc = '\n';
static int mode = NORMAL;

static char *find_include(const char *prefix, const char *file) {
    char *pfx = NULL, *ret = NULL, *env = r_sys_getenv (R_EGG_INCDIR_ENV);
//edited by izhuer
eprintf ("find_include (%s,%s)\n", prefix, file);
eprintf ("R_EGG_INCDIR_ENV: %s\n", env);
    if (!prefix) prefix = "";
    if (*prefix=='$') {
        char *out = r_sys_getenv (prefix+1);
        pfx = out? out: strdup ("");
    } else {
        pfx = strdup (prefix);
        if (!pfx) {
            free (env);
            return NULL;
        }
    }

    if (env) {
        char *str, *ptr = strchr (env, ':');
    //    eprintf ("MUST FIND IN PATH (%s)\n", env);
        str = env;
        while (str) {
            if (ptr)
                *ptr = 0;
            free (ret);
            ret = r_str_appendf (NULL, "%s/%s", pfx, file);
            {
                char *filepath = r_str_appendf (NULL, "%s/%s/%s", str, pfx, file);
                // eprintf ("try (%s)\n", filepath);
                if (r_file_exists (filepath)) {
                    free (env);
                    free (pfx);
                    free (ret);
                    return filepath;
                }
                free (filepath);
            }
            if (!ptr) break;
            str = ptr+1;
            ptr = strchr (str, ':');
        }
        free (env);
    } else ret = r_str_appendf (NULL, "%s/%s", pfx, file);
//edited by izhuer
eprintf ("find_include (%s,%s)\n", pfx, file);
    free (pfx);
    return ret;
}

R_API void r_egg_lang_include_path (REgg *egg, const char *path) {
    char *tmp_ptr = NULL;
    char *env = r_sys_getenv (R_EGG_INCDIR_ENV);
    if (!env || !*env) {
        r_egg_lang_include_init (egg);
        free (env);
        env = r_sys_getenv (R_EGG_INCDIR_ENV);
        tmp_ptr = env;
    }
    env = r_str_appendf (NULL, "%s:%s", path, env);
    free (tmp_ptr);
    r_sys_setenv (R_EGG_INCDIR_ENV, env);
    free (env);
}

R_API void r_egg_lang_include_init (REgg *egg) {
    r_sys_setenv (R_EGG_INCDIR_ENV, ".:"R_EGG_INCDIR_PATH);
}

static void rcc_set_callname(const char *s) {
    free (callname);
    callname = NULL;
    nargs = 0;
    callname = trim (strdup (skipspaces (s)));
    pushargs = !((!strcmp (s, "goto")) || (!strcmp (s, "break")));
}

static void rcc_reset_callname() {
    R_FREE (callname);
    nargs = 0;
}

#define SYNTAX_ATT 0
#if SYNTAX_ATT
#define FRAME_FMT ".LC%d_%d_frame%d"
#define FRAME_END_FMT ".LC%d_%d_end_frame%d"
#else
#define FRAME_FMT "__%d_%d_frame%d"
#define FRAME_END_FMT "__%d_%d_end_frame%d"
#endif

#if 0
static char *get_frame_label(int type) {
    static char label[128];
    int nf = nfunctions;
    int nb = nbrackets;
    int ct = context;
    /* TODO: this type hack to substruct nb and ctx looks weird */
#if 1
    if (type == 1) nb--; else
    if (type == 2) ct--;
#endif
    /* THIS IS GAS_ONLY */
    snprintf (label, sizeof (label), FRAME_FMT, nf, nb, ct);
    return label;
}

static char *get_end_frame_label(REgg *egg) {
    static char label[128];
    snprintf (label, sizeof (label)-1, FRAME_END_FMT,
        nfunctions, nbrackets, context-1);
//eprintf ("--> (endframe: %d %d %d)\n", nfunctions, nbrackets, context);
    //snprintf (label, sizeof (label)-1, "frame_end_%d_%d", nfunctions, nbrackets);
    return label;
}
#endif

static const char * find_alias(const char *str) {
//edited by izhuer
eprintf("Getting into find_alias with str: %s\n", str);
    // do not forget to free return strings to avoid memory leak
    char *p = (char *)str;
    if (*str == '"')
        return strdup(str);
        // strings could not means aliases
    while ( *p && ! is_space(*p)) p++;
    *p = '\x00';
    for (int i = 0; i < nalias; i++)
        if (! strcmp(str, aliases[i].name))
            return strdup(aliases[i].content);
    return NULL;
    // only strings or alias could return valuable data 
}

static void rcc_pusharg(REgg *egg, char *str) {
    REggEmit *e = egg->remit;
    char buf[64], *p = r_egg_mkvar (egg, buf, str, 0);
    if (!p) return;
    // TODO: free (ctxpush[context]);
    ctxpush[CTX] = strdup (p); // INDEX IT WITH NARGS OR CONTEXT?!?
    nargs++;
    if (pushargs)
        e->push_arg (egg, varxs, nargs, p);
    //ctxpush[context+nbrackets] = strdup(str); // use nargs??? (in callname)
    free (p);
}

static void rcc_element(REgg *egg, char *str) {
    REggEmit *e = egg->remit;
    char *ptr, *p = str + strlen(str);
    int inside = 0;
    int num, num2;
    int i;

//fixed by izhuer
    if (CTX) {
        if (slurp == '"') {
            if (mode == NORMAL) {
                if (!dstvar)
                    dstvar = strdup(".fix0");
                rcc_pushstr(egg, str, 1);
            }
        } else {
            nargs = 0;
            if (mode == GOTO)
                mode = NORMAL; // XXX
            while (p-- != str) {
                if (*p == '"')
                    inside ^= 1;
                else if (*p == ',' && !inside){
                    *p = '\0';
                    p = (char *)skipspaces (p+1);
                    rcc_pusharg (egg, p);
                }
            }
            rcc_pusharg (egg, str);
        }
    } else {
//fixed by izhuer
eprintf("Getting into rcc_element with str: %s\n", str);
        switch (mode) {
        case ALIAS:
            e->equ (egg, dstvar, str);
            if (nalias > 255) {
                eprintf("global-buffer-overflow in aliases\n");
                break;
            }
            if (dstvar == NULL || str == NULL){
                eprintf ("does not set name or content for alias\n");
                break;
            }
            for (i = 0; i < nalias; i++)
                if (! strcmp(dstvar, aliases[i].name)) {
                    R_FREE (aliases[i].name);
                    R_FREE (aliases[i].content);
                    break;
                }
            aliases[i].name = strdup(dstvar);
            aliases[i].content = strdup(str);
            nalias = (i == nalias) ? nalias + 1 : nalias;
            //allow alias overwrite
            R_FREE (dstvar);
            mode = NORMAL;
            break;
        case SYSCALL:
            if (nsyscalls > 255) {
                eprintf ("global-buffer-overflow in syscalls\n");
                break;
            }
//fixed by izhuer
            if (dstvar == NULL || str == NULL){
                eprintf ("does not set name or arg for syscall\n");
                break;
            }
            //XXX the mem for name and arg are not freed - MEMLEAK
            syscalls[nsyscalls].name = strdup (dstvar);
            syscalls[nsyscalls].arg = strdup (str);
            nsyscalls++;
            R_FREE (dstvar);
            break;
        case GOTO:
            elem[elem_n] = 0;
            e->jmp (egg, elem, 0);
            break;
        case INCLUDE:
            str = ptr = (char *)find_alias(skipspaces(str));
//edited by izhuer
eprintf("Getting out of find_alias with return value: %s\n", ptr);
            if (ptr != NULL){
                if (strchr(ptr, '"')){
                    ptr = strchr(ptr, '"') + 1;
                    if ((p = strchr(ptr, '"')))
                        *p = '\x00';
                    else eprintf("loss back quote in include directory\n");
                    includedir = strdup(ptr);
                } else {
                    eprintf("wrong include syntax\n");
                    //for must use string to symbolize directory
                    includedir = NULL;
                }
            } else
                includedir = NULL;
            R_FREE (str);
            eprintf("Test: ptr: %s\n", ptr);
            break;
        default:
            p = strchr (str, ',');
            if (p) {
                *p='\0';
                num2 = atoi (p+1);
            } else num2 = 0;
            num = atoi (str) + num2;
            stackframe = num;
            stackfixed = num2;
            if (mode != NAKED)
                e->frame (egg, stackframe+stackfixed);
        }
        elem[0] = 0;
        elem_n = 0;
    }
}

static void rcc_pushstr(REgg *egg, char *str, int filter) {
        int dotrim;
        int i, j, len, ch;
        REggEmit *e = egg->remit;

        e->comment (egg, "encode %s string (%s) (%s)",
                filter? "filtered": "unfiltered", str, callname);

//fixed by izhuer
        if (filter)
        for (i=0; str[i]; i++) {
            dotrim = 0;
            if (str[i]=='\\') {
                    switch (str[i+1]) {
                    case 't': 
                        str[i]='\t';
                        dotrim = 1;
                        break;
                    case 'n': 
                        str[i]='\n';
                        dotrim = 1;
                        break;
                    case 'e': 
                        str[i]='\x1b';
                        dotrim = 1;
                        break;
                    case 'x':
                        ch = r_hex_pair2bin(str+i+2);
                        if (ch == -1)
                            eprintf("%s:%d Error string format\n",
                                   file, line);
                        str[i] = (char)ch;
                        dotrim = 3;
                        break;
                    default: 
                        dotrim = 0; 
                        break;
                    }
                    if (dotrim)
                            memmove (str+i+1, str+i+dotrim+1, 
                                     strlen (str+i+dotrim+1)+1);
                            // DO NOT forget the '\x00' terminate char
            }
        }

        len = strlen (str);
        j = (len-len%e->size)+e->size;
//edited by izhuer
eprintf("Getting into rcc_pushstr with str: %s\n", str);
eprintf("Getting into rcc_pushstr with len: %lu\n", strlen(str));
eprintf("Getting into rcc_pushstr with j: %d\n", j);
        e->set_string (egg, dstvar, str, j);
        free (dstvar);
        dstvar = NULL;
}

R_API char *r_egg_mkvar(REgg *egg, char *out, const char *_str, int delta) {
    int i, idx, len, qi;
    char *oldstr = NULL, *str = NULL, foo[32], *q, *ret = NULL;

//edited by izhuer
eprintf("Getting into r_egg_mkvar with _str: %s\n", _str);
eprintf("Getting into r_egg_mkvar with delta: %d\n", delta);
    delta += stackfixed; // XXX can be problematic
    if (!_str)
        return NULL; /* fix segfault, but not badparsing */
    /* XXX memory leak */
    ret = str = oldstr = strdup (skipspaces (_str));
    //if (num || str[0]=='0') { sprintf(out, "$%d", num); ret = out; }
    if ( (q = strchr (str, ':')) ) {
        *q = '\0';
        qi = atoi (q+1);
        varsize = (qi==1)? 'b': 'l';
    } else varsize='l';
    if (*str == '*' || *str == '&') {
        varxs = *str;
        str++;
    } else varxs = 0;
    if (str[0] == '.') {
        REggEmit *e = egg->remit;
        idx = atoi (str+4) + delta + e->size;
        if (!strncmp (str+1, "ret", 3)) {
            strcpy (out, e->retvar);
        } else
        if (!strncmp (str+1, "fix", 3)) {
            e->get_var (egg, 0, out, idx-stackfixed);
            //sprintf(out, "%d(%%"R_BP")", -(atoi(str+4)+delta+R_SZ-stackfixed));
        } else
        if (!strncmp (str+1, "var", 3)) {
            e->get_var (egg, 0, out, idx);
        //sprintf(out, "%d(%%"R_BP")", -(atoi(str+4)+delta+R_SZ));
        } else
        if (!strncmp (str+1, "arg", 3)) {
            if (str[4]) {
                if (stackframe == 0) {
                    e->get_var (egg, 1, out, 4); //idx-4);
                } else {
                    e->get_var (egg, 2, out, idx+4);
                }
            } else {
                /* TODO: return size of syscall */
                if (callname) {
                    for (i=0; i<nsyscalls; i++)
                        if (!strcmp (syscalls[i].name, callname)) {
                            free (oldstr);
                            return strdup(syscalls[i].arg);
                        }
                    eprintf ("Unknown arg for syscall '%s'\n", callname);
                } else eprintf ("NO CALLNAME '%s'\n", callname);
            }
        } else
        if (!strncmp (str+1, "reg", 3)) {
            // XXX: can overflow if out is small
            if (attsyntax)
                snprintf (out, 32, "%%%s", e->regs (egg, atoi (str+4)));
            else snprintf (out, 32, "%s", e->regs (egg, atoi (str+4)));
        } else {
            out = str; /* TODO: show error, invalid var name? */
            eprintf ("Something is really wrong\n");
        }
        ret = strdup(out);
        free (oldstr);
    } else if (*str=='"' || *str=='\'') {
        int mustfilter = *str=='"';
        /* TODO: check for room in stackfixed area */
        str++;
        len = strlen (str)-1;
        if (!stackfixed || stackfixed <len)
            eprintf ("WARNING: No room in the static stackframe! (%d must be %d)\n",
                stackfixed, len);
        str[len]='\0';
        snprintf (foo, sizeof (foo)-1, ".fix%d", nargs*16); /* XXX FIX DELTA !!!1 */
        free(dstvar);
        dstvar = strdup (skipspaces (foo));
        rcc_pushstr (egg, str, mustfilter);
        ret = r_egg_mkvar (egg, out, foo, 0);
        free (oldstr);
    }
    return ret;
}

static void rcc_fun(REgg *egg, const char *str) {
    char *ptr, *ptr2;
    REggEmit *e = egg->remit;
    str = skipspaces (str);
eprintf("Getting into rcc_fun with str: %s\n", str);
    if (CTX) {
        ptr = strchr (str, '=');
        if (ptr) {
            *ptr++ = '\0';
            free (dstvar);
            dstvar = strdup (skipspaces (str));
            ptr2 = (char *)skipspaces (ptr);
            if (*ptr2)
                rcc_set_callname (skipspaces (ptr));
        } else {
            str = skipspaces (str);
            rcc_set_callname (skipspaces (str));
            egg->remit->comment (egg, "rcc_fun %d (%s)",
                CTX, callname);
        }
    } else {
        ptr = strchr (str, '@');
        if (ptr) {
            *ptr++ = '\0';
            mode = NORMAL;
            if (strstr (ptr, "env")) {
                //eprintf ("SETENV (%s)\n", str);
                free (setenviron);
                setenviron = strdup (skipspaces (str));
                slurp = 0;
            } else
            if (strstr (ptr, "fastcall")) {
                /* TODO : not yet implemented */
            } else
            if (strstr (ptr, "syscall")) {
                if (*str) {
                    mode = SYSCALL;
                    dstvar = strdup (skipspaces (str));
                } else {
                    mode = INLINE;
                    free (syscallbody);
                    syscallbody = malloc (4096); // XXX hardcoded size
                    dstval = syscallbody;
                    R_FREE (dstvar);
                    ndstval = 0;
                    *syscallbody = '\0';
                }
            } else
            if (strstr (ptr, "include")) {
                mode = INCLUDE;
                free (includefile);
                includefile = strdup (skipspaces (str));
//edited by izhuer
eprintf("Getting into rcc_fun with includefile: %s\n", includefile);
                //slurp = 0;
                //try to deal with alias
            } else
            if (strstr (ptr, "alias")) {
                mode = ALIAS;
                ptr2 = dstvar = strdup (skipspaces (str));
                while ( *ptr2 && ! is_space(*ptr2)) ptr2++;
                *ptr2 = '\x00';
                //for aliases must be valid and accurate strings
            } else
            if (strstr (ptr, "data")) {
                mode = DATA;
                ndstval = 0;
                dstvar = strdup (skipspaces (str));
                dstval = malloc (4096);
            } else
            if (strstr (ptr, "naked")) {
                mode = NAKED;
                free (dstvar);
                dstvar = strdup (skipspaces (str));
                dstval = malloc (4096);
                ndstval = 0;
                r_egg_printf (egg, "%s:\n", str);
            } else
            if (strstr (ptr, "inline")) {
                mode = INLINE;
                free (dstvar);
                dstvar = strdup (skipspaces (str));
                dstval = malloc (4096);
                ndstval = 0;
            } else {
                // naked label
                if (*ptr)
                    r_egg_printf (egg, "\n.%s %s\n", ptr, str);
                r_egg_printf (egg, "%s:\n", str);
            }
        } else {
eprintf("Getting into rcc_fun with str: %s\n", str);
            //e->jmp (egg, ctxpush[context], 0);
            if (CTX>0) {
                // WTF?
                eprintf ("LABEL %d\n", CTX);
                r_egg_printf (egg, "\n%s:\n", str);
            } else {
                if (!strcmp (str, "goto")) {
                    mode = GOTO;
                } else {
                    // call() // or maybe jmp?
                    e->call (egg, str, 0);
                }
            }
        }
    }
}

#if 0
static void shownested() {
    int i;
    eprintf ("[[[NESTED %d]]] ", context);
    for(i=0;nested[i];i++) {
        eprintf ("%s ", nested[i]);
    }
    eprintf("\n");
}
#endif

static void set_nested(REgg *egg, const char *s) {
    int c = CTX-1;
    int i=0;
    if (CTX<1)
        return;
    free (nested[c]);
    nested[c] = strdup (s);
    nestedi[c]++;
    /** clear inner levels **/
    for (i=0; i<10; i++) {
        //nestedi[context+i] = 0;
        free (nested[CTX+i]);
        nested[CTX+i] = NULL;
    }
}

static void rcc_context(REgg *egg, int delta) {
    REggEmit *emit = egg->remit;
    char str[64];

//edited by izhuer
eprintf("Getting into rcc_context with delta: %d\n", delta);
eprintf("Getting into rcc_context with callname: %s\n", callname);

    if (CTX>31 || CTX <0)
        return;

    nestedi[CTX]++;
    if (callname && CTX>0) {// && delta>0) {
    //    set_nested (callname);
//eprintf (" - - - - - - -  set nested d=%d c=%d (%s)\n", delta, context-1, callname);
//shownested();
    }
    CTX += delta;
    lastctxdelta = delta;

    if (CTX == 0 && delta < 0) {
        if (mode != NAKED)
            emit->frame_end (egg, stackframe+stackfixed, nbrackets);
        if (mode == NORMAL) /* XXX : commenting this makes hello.r unhappy! TODO: find a cleaner alternative */
            stackframe = 0;
        mode = NORMAL;
    } else {
        /* conditional block */
//eprintf ("Callname is (%s)\n", callname);
        const char *elm = skipspaces (elem);
        const char *cn = callname;
//if (nested[context-1])
#if 0
if (delta<0 && context>0) {
eprintf ("close bracket foo!!!\n");
shownested ();
cn = strdup (nested[context-1]);
eprintf ("STATEMENT cn=(%s) idx=%d (%s)\n", cn, context-1, nested[context-1]);
eprintf ("CNTXXXPUSH (%s)\n", ctxpush[context-1]);
#if 0
if (!strcmp (cn, "while")) {
emit->while_end (egg, get_frame_label (context-1));
    //char *var = get_frame_label (0);
    //emit->jmp (egg, var, 0);
    return;
}
#endif
}
#endif
//eprintf ("ELEM (%s)\n", elm);
//eprintf ("END BLOCK %d, (%s)\n", context, nested[context-1]);
//eprintf ("CN = (%s) %d (%s) delta=%d\n", cn, context, nested[context-1], delta);
        if (cn) {
        //if (callname) { // handle 'foo() {'
            /* TODO: this must be an array */
            char *b, *g, *e, *n;
            emit->comment (egg, "cond frame %s (%s)", cn, elm);
            /* TODO: simplify with a single for */
            b = strchr (elem, '<'); /* below */
            g = strchr (elem, '>'); /* greater */
            e = strchr (elem, '='); /* equal */
            n = strchr (elem, '!'); /* negate */
            if (!strcmp (cn, "while")) {
                char lab[128];
                sprintf (lab, "__begin_%d_%d_%d", nfunctions,
                    CTX-1, nestedi[CTX-1]);
                emit->get_while_end (egg, str, ctxpush[CTX-1], lab); //get_frame_label (2));
//get_frame_label (2));
//eprintf ("------ (%s)\n", ctxpush[context-1]);
            //    free (endframe);
// XXX: endframe is deprecated, must use set_nested only
                if (delta>0) {
                    set_nested (egg, str);
                }
                rcc_set_callname ("if"); // append 'if' body
            }
            if (!strcmp (cn, "if")) {
                //emit->branch (egg, b, g, e, n, varsize, get_end_frame_label (egg));
                // HACK HACK :D
                sprintf (str, "__end_%d_%d_%d", nfunctions,
                    CTX-1, nestedi[CTX-1]);
                nestede[CTX-1] = strdup (str);
                sprintf (str, "__end_%d_%d_%d", nfunctions,
                    CTX, nestedi[CTX-1]);
                emit->branch (egg, b, g, e, n, varsize, str);
                if (CTX>0) {
                    /* XXX .. */
                }
                rcc_reset_callname ();
            } //else eprintf ("Unknown statement (%s)(%s)\n", cn, elem);
        } // handle '{ ..'
    }
}

static int parsedatachar(REgg *egg, char c) {
    static int inlinectr = 0;
    char *str;
    int i, j;

    if (!dstval) {
        return 0;
    }
    /* skip until '{' */
    if (c == '{') { /* XXX: repeated code!! */
        rcc_context (egg, 1);
        if (++inlinectr==1)
            return (ndstval = 0);
    } else if (inlinectr == 0) {
        /* capture value between parenthesis foo@data(NNN) { ... } */
        if (c==')') {
            stackframe = atoi (dstval);
            ndstval = 0;
        } else {
            dstval[ndstval++] = c;
        }
        return 0;
    }
    /* capture body */
    if (c == '}') { /* XXX: repeated code!! */
        if (CTX< 2) {
            inlinectr = 0;
            rcc_context (egg, -1);
            slurp = 0;
            mode = NORMAL;
            /* register */
            if (dstval != NULL && dstvar != NULL) {
                dstval[ndstval]='\0';
                egg->remit->comment (egg, "data (%s)(%s)size=(%d)\n",
                    dstvar, dstval, stackframe);
                r_egg_printf (egg, ".data\n");
                for (str=dstval; is_space (*str); str++);
                j = (stackframe)? stackframe: 1;
                /* emit label */
                r_egg_printf (egg, "%s:\n", dstvar);
                for (i=1; i<=j; i++) {
                    if (*str=='"')
                        r_egg_printf (egg, ".ascii %s%s\n", dstval, (i==j)?"\"\\x00\"":"");
                    else r_egg_printf (egg, ".long %s\n", dstval);
                }
                r_egg_printf (egg, ".text\n");
                R_FREE (dstvar);
                R_FREE (dstval);
                ndstval = 0;
                CTX = 0;
                return 1;
            }
        }
    }
    dstval[ndstval++] = c;
    return 0;
}

static int parseinlinechar(REgg *egg, char c) {
    static int inlinectr = 0;

    /* skip until '{' */
    if (c == '{') { /* XXX: repeated code!! */
        rcc_context (egg, 1);
        inlinectr++;
        if (inlinectr==1)
            return 0;
    } else
    if (inlinectr == 0)
        return 0;

    /* capture body */
    if (c == '}') { /* XXX: repeated code!! */
        if (CTX < 2) {
            rcc_context (egg, -1);
            slurp = 0;
            mode = NORMAL;
            inlinectr = 0;
            if (!dstvar && dstval == syscallbody) {
                dstval = NULL;
                return 1;
            } else
            /* register */
            if (dstval != NULL && dstvar != NULL) {
                dstval[ndstval]='\0';
                //printf(" /* END OF INLINE (%s)(%s) */\n", dstvar, dstval);
                inlines[ninlines].name = strdup (skipspaces (dstvar));
                inlines[ninlines].body = strdup (skipspaces (dstval));
                ninlines++;
                R_FREE (dstvar);
                R_FREE (dstval);
                return 1;
            }
            eprintf ("Parse error\n");
        }
    }
    dstval[ndstval++] = c;
    dstval[ndstval]=0;
    return 0;
}

/* TODO: split this function into several ones..quite long fun */
static void rcc_next(REgg *egg) {
    const char *ocn;
    REggEmit *e = egg->remit;
    char *str = NULL, *p, *ptr, buf[64];
    int i;

    if (setenviron) {
        elem[elem_n - 1] = 0;
        r_sys_setenv (setenviron, elem);
        R_FREE (setenviron);
        return;
    }
//edited by izhuer
eprintf("Getting into rcc_next with includefile: %s\n", includefile);
    if (includefile) {
        char *p, *q, *path;
        elem[elem_n-1] = 0;
        path = find_include (includedir, includefile);
//edited by izhuer
eprintf("Including file: %s\n", path);
eprintf("Including file with elem: %s\n", elem);
        if (!path) {
            eprintf ("Cannot find include file '%s'\n", elem);
            return;
        }
        free (includefile);
        free (includedir);
        includefile = includedir = NULL;
        rcc_reset_callname ();
        p = q = r_file_slurp (path, NULL);
        if (p) {
            int oline = ++line;
            elem[0] = 0; // TODO: this must be a separate function
            elem_n = 0;
            line = 0;
            for (; *p; p++)
                r_egg_lang_parsechar (egg, *p);
            free (q);
            line = oline;
        } else {
            eprintf ("Cannot find '%s'\n", path);
        }
        free (path);
        return;
    }
    docall = 1;
    if (callname) {
//edited by izhuer
eprintf("Getting into rcc_next with callname: %s\n", callname);
        if (!strcmp (callname, "goto")) {
            if (nargs != 1) {
                eprintf ("Invalid number of arguments for goto()\n");
                return;
            }
            e->jmp (egg, ctxpush[CTX], 0);
            rcc_reset_callname ();
            return;
        }
        if (!strcmp (callname, "break")) {
            e->trap (egg);
            rcc_reset_callname ();
            return;
        }
        ptr = strchr (callname, '=');
        if (ptr) {
            *ptr = '\0';
            //ocn = ptr+1; // what is the point of this?
        }
        ocn = skipspaces (callname);
        if (!ocn) return;
        str = r_egg_mkvar (egg, buf, ocn, 0);
        if (!str) {
            eprintf ("Cannot mkvar\n");
            return;
        }
        if (*ocn=='.')
            e->call (egg, str, 1);
        if (!strcmp (str, "while")) {
            char var[128];
            if (lastctxdelta >= 0)
                exit (eprintf ("ERROR: Unsupported while syntax\n"));
            sprintf (var, "__begin_%d_%d_%d\n", nfunctions, CTX, nestedi[CTX-1]);
            e->while_end (egg, var); //get_frame_label (1));
#if 0
            eprintf ("------------------------------------------ lastctx: %d\n", lastctxdelta);
            // TODO: the pushvar is required for the if(){}while(); constructions
            //char *pushvar = ctxpush[context+nbrackets-1];
            /* TODO: support to compare more than one expression (LOGICAL OR) */
            rcc_printf ("  pop %%eax\n");
            rcc_printf ("  cmp $0, %%eax\n"); // XXX MUST SUPPORT != 0 COMPARE HERE
            /* TODO : Simplify!! */
            //if (pushvar)
            //    printf("  push %s /* wihle push */\n", pushvar);
            if (lastctxdelta<0)
                rcc_printf ("  jnz %s\n", get_frame_label (1));
            else rcc_printf ("  jnz %s\n", get_frame_label (0));
            //if (pushvar)
            //    printf("  pop %%"R_AX" /* while pop */\n");
#endif
            nargs = 0;
        } else {
            for (i = 0; i < nsyscalls; i++) {
                if (!strcmp (str, syscalls[i].name)) {
                    p = syscallbody;
                    e->comment (egg, "set syscall args");
                    e->syscall_args (egg, nargs);
                    docall = 0;
                    e->comment (egg, "syscall");
                    r_egg_lang_parsechar (egg, '\n'); /* FIX parsing issue */
                    if (p) {
                        for (; *p; p++)
                            r_egg_lang_parsechar (egg, *p);
                    } else {
                        char *q, *s = e->syscall (egg, nargs);
                        if (s) {
                            for (q=s; *q; q++)
                                r_egg_lang_parsechar (egg, *q);
                            free (s);
                        } else eprintf ("Cannot get @syscall payload\n");
                    }
                    docall = 0;
                    break;
                }
            }
            if (docall)
            for (i = 0; i < ninlines; i++) {
                if (!strcmp (str, inlines[i].name)) {
                    p = inlines[i].body;
                    docall = 0;
                    e->comment (egg, "inline");
                    r_egg_lang_parsechar (egg, '\n'); /* FIX parsing issue */
                    for (; *p; p++)
                        r_egg_lang_parsechar (egg, *p);
                    docall = 0;
                    break;
                }
            }
            if (docall) {
                e->comment (egg, "call in mode %d", mode);
                e->call (egg, str, 0);
            }
        }
        if (nargs > 0)
            e->restore_stack (egg, nargs*e->size);

//fixed by izhuer
        /*
        if (ocn) { // Used to call .var0()
            // WTF? ocn mustn't be NULL here
            // XXX: Probably buggy and wrong
            *buf = 0;
            free (str);
            str = r_egg_mkvar (egg, buf, ocn, 0);
            if (*buf)
                e->get_result (egg, buf); // Why should get_result into ocn?
            //else { eprintf("external symbol %s\n", ocn); }
        }
        */

        /* store result of call */
        if (dstvar) {
            if (mode != NAKED) {
                *buf = 0;
                free (str);
                str = r_egg_mkvar (egg, buf, dstvar, 0);
                if (*buf == 0)
                    eprintf ("Cannot resolve variable '%s'\n", dstvar);
                else e->get_result (egg, buf);
            }
            R_FREE (dstvar);
        }
        rcc_reset_callname ();
    } else { // handle mathop
        int vs = 'l';
        char type, *eq, *ptr = elem;
        elem[elem_n] = '\0';
        ptr = (char*)skipspaces (ptr);
        if (*ptr) {
            eq = strchr (ptr, '=');
            if (eq) {
                char str2[64], *p, ch = *(eq-1);
                *eq = '\0';
                eq = (char*) skipspaces (eq+1);
                p = r_egg_mkvar (egg, str2, ptr, 0);
                vs = varsize;
                if (is_var (eq)) {
                    eq = r_egg_mkvar (egg, buf, eq, 0);
                    if (varxs=='*')
                        e->load (egg, eq, varsize);
                    else
                    /* XXX this is a hack .. must be integrated with pusharg */
                    if (varxs=='&')
                        e->load_ptr (egg, eq);
                    if (eq) {
                        free (eq);
                        eq = NULL;
                    }
                    type = ' ';
                } else type = '$';
                vs = 'l'; // XXX: add support for != 'l' size
//edited by izhuer
eprintf("Getting into e->mathop with ch: %c\n", ch);
eprintf("Getting into e->mathop with vs: %c\n", vs);
eprintf("Getting into e->mathop with type: %c\n", type);
eprintf("Getting into e->mathop with eq: %s\n", eq);
eprintf("Getting into e->mathop with p: %s\n", p);
                e->mathop (egg, ch, vs, type, eq, p);
                free(p);
            } else {
                if (!strcmp (ptr, "break")) { // handle 'break;'
                    e->trap (egg);
                    rcc_reset_callname ();
                } else {
                    e->mathop (egg, '=', vs, '$', ptr, NULL);
                }
            }
        }
    }
    free (str);
}

R_API int r_egg_lang_parsechar(REgg *egg, char c) {
    REggEmit *e = egg->remit;
    char *ptr, str[64], *tmp_ptr = NULL;
    if (c=='\n') {
        line++;
        elem_n = 0;
    }
//edited by izhuer
eprintf ("----------------------------\n");
eprintf ("CH  %c\n", c);
eprintf ("OC  %c\n", oc);
eprintf ("elem  %*s\n", elem_n, elem);
eprintf ("elem_n  %d\n", elem_n);
eprintf ("mode  %d\n", mode);
eprintf ("skipline  %d\n", skipline);
eprintf ("slurp  %c\n", slurp);
eprintf ("----------------------------\n\n");
    /* comments */
    if (skipline) {
        if (c != '\n') {
            oc = c;
            return 0;
        }
        skipline = 0;
    }
    if (mode == DATA)
        return parsedatachar (egg, c);
    if (mode == INLINE)
        return parseinlinechar (egg, c);
    /* quotes */
    if (quoteline) {
        if (c != quoteline) {
            if (quotelinevar == 1) {
                if (c == '`') {
                    elem[elem_n] = 0;
                    elem_n = 0;
                    tmp_ptr = r_egg_mkvar (egg, str, elem, 0);
                    r_egg_printf (egg, "%s", tmp_ptr);
                    free (tmp_ptr);
                    quotelinevar = 0;
                } else elem[elem_n++] = c;
            } else {
                if (c == '`') {
                    elem_n = 0;
                    quotelinevar = 1;
                } else r_egg_printf (egg, "%c", c);
            }
            oc = c;
            return 0;
        } else {
            r_egg_printf (egg, "\n");
            quoteline = 0;
        }
    }

    if (commentmode) {
        if (c=='/' && oc == '*')
            commentmode = 0;
        oc = c;
        return 0;
    } else if (c=='*' && oc == '/')
        commentmode = 1;
    if (slurp) {
        if (slurp != '"' && c == slurpin)   // only happend when (...(...)...)
            exit (eprintf (
                "%s:%d Nesting of expressions not yet supported\n",
                file, line));
        if (c == slurp && oc != '\\') {  // close slurp
            elem[elem_n] = '\0';
            if (elem_n > 0)
                rcc_element (egg, elem);
            else e->frame (egg, 0);
            elem_n = 0;
            slurp = 0;
        } else elem[elem_n++] = c;
        elem[elem_n] = '\0';
    } else {
        switch (c) {
        case ';':
            rcc_next (egg);
            break;
        case '"':
            slurp = '"';
            break;
        case '(':
            slurpin = '(';
            slurp = ')';
            break;
        case '{':
            if (CTX>0) {
            //    r_egg_printf (egg, " %s:\n", get_frame_label (0));
                r_egg_printf (egg, " __begin_%d_%d_%d:\n",
                    nfunctions, CTX, nestedi[CTX]); //%s:\n", get_frame_label (0));
            }
            rcc_context (egg, 1);
            break;
        case '}':
            endframe = nested[CTX-1];
            if (endframe) {
                // XXX: use endframe[context]
                r_egg_printf (egg, "%s\n", endframe);
            //    R_FREE (endframe);
            }
            if (CTX>0) {
                if (nestede[CTX]) {
                    r_egg_printf (egg, "%s:\n", nestede[CTX]);
                    //nestede[CTX] = NULL;
                } else {
                    r_egg_printf (egg, "  __end_%d_%d_%d:\n",
                        nfunctions, CTX, nestedi[CTX-1]);
                    //get_end_frame_label (egg));
                }
                nbrackets++;
            }
            rcc_context (egg, -1);
            if (CTX== 0) {
                nbrackets = 0;
                nfunctions++;
            }
            break;
        case ':':
            if (oc == '\n' || oc == '}')
                quoteline = '\n';
            else elem[elem_n++] = c;
            break;
        case '#':
            if (oc == '\n')
                skipline = 1;
            break;
        case '/':
            if (oc == '/')
                skipline = 1;
            else elem[elem_n++] = c;
            break;
        default:
            elem[elem_n++] = c;
        }
        if (slurp) {
            if (elem_n) {
                ptr = elem;
                elem[elem_n] = '\0';
                while (is_space (*ptr)) ptr++;
                rcc_fun (egg, ptr);
            }
            elem_n = 0;
        }
    }
    if (c!='\t' && c!=' ')
        oc = c;
    return 0;
}
