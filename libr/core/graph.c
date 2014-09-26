/* Copyright radare2 2014 - Author: pancake */

#include <r_core.h>

// TODO: handle mouse wheel

typedef struct {
	int x;
	int y;
	int w;
	int h;
	ut64 addr;
	int depth;
	char *text;
} Node;

typedef struct {
	int nth;
	int from;
	int to;
} Edge;

static int curnode = 0;

#if 0
static Node nodes[] = {
	 {25,4, 18, 6, 0x8048320, "push ebp\nmov esp, ebp\njz 0x8048332" },
	 {10,13, 18, 5, 0x8048332, "xor eax, eax\nint 0x80\n"},
	 {30,13, 18, 5, 0x8048324, "pop ebp\nret"},
	{NULL}
};

static Edge edges[] = {
	{ 0, 0, 1 },
	{ 1, 0, 2 },
	{ -1 }
};
#endif

#define G(x,y) r_cons_canvas_gotoxy (can, x, y)
#define W(x) r_cons_canvas_write (can, x)
#define B(x,y,w,h) r_cons_canvas_box(can, x,y,w,h)
#define L(x,y,x2,y2) r_cons_canvas_line(can, x,y,x2,y2,0)
#define F(x,y,x2,y2,c) r_cons_canvas_fill(can, x,y,x2,y2,c,0)

static void Node_print(RConsCanvas *can, Node *n, int cur) {
	char title[128];

	if (!can)
		return;
	n->w = r_str_bounds (n->text, &n->h);
	n->w += 4;
	n->h += 3;
	n->w = R_MAX (18, n->w);
	{
		int x = n->x + can->sx;
		int y = n->y + n->h + can->sy;
		if (x<0 || x> can->w)
			return;
		if (y<0 || y> can->h)
			return;
	}
	if (cur) {
		//F (n->x,n->y, n->w, n->h, '.');
		snprintf (title, sizeof (title)-1,
			"-[ 0x%08"PFMT64x" ]-", n->addr);
	} else {
		snprintf (title, sizeof (title)-1,
			"   0x%08"PFMT64x"   ", n->addr);
	}
	if (G (n->x+1, n->y+1))
		W (title);
	if (G (n->x+2, n->y+2)) {
// TODO: temporary crop depending on out of screen offsets
//n->text = r_str_crop (n->text, 1,1,4,4);
		W (n->text);
	}
	if (G (n->x+1, n->y+1))
		W (title);
	B (n->x, n->y, n->w, n->h);
}

static void Edge_print(RConsCanvas *can, Node *a, Node *b, int nth) {
	int x, y, x2, y2;
	int xinc = 3+(nth*3);
	x = a->x + xinc;
	y = a->y + a->h;
	x2 = b->x + xinc;
	y2 = b->y;
	L (x, y, x2, y2);
}

static int Edge_node(Edge *edges, int cur, int nth) {
	int i;
	if (edges)
	for (i=0; edges[i].nth!=-1; i++) {
		if (edges[i].nth == nth)
			if (edges[i].from == cur)
				return edges[i].to;
	}
	return -1;
}

static int Node_find(const Node* nodes, ut64 addr) {
	int i;
	if (nodes)
	for (i=0; nodes[i].text; i++) {
		if (nodes[i].addr == addr)
			return i;
	}
	return -1;
}

static void Layout_depth2(Node *nodes, Edge *edges, int nth, int depth) {
	int j, f;
	if (!nodes || !nodes[nth].text)
		return;
	if (nodes[nth].depth != -1) {
		nodes[nth].depth = depth;
		return;
	} else nodes[nth].depth = depth;
	j = Edge_node (edges, nth, 0);
	if (j!=-1)
		Layout_depth2 (nodes, edges, j, depth+1);
	f = Edge_node (edges, nth, 1);
	if (f!=-1)
		Layout_depth2 (nodes, edges, f, depth+1);
	// TODO: support more than two destination points (switch tables?)
}

static void Layout_depth(Node *nodes, Edge *edges) {
	int i, j, rh, nx;
	int *rowheight = NULL;
	int maxdepth = 0;
	const int h_spacing = 12;
	const int v_spacing = 4;

	Layout_depth2 (nodes, edges, 0, 0);

	// identify max depth
	for (i=0; nodes[i].text; i++) {
		if (nodes[i].depth>maxdepth)
			maxdepth = nodes[i].depth;
	}
	// identify row height
	rowheight = malloc (sizeof (int)*maxdepth);
	for (i=0; i<maxdepth; i++) {
		rh = 0;
		for (j=0; nodes[j].text; j++) {
			if (nodes[j].depth == i)
				if (nodes[j].h>rh)
					rh = nodes[j].h;
		}
		rowheight[i] = rh;
	}

	// vertical align // depe
	for (i=0; nodes[i].text; i++) {
		nodes[i].y = 1;
		for (j=0;j<nodes[i].depth;j++)
			nodes[i].y += rowheight[j] + v_spacing;
	}
	// horitzontal align
	for (i=0; i<maxdepth; i++) {
		nx = (i%2)*10;
		for (j=0; nodes[j].text; j++) {
			if (nodes[j].depth == i) {
				nodes[j].x = nx;
				nx += nodes[j].w + h_spacing;
			}
		}
	}
	free (rowheight);
}

static int bbEdges (RAnalFunction *fcn, Node *nodes, Edge **e) {
	Edge *edges = NULL;
	RListIter *iter;
	RAnalBlock *bb;
	int i = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		// add edge from bb->addr to bb->jump / bb->fail
		if (bb->jump != UT64_MAX) {
			edges = realloc (edges, sizeof (Edge)*(i+2));
			edges[i].nth = 0;
			edges[i].from = Node_find (nodes, bb->addr);
			edges[i].to = Node_find (nodes, bb->jump);
			i++;
			if (bb->fail != UT64_MAX) {
				edges = realloc (edges, sizeof (Edge)*(i+2));
				edges[i].nth = 1;
				edges[i].from = Node_find (nodes, bb->addr);
				edges[i].to = Node_find (nodes, bb->fail);
				i++;
			}
		}
	}
	if (edges)
		edges[i].nth = -1;
	free (*e);
	*e = edges;
	return i;
}

static int cgNodes (RCore *core, RAnalFunction *fcn, Node **n) {
	int i = 0;
#if FCN_OLD
	int j;
	char *code;
	RAnalRef *ref;
	RListIter *iter;
	Node *nodes;

	int fcn_refs_length = r_list_length (fcn->refs);
	nodes = calloc (1, sizeof(Node)*(fcn_refs_length+2));
	if (!nodes)
		return R_FALSE;
	nodes[i].text = strdup ("");
	nodes[i].addr = fcn->addr;
	nodes[i].depth = -1;
	nodes[i].x = 10;
	nodes[i].y = 3;
	nodes[i].w = 0;
	nodes[i].h = 0;
	i++;
	r_list_foreach (fcn->refs, iter, ref) {
		/* avoid dups wtf */
		for (j=0; j<i; j++) {
			if (ref->addr == nodes[j].addr)
				goto sin;
		}
		RFlagItem *fi = r_flag_get_at (core->flags, ref->addr);
		if (fi) {
			nodes[i].text = strdup (fi->name);
			nodes[i].text = r_str_concat (nodes[i].text, ":\n");
		} else {
			nodes[i].text = strdup ("");
		}
		code = r_core_cmd_strf (core,
			"pi 4 @ 0x%08"PFMT64x, ref->addr);
		nodes[i].text = r_str_concat (nodes[i].text, code);
		free (code);
		nodes[i].text = r_str_concat (nodes[i].text, "...\n");
		nodes[i].addr = ref->addr;
		nodes[i].depth = -1;
		nodes[i].x = 10;
		nodes[i].y = 10;
		nodes[i].w = 0;
		nodes[i].h = 0;
		i++;
		sin:
		continue;
	}
	free (*n);
	*n = nodes;
#else
	eprintf ("Must be sdbized\n");
#endif
	return i;
}

static int cgEdges (RAnalFunction *fcn, Node *nodes, Edge **e) {
	int i = 0;
#if FCN_OLD
	Edge *edges = NULL;
	RAnalRef *ref;
	RListIter *iter;
	r_list_foreach (fcn->refs, iter, ref) {
		edges = realloc (edges, sizeof (Edge)*(i+2));
		edges[i].nth = 0;
		edges[i].from = Node_find (nodes, fcn->addr);
		edges[i].to = Node_find (nodes, ref->addr);
		i++;
	}
	if (edges)
		edges[i].nth = -1;
	free (*e);
	*e = edges;
#else
	#warning cgEdges not sdbized for fcn refs
#endif
	return i;
}

static int bbNodes (RCore *core, RAnalFunction *fcn, Node **n) {
	int i;
	RAnalBlock *bb;
	RListIter *iter;
	Node *nodes = malloc (sizeof(Node)*(r_list_length (fcn->bbs)+1));
	if (!nodes)
		return 0;
	i = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		nodes[i].text = r_core_cmd_strf (core,
			"pI %d @ 0x%08"PFMT64x, bb->size, bb->addr);
		nodes[i].addr = bb->addr;
		nodes[i].depth = -1;
		nodes[i].x = 10;
		nodes[i].y = 3;
		nodes[i].w = 0;
		nodes[i].h = 0;
		i++;
	}
	free (*n);
	*n = nodes;
	nodes[i].text = NULL;
	return i;
}

// damn singletons.. there should be only one screen and therefor
// only one visual instance of the graph view. refactoring this
// into a struct makes the code to reference pointers unnecesarily
// we can look for a non-global solution here in the future if
// necessary
static RConsCanvas *can;
static RAnalFunction *fcn;
static Node *nodes = NULL;
static Edge *edges = NULL;
static int n_nodes = 0;
static int n_edges = 0;
static int callgraph = 0;

static void r_core_graph_refresh (RCore *core) {
	char title[128];
	int i, h, w = r_cons_get_size (&h);
	r_cons_clear00 ();
	if (!can) {
		return;
	}
	r_cons_canvas_resize (can, w, h);
	r_cons_canvas_clear (can);

	if (edges)
	for (i=0;edges[i].nth!=-1;i++) {
		if (edges[i].from == -1 || edges[i].to == -1)
			continue;
		Node *a = &nodes[edges[i].from];
		Node *b = &nodes[edges[i].to];
		Edge_print (can, a, b, edges[i].nth);
	}
	for (i=0;i<n_nodes;i++) {
		Node_print (can, &nodes[i], i==curnode);
	}

	G (-can->sx, -can->sy);
	snprintf (title, sizeof (title)-1,
		"[0x%08"PFMT64x"]> VV @ %s (nodes %d edges %d) %s",
		fcn->addr, fcn->name, n_nodes, n_edges, callgraph?"CG":"BB");
	W (title);

	r_cons_canvas_print (can);
	r_cons_flush ();
}

R_API int r_core_visual_graph(RCore *core, RAnalFunction *_fcn) {
	int key, cn, prevnode = curnode;
	int i, w, h;
	n_nodes = n_edges = 0;
	nodes = NULL;
	edges = NULL;
	callgraph = 0;

	fcn = _fcn? _fcn: r_anal_get_fcn_at (core->anal, core->offset, 0);
	if (!fcn) {
		eprintf ("No function in current seek\n");
		return R_FALSE;
	}
	w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w-1, h-1);
	if (!can) {
		eprintf ("Cannot create RCons.canvas context\n");
		return R_FALSE;
	}

	n_nodes = bbNodes (core, fcn, &nodes);
	if (!nodes) {
		free (can);
		return R_FALSE;
	}

	n_edges = bbEdges (fcn, nodes, &edges);
	if (!edges)
		n_edges = 0;

	// hack to make layout happy
	for (i=0; nodes[i].text; i++) {
		Node_print (can, &nodes[i], i==curnode);
	}
	// run layout
	Layout_depth (nodes, edges);
repeat:
	core->cons->event_data = core;
	core->cons->event_resize = \
		(RConsEvent)r_core_graph_refresh;
	r_core_graph_refresh (core);

	// r_core_graph_inputhandle()
	key = r_cons_readchar ();
#define N nodes[curnode]
	prevnode = curnode;
	switch (key) {
	case 'V':
		callgraph = !!!callgraph;
		if (callgraph) {
			int y = 5, x = 20;
			n_nodes = cgNodes (core, fcn, &nodes);
			n_edges = cgEdges (fcn, nodes, &edges);
			// callgraph layout
			for (i=0; nodes[i].text; i++) {
				// wrap to width 'w'
				if (i>0) {
					if (nodes[i].x < nodes[i-1].x) {
						y += 10;
						x = 0;
					}
				}
				nodes[i].x = x;
				nodes[i].y = i? y: 2;
				x += 30;
			}
		} else {
			n_nodes = bbNodes (core, fcn, &nodes);
			n_edges = bbEdges (fcn, nodes, &edges);
			curnode = 0;
			// hack to make the layout happy
			for (i=0; nodes[i].text; i++) {
				Node_print (can, &nodes[i], i==curnode);
			}
			Layout_depth (nodes, edges);
		}
		break;
	case 'x':
		if (r_core_visual_xrefs_x (core))
			goto beach;
		break;
	case 'X':
		if (r_core_visual_xrefs_X (core))
			goto beach;
		break;
	case 9: curnode++;
		if (!nodes[curnode].text)
			curnode = 0;
		break;
	case '?':
		r_cons_clear00();
		r_cons_printf ("Visual Ascii Art graph keybindings:\n"
			" hjkl - move node\n"
		" asdw - scroll canvas\n"
		" tab  - select next node\n"
		" TAB  - select previous node\n"
		" t/f  - follow true/false edges\n"
		" V    - toggle basicblock / call graphs\n"
		" R    - relayout\n");
		r_cons_flush();
		r_cons_any_key();
		break;
	case 'R':
	case 'r': Layout_depth (nodes, edges); break;
	case 'j': N.y++; break;
	case 'k': N.y--; break;
	case 'h': N.x--; break;
	case 'l': N.x++; break;
	case 'J': N.y+=5; break;
	case 'K': N.y-=5; break;
	case 'H': N.x-=5; break;
	case 'L': N.x+=5; break;
	// scroll
	case '0': can->sx = can->sy = 0; break;
	case 'w': can->sy -= 1; break;
	case 's': can->sy += 1; break;
	case 'a': can->sx -= 1; break;
	case 'd': can->sx += 1; break;
	case 'W': can->sy -= 5; break;
	case 'S': can->sy += 5; break;
	case 'A': can->sx -= 5; break;
	case 'D': can->sx += 5; break;
		break;
	case 'u':
		curnode = prevnode;
		break;
	case 't':
		cn = Edge_node (edges, curnode, 0);
		if (cn != -1)
			curnode = cn;
		// select jump node
		break;
	case ':':
		r_core_visual_prompt_input (core);
		break;
	case 'f':
		cn = Edge_node (edges, curnode, 1);
		if (cn != -1)
			curnode = cn;
		// select false node
		break;
	case 'q':
		goto beach;
	case 27: // ESC
		if (r_cons_readchar () == 91) {
			if (r_cons_readchar () == 90) {
				if (curnode<1) {
					int i;
					for (i=0; nodes[i].text; i++) {};
					curnode = i-1;
				} else curnode--;
			}
		}
		break;
	default:
		eprintf ("Key %d\n", key);
		//sleep (1);
		break;
	}
	goto repeat;
beach:
	free (nodes);
	free (edges);
	free (can);
	return R_TRUE;
}
