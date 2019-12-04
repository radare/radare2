/* radare2 - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_util/r_intervaltree.h>

#define unwrap(rbnode) container_of (rbnode, RIntervalNode, node)

static void node_max(RBNode *node) {
	RIntervalNode *intervalnode = unwrap (node);
	intervalnode->max_end = intervalnode->end;
	int i;
	for (i = 0; i < 2; i++) {
		if (node->child[i]) {
			ut64 end = unwrap (node->child[i])->max_end;
			if (end > intervalnode->max_end) {
				intervalnode->max_end = end;
			}
		}
	}
}

static int cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 incoming_start = *(ut64 *)incoming;
	ut64 other_start = container_of (in_tree, const RIntervalNode, node)->start;
	if(incoming_start < other_start) {
		return -1;
	}
	if(incoming_start > other_start) {
		return 1;
	}
	return 0;
}

// like cmp, but handles searches for an exact RIntervalNode * in the tree instead of only comparing the start values
static int cmp_exact_node(const void *incoming, const RBNode *in_tree, void *user) {
	RIntervalNode *incoming_node = (RIntervalNode *)incoming;
	RIntervalNode *node = container_of (in_tree, const RIntervalNode, node);
	if (node == incoming_node) {
		return 0;
	}
	if(incoming_node->start < node->start) {
		return -1;
	}
	if(incoming_node->start > node->start) {
		return 1;
	}
	// Here we have the same start value, but a different pointer.
	// This means we need to guide the caller into the direction where the actual node is.
	// Since we have nothing to compare anymore, we have to iterate through all the same-start children to find the path.
	RBNode *next_child = NULL;
	RBIter *path_cache = user;
	if (!path_cache->len) {
		RBNode *cur;
		// go down to the leftmost child that has the same start
		for (cur = &node->node; cur && unwrap (cur->child[0])->start == incoming_node->start; cur = cur->child[0]) {
			path_cache->path[path_cache->len++] = cur;
		}
		// iterate through all children with the same start and stop when the pointer is identical
		while (r_rbtree_iter_has (path_cache)) {
			RIntervalNode *intervalnode = r_rbtree_iter_get (path_cache, RIntervalNode, node);
			if (intervalnode == incoming_node) {
				next_child = path_cache->path[0];
				break;
			}
			r_rbtree_iter_next (path_cache);
		}
	} else {
		// Path has already been found by a previous call of this function
		// Go through the path to find the next node one step down
		size_t i;
		for (i = 0; i < path_cache->len - 1; i++) {
			if (unwrap (path_cache->path[i]) == node) {
				next_child = path_cache->path[i + 1];
			}
		}
	}
	// Determine the direction from the next child node
	return node->node.child[0] == next_child ? -1 : 1;
}

R_API void r_interval_tree_init(RIntervalTree *tree, RIntervalNodeFree free) {
	tree->root = NULL;
	tree->free = free;
}

static void interval_node_free(RBNode *node, void *user) {
	RIntervalNode *ragenode /* >:-O */ = unwrap (node);
	if (user) {
		((RContRBFree)user) (ragenode->data);
	}
	free (ragenode);
}

R_API void r_interval_tree_fini(RIntervalTree *tree) {
	if (!tree || !tree->root) {
		return;
	}
	r_rbtree_free (&tree->root->node, interval_node_free, tree->free);
}

R_API bool r_interval_tree_insert(RIntervalTree *tree, ut64 start, ut64 end, void *data) {
	RIntervalNode *node = R_NEW0 (RIntervalNode);
	if (!node) {
		return false;
	}
	node->start = start;
	node->end = end;
	node->data = data;
	RBNode *root = tree->root ? &tree->root->node : NULL;
	bool r = r_rbtree_aug_insert (&root, &start, &node->node, cmp, NULL, node_max);
	tree->root = unwrap (root);
	if (!r) {
		free (node);
	}
	return r;
}

R_API bool r_interval_tree_delete(RIntervalTree *tree, RIntervalNode *node, bool free) {
	RBNode *root = &tree->root->node;
	RBIter path_cache = { 0 };
	bool r = r_rbtree_aug_delete (&root, node, cmp_exact_node, &path_cache, interval_node_free, free ? tree->free : NULL, node_max);
	tree->root = unwrap (root);
	return r;
}

R_API bool r_interval_tree_resize(RIntervalTree *tree, RIntervalNode *node, ut64 new_start, ut64 new_end) {
	if (node->start != new_start) {
		// Start change means the tree needs a different structure
		void *data = node->data;
		if (!r_interval_tree_delete (tree, node, false)) {
			return false;
		}
		return r_interval_tree_insert (tree, new_start, new_end, data);
	}
	if (node->end != new_end) {
		// Only end change just needs the updated augmented max value to be propagated upwards
		node->end = new_end;
		RBIter path_cache = { 0 };
		return r_rbtree_aug_update_sum (&tree->root->node, node, &node->node, cmp_exact_node, &path_cache, node_max);
	}
	// no change
	return true;
}

// This must always return the topmost node that matches start!
// Otherwise r_interval_node_all_at will break.
R_API RIntervalNode *r_interval_tree_node_at(RIntervalTree *tree, ut64 start) {
	RIntervalNode *node = tree->root;
	while (node) {
		if (start < node->start) {
			node = unwrap (node->node.child[0]);
		} else if (start > node->start) {
			node = unwrap (node->node.child[1]);
		} else {
			return node;
		}
	}
	return NULL;
}

R_API void r_interval_tree_all_at(RIntervalTree *tree, ut64 start, RIntervalIterCb cb, void *user) {
	// Find the topmost node matching start so we have a sub-tree with all entries that we want to find.
	RIntervalNode *top_intervalnode = r_interval_tree_node_at (tree, start);
	if (!top_intervalnode) {
		return;
	}

	// If there are more nodes with the same key, they can be in both children.
	// Start with the leftmost child that matches start and iterate from there
	RBIter it;
	it.len = 0;
	RBNode *node;
	for (node = &top_intervalnode->node; node && unwrap (node->child[0])->start == start; node = node->child[0]) {
		it.path[it.len++] = node;
	}
	while (r_rbtree_iter_has (&it)) {
		RIntervalNode *intervalnode = r_rbtree_iter_get (&it, RIntervalNode, node);
		if (intervalnode->start != start) {
			break;
		}
		cb (intervalnode, user);
		r_rbtree_iter_next (&it);
	}
}

R_API void r_interval_node_all_in(RIntervalNode *node, ut64 value, bool end_inclusive, RIntervalIterCb cb, void *user) {
	while (node && value < node->start) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->node.child[0]);
	}
	if (!node) {
		return;
	}
	if (end_inclusive ? value > node->max_end : value >= node->max_end) {
		return;
	}
	if (end_inclusive ? value <= node->end : value < node->end) {
		cb (node, user);
	}
	// This can be done more efficiently by building the stack manually
	r_interval_node_all_in (unwrap (node->node.child[0]), value, end_inclusive, cb, user);
	r_interval_node_all_in (unwrap (node->node.child[1]), value, end_inclusive, cb, user);
}

R_API void r_interval_tree_all_in(RIntervalTree *tree, ut64 value, bool end_inclusive, RIntervalIterCb cb, void *user) {
	// all in! 🂡
	r_interval_node_all_in (tree->root, value, end_inclusive, cb, user);
}

static void r_interval_node_all_intersect(RIntervalNode *node, ut64 start, ut64 end, bool end_inclusive, RIntervalIterCb cb, void *user) {
	while (node && (end_inclusive ? end < node->start : end <= node->start)) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->node.child[0]);
	}
	if (!node) {
		return;
	}
	if (end_inclusive ? start > node->max_end : start >= node->max_end) {
		return;
	}
	if (end_inclusive ? start <= node->end : start < node->end) {
		cb (node, user);
	}
	// This can be done more efficiently by building the stack manually
	r_interval_node_all_intersect (unwrap (node->node.child[0]), start, end, end_inclusive, cb, user);
	r_interval_node_all_intersect (unwrap (node->node.child[1]), start, end, end_inclusive, cb, user);
}

R_API void r_interval_tree_all_intersect(RIntervalTree *tree, ut64 start, ut64 end, bool end_inclusive, RIntervalIterCb cb, void *user) {
	r_interval_node_all_intersect (tree->root, start, end, end_inclusive, cb, user);
}
