#ifndef R2_RBTREE_H
#define R2_RBTREE_H

#include <limits.h>
#include <stdbool.h>

#include "r_list.h"

// max height <= 2 * floor(log2(n + 1))
// We use `int` for size, so <= 2 * 31
#define R_RBTREE_MAX_HEIGHT 62

typedef struct r_rbnode_t {
	void *data;
	struct r_rbnode_t *child[2];
	bool red;
} RBNode;

typedef struct r_rbtree_t {
	RBNode *root;
	RListComparator cmp;
	RListFree free;
	int size;
} RBTree;


typedef struct r_rbtree_iter_t {
	int len;
	RBNode *path[R_RBTREE_MAX_HEIGHT];
} RBTreeIter;

R_API void r_rbtree_clear(RBTree *tree);
R_API bool r_rbtree_delete(RBTree *tree, void *data);
R_API void *r_rbtree_find(RBTree *tree, void *data);
R_API void r_rbtree_free(RBTree *tree);
R_API int r_rbtree_insert(RBTree *tree, void *data);
R_API void *r_rbtree_lower_bound(RBTree *tree, void *data);
R_API RBTree *r_rbtree_new(RListFree free, RListComparator cmp);
R_API void r_rbtree_print(RBTree *tree);
R_API int r_rbtree_size(RBTree *tree);
R_API void *r_rbtree_upper_bound(RBTree *tree, void *data);

// Unidirectional iterator used with r_rbtree_next
R_API RBTreeIter r_rbtree_first(RBTree *tree);
// Unidirectional iterator used with r_rbtree_prev
R_API RBTreeIter r_rbtree_last(RBTree *tree);
R_API void *r_rbtree_iter_next(RBTreeIter *it);
R_API void *r_rbtree_iter_prev(RBTreeIter *it);
// Iterate [lower_bound, end) forward, used with r_rbtree_iter_next
R_API RBTreeIter r_rbtree_lower_bound_backward(RBTree *tree, void *data);
// Iterate [begin, lower_bound) backward, used with r_rbtree_iter_prev
R_API RBTreeIter r_rbtree_lower_bound_forward(RBTree *tree, void *data);
// Iterate [upper_bound, end) forward, used with r_rbtree_iter_next
R_API RBTreeIter r_rbtree_upper_bound_backward(RBTree *tree, void *data);
// Iterate [begin, upper_bound) backward, used with r_rbtree_iter_prev
R_API RBTreeIter r_rbtree_upper_bound_forward(RBTree *tree, void *data);

// has_next or has_prev
#define r_rbtree_has(it) (it.len)

#define r_rbtree_foreach(tree, it, data) \
	for (it = r_rbtree_first (tree); it.len && (data = r_rbtree_iter_next (&it), 1); )

#define r_rbtree_foreach_prev(tree, it, data) \
	for (it = r_rbtree_last (tree); it.len && (data = r_rbtree_iter_prev (&it), 1); )

#define r_rbtree_iter_while(it, data) \
	while (it.len && (data = r_rbtree_iter_next (&it), 1))

#define r_rbtree_iter_while_prev(it, data) \
	while (it.len && (data = r_rbtree_iter_prev (&it), 1))

#endif
