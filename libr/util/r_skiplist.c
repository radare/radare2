// (c) 2016 Jeffrey Crowell, Riccardo Schirone(ret2libc)
// BSD 3 Clause License
// radare2

// Skiplists are a probabilistic datastructure than can be used as a k-v store
// with average case O(lg n) lookup time, and worst case O(n).

// https://en.wikipedia.org/wiki/Skip_list

#include <r_skiplist.h>

const int kSkipListDepth = 15; // max depth

RSkipListNode *r_skiplist_node_new (void *data) {
	RSkipListNode *res = R_NEW (RSkipListNode);
	if (!res) return NULL;
	res->forward = R_NEWS (RSkipListNode *, kSkipListDepth + 1);
	if (!res->forward) goto err_forward;
	res->data = data;
	return res;

err_forward:
	free (res);
	return NULL;
}

void r_skiplist_node_free (RSkipList *list, RSkipListNode *node) {
	if (list->freefn && node->data) {
		list->freefn (node->data);
	}
	free (node->forward);
	free (node);
}

void init_head (RSkipList *list) {
	int i;
	for (i = 0; i <= kSkipListDepth; i++) {
		list->head->forward[i] = list->head;
	}
}

// Find the insertion/deletion point for the element `data` in the list.
// The array `updates`, if provided, is filled with the nodes that need to be
// updated for each layer.
//
// NOTE: `updates` should be big enough to contain `list->list_level + 1`
//       elements, when provided.
RSkipListNode *find_insertpoint(RSkipList *list, void *data, RSkipListNode **updates) {
	RSkipListNode *x = list->head;
	int i;

	for (i = list->list_level; i >= 0; i--) {
		while (x->forward[i] != list->head
			&& list->compare (x->forward[i]->data, data) < 0) {
			x = x->forward[i];
		}
		if (updates) {
			updates[i] = x;
		}
	}
	x = x->forward[0];
	return x;
}

// Takes in a pointer to the function to free a list element, and a pointer to
// a function that retruns 0 on equality between two elements, and -1 or 1
// when unequal (for sorting).
// Returns a new heap-allocated skiplist.
R_API RSkipList* r_skiplist_new(RListFree freefn, RListComparator comparefn) {
	RSkipList *list = R_NEW0 (RSkipList);
	if (!list) return NULL;

	list->head = r_skiplist_node_new (NULL);
	if (!list->head) goto err_head;

	init_head (list);
	list->list_level = 0;
	list->size = 0;
	list->freefn = freefn;
	list->compare = comparefn;
	return list;

err_head:
	free (list);
	return NULL;
}

// Remove all elements from the list
R_API void r_skiplist_purge(RSkipList *list) {
	RSkipListNode *n;
	if (!list) return;

	n = list->head->forward[0];
	while (n != list->head) {
		RSkipListNode *x = n;
		n = n->forward[0];

		r_skiplist_node_free (list, x);
	}
	init_head (list);
	list->size = 0;
	list->list_level = 0;
}

// Free the entire list and it's element (if freefn is specified)
R_API void r_skiplist_free(RSkipList *list) {
	if (!list) return;
	r_skiplist_purge (list);
	r_skiplist_node_free (list, list->head);
	free (list);
}

// Inserts an element to the skiplist, and returns a pointer to the element's
// node.
R_API RSkipListNode* r_skiplist_insert(RSkipList* list, void* data) {
	RSkipListNode *update[kSkipListDepth+1];
	RSkipListNode *x;
	int i, x_level, new_level;

	// locate insertion points in the lists of all levels
	x = find_insertpoint (list, data, update);
	// check whether the element is already in the list
	if (x != list->head && list->compare(x->data, data) == 0) {
		return x;
	}

	// randomly choose the number of levels the new node will be put in
	for (x_level = 0; rand() < RAND_MAX/2 && x_level <= kSkipListDepth; x_level++);

	// update the `update` array with default values when the current node
	// has a level greater than the current one
	new_level = list->list_level;
	if (x_level > list->list_level) {
		for (i = list->list_level + 1; i <= x_level; i++) {
			update[i] = list->head;
		}
		new_level = x_level;
	}

	x = r_skiplist_node_new (data);
	if (!x) return NULL;

	// update forward links for all `update` points,
	// by inserting the new element in the list in each level
	for (i = 0; i <= x_level; i++) {
		x->forward[i] = update[i]->forward[i];
		update[i]->forward[i] = x;
	}

	list->list_level = new_level;
	list->size++;
	return x;
}

// Delete node with data as it's payload.
R_API void r_skiplist_delete(RSkipList* list, void* data) {
	int i;
	RSkipListNode *update[kSkipListDepth + 1], *x;

	// locate delete points in the lists of all levels
	x = find_insertpoint (list, data, update);
	// do nothing if the element is not present in the list
	if (x == list->head || list->compare(x->data, data) != 0) {
		return;
	}

	// update forward links for all `update` points,
	// by removing the element from the list in each level
	for (i = 0; i <= list->list_level; i++) {
		if (update[i]->forward[i] != x) break;
		update[i]->forward[i] = x->forward[i];
	}
	r_skiplist_node_free (list, x);

	// update the level of the list
	while ((list->list_level > 0) &&
		(list->head->forward[list->list_level] == list->head)) {
		list->list_level--;
	}
	list->size--;
}

R_API RSkipListNode* r_skiplist_find(RSkipList* list, void* data) {
	int i;
	RSkipListNode* x = find_insertpoint (list, data, NULL);
	if (x != list->head && list->compare (x->data, data) == 0) {
		return x;
	}
	return NULL;
}
