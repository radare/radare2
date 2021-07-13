/* radare2 - LGPL - Copyright 2021 - condret */

#include <r_io.h>
#include <r_util.h>

#define	OLD_SM	0

R_API RIOBank *r_io_bank_new(void) {
	RIOBank *bank = R_NEW0 (RIOBank);
	if (!bank) {
		return NULL;
	}
	bank->submaps = r_rbtree_cont_newf (free);
	if (!bank->submaps) {
		free (bank);
		return NULL;
	}
	bank->maprefs = r_list_newf (free);
	if (!bank->maprefs) {
		r_rbtree_cont_free (bank->submaps);
		free (bank);
		return NULL;
	}
	bank->todo = r_queue_new (8);
	if (!bank->todo) {
		r_list_free (bank->maprefs);
		r_rbtree_cont_free (bank->submaps);
		free (bank);
		return NULL;
	}
	return bank;
}

R_API void r_io_bank_free(RIOBank *bank) {
	if (!bank) {
		return;
	}
	r_queue_free (bank->todo);
	r_list_free (bank->maprefs);
	r_rbtree_cont_free (bank->submaps);
	free (bank);
}

static bool _bank_free_cb(void *user, void *data, ut32 id) {
	r_io_bank_free ((RIOBank *)data);
	return true;
}

R_API void r_io_bank_init(RIO *io) {
	r_return_if_fail (io);
	r_io_bank_fini (io);
	io->banks = r_id_storage_new (0, UT32_MAX);
}

R_API void r_io_bank_fini(RIO *io) {
	r_return_if_fail (io);
	if (io->banks) {
		r_id_storage_foreach (io->banks, _bank_free_cb, NULL);
		r_id_storage_free (io->banks);
		io->banks = NULL;
	}
}

R_API RIOBank *r_io_bank_get(RIO *io, const ut32 bankid) {
	r_return_val_if_fail (io && io->banks, NULL);
	return (RIOBank *)r_id_storage_get (io->banks, bankid);
}

static RIOMapRef *_mapref_from_map(RIOMap *map) {
	RIOMapRef *mapref = R_NEW (RIOMapRef);
	if (!mapref) {
		return NULL;
	}
	mapref->id = map->id;
	mapref->ts = map->ts;
	return mapref;
}

static int _find_sm_by_vaddr_cb(void *incoming, void *in, void *user) {
	RIOSubMap *bd = (RIOSubMap *)incoming, *sm = (RIOSubMap *)in;
	if (bd->itv.addr > sm->itv.addr) {
		return -1;
	}
	if (bd->itv.addr < sm->itv.addr) {
		return 1;
	}
	return 0;
}

static int _find_lowest_intersection_sm_cb(void *incoming, void *in, void *user) {
	RIOSubMap *bd = (RIOSubMap *)incoming, *sm = (RIOSubMap *)in;
	if (r_io_submap_overlap (bd, sm)) {
		return 0;
	}
	if (bd->itv.addr > sm->itv.addr) {
		return -1;
	}
	return 1;
}

// returns the node containing the submap with lowest itv.addr, that intersects with sm
static RContRBNode *_find_entry_submap_node(RIOBank *bank, RIOSubMap *sm) {
	RContRBNode *node = r_rbtree_cont_find_node (bank->submaps, sm, _find_lowest_intersection_sm_cb, NULL);
	if (!node) {
		return NULL;
	}
	RContRBNode *prev = r_rbtree_cont_node_prev (node);
	while (prev && r_io_submap_overlap (((RIOSubMap *)prev->data), sm)) {
		node = prev;
		prev = r_rbtree_cont_node_prev (node);
	}
	return node;
}

R_API bool r_io_bank_map_add_top(RIO *io, const ut32 bankid, const ut32 mapid) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	RIOMap *map = r_io_map_get (io, mapid);
	r_return_val_if_fail (io && bank && map, false);
	RIOMapRef *mapref = _mapref_from_map (map);
	if (!mapref) {
		return false;
	}
	RIOSubMap *sm = r_io_submap_new (io, mapref);
	if (!sm) {
		free (mapref);
		return false;
	}
	RContRBNode *entry = _find_entry_submap_node (bank, sm);
	if (!entry) {
		// no intersection with any submap, so just insert
		if (!r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL)) {
			free (sm);
			free (mapref);
			return false;
		}
		r_list_append (bank->maprefs, mapref);
		return true;
	}
	RIOSubMap *bd = (RIOSubMap *)entry->data;
	if (r_itv_eq (bd->itv, sm->itv)) {
		// this makes gb bankswitches way faster than skyline
		// instead of deleting and inserting, just replace the mapref
		bd->mapref = sm->mapref;
		free (sm);
		r_list_append (bank->maprefs, mapref);
		return true;
	}
	if (r_io_submap_from (bd) < r_io_submap_from (sm) &&
		r_io_submap_to (sm) < r_io_submap_to (bd)) {
		// split bd into 2 maps => bd and bdsm
		RIOSubMap *bdsm = R_NEWCOPY (RIOSubMap, bd);
		if (!bdsm) {
			free (sm);
			free (mapref);
			return false;
		}
#if OLD_SM
		bdsm->itv.addr = r_io_submap_to (sm) + 1;
		bdsm->itv.size = r_io_submap_to (bd) - r_io_submap_from (bdsm) + 1;
		bd->itv.size = r_io_submap_from (sm) - r_io_submap_from (bd);
#else
		r_io_submap_set_from (bdsm, r_io_submap_to (sm) + 1);
		r_io_submap_set_to (bd, r_io_submap_from (sm) - 1);
#endif
		// TODO: insert and check return value, before adjusting sm size
		if (!r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL)) {
			free (sm);
			free (bdsm);
			free (mapref);
			return false;
		}
		if (!r_rbtree_cont_insert (bank->submaps, bdsm, _find_sm_by_vaddr_cb, NULL)) {
			r_rbtree_cont_delete (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL);
			free (sm);
			free (bdsm);
			free (mapref);
			return false;
		}
		r_list_append (bank->maprefs, mapref);
		return true;
	}

#if OLD_SM
	bd->itv.size = r_io_submap_from (sm) - r_io_submap_from (bd);
#else
	r_io_submap_set_to (bd, r_io_submap_from (sm) -1);
#endif
	entry = r_rbtree_cont_node_next (entry);
	while (entry && r_io_submap_to (((RIOSubMap *)entry->data)) <= r_io_submap_to (sm)) {
		//delete all submaps that are completly included in sm
		RContRBNode *next = r_rbtree_cont_node_next (entry);
		// this can be optimized, there is no need to do search here
		r_rbtree_cont_delete (bank->submaps, entry->data, _find_sm_by_vaddr_cb, NULL);
		entry = next;
	}
	if (entry && r_io_submap_from (((RIOSubMap *)entry->data)) <= r_io_submap_to (sm)) {
		bd = (RIOSubMap *)entry->data;
#if OLD_SM
		bd->itv.size = r_io_submap_to (bd) - r_io_submap_to (sm);
		bd->itv.addr = r_io_submap_to (sm) + 1;
#else
		r_io_submap_set_from (bd, r_io_submap_to (sm) + 1);
#endif
	}
	if (!r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL)) {
		free (sm);
		free (mapref);
		return false;
	}
	r_list_append (bank->maprefs, mapref);
	return true;
}

R_API bool r_io_bank_map_priorize(RIO *io, const ut32 bankid, const ut32 mapid) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	r_return_val_if_fail (io && bank, false);
	RListIter *iter;
	RIOMapRef *mapref;
	r_list_foreach (bank->maprefs, iter, mapref) {
		if (mapref->id == mapid) {
			goto found;
		}
	}
	return false;
found:
	if (iter == bank->maprefs->tail) {	//tail is top
		return r_io_map_get_by_ref (io, mapref) ? true : false;
	}
	RIOSubMap *sm = r_io_submap_new (io, mapref);
	if (!sm) {
		return false;
	}
	RContRBNode *entry = _find_entry_submap_node (bank, sm);
	if (!entry) {
		// if this happens, something is really fucked up
		free (sm);
		return false;
	}
	RIOSubMap *bd = (RIOSubMap *)entry->data;
	if (r_itv_eq (bd->itv, sm->itv)) {
		// no need to insert new sm, if boundaries match perfectly
		// instead override mapref of existing node/submap
		bd->mapref = *mapref;
		free (sm);
		r_list_iter_to_top (bank->maprefs, iter);
		return true;
	}
	if (r_io_submap_from (bd) < r_io_submap_from (sm) &&
		r_io_submap_to (sm) < r_io_submap_to (bd)) {
		// bd completly overlaps sm on both ends,
		// therefor split bd into 2 maps => bd and bdsm
		// |---bd---||--sm--|-bdsm-|
		RIOSubMap *bdsm = R_NEWCOPY (RIOSubMap, bd);
		if (!bdsm) {
			free (sm);
			return false;
		}
#if OLD_SM
		bdsm->itv.addr = r_io_submap_to (sm) + 1;
		bdsm->itv.size = r_io_submap_to (bd) - r_io_submap_from (bdsm) + 1;
		bd->itv.size = r_io_submap_from (sm) - r_io_submap_from (bd);
#else
		r_io_submap_set_from (bdsm, r_io_submap_to (sm) + 1);
		r_io_submap_set_to (bd, r_io_submap_from (sm) - 1);
#endif
		// TODO: insert and check return value, before adjusting sm size
		r_list_iter_to_top (bank->maprefs, iter);
		return r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL) &
			r_rbtree_cont_insert (bank->submaps, bdsm, _find_sm_by_vaddr_cb, NULL);
	}

	// bd overlaps by it's upper boundary with sm, due to how _find_entry_submap_node works
	// therefor no check is needed here, and the upper boundary can be adjusted safely
#if OLD_SM
	bd->itv.size = r_io_submap_from (sm) - r_io_submap_from (bd);
#else
	r_io_submap_set_to (bd, r_io_submap_from (sm) - 1);
#endif
	entry = r_rbtree_cont_node_next (entry);
	while (entry && r_io_submap_to (((RIOSubMap *)entry->data)) <= r_io_submap_to (sm)) {
		//delete all submaps that are completly included in sm
		RContRBNode *next = r_rbtree_cont_node_next (entry);
		// this can be optimized, there is no need to do search here
		r_rbtree_cont_delete (bank->submaps, entry->data, _find_sm_by_vaddr_cb, NULL);
		entry = next;
	}
	if (entry && r_io_submap_from (((RIOSubMap *)entry->data)) <= r_io_submap_to (sm)) {
		bd = (RIOSubMap *)entry->data;
#if OLD_SM
		bd->itv.size = r_io_submap_to (bd) - r_io_submap_to (sm);
		bd->itv.addr = r_io_submap_to (sm) + 1;
#else
		r_io_submap_set_from (bd, r_io_submap_to (sm) + 1);
#endif
	}
	r_list_iter_to_top (bank->maprefs, iter);
	return r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL);
}

R_API bool r_io_bank_locate(RIO *io, const ut32 bankid, const ut64 size, ut64 *addr) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	r_return_val_if_fail (io && bank && bank->submaps && addr && size, false);
	RContRBNode *entry = r_rbtree_cont_first (bank->submaps);
	if (!entry) {
		// no submaps in this bank
		*addr = 0LL;
		return true;
	}
	ut64 next_location = 0LL;
	while (entry) {
		RIOSubMap *sm = (RIOSubMap *)entry->data;
		if (size <= r_io_submap_from (sm) - next_location) {
			*addr = next_location;
			return true;
		}
		next_location = r_io_submap_to (sm) + 1;
		entry = r_rbtree_cont_node_next (entry);
	}
	if (next_location == 0LL) {
		// overflow from last submap in the tree => no location
		return false;
	}
	if (UT64_MAX - size + 1 < next_location) {
		return false;
	}
	*addr = next_location;
	return true;
}

R_API bool r_io_bank_read_at(RIO *io, const ut32 bankid, ut64 addr, ut8 *buf, int len) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	r_return_val_if_fail (io && bank, false);
	RIOSubMap fake_sm;
	memset (&fake_sm, 0x00, sizeof(RIOSubMap));
	fake_sm.itv.addr = addr;
	fake_sm.itv.size = len;
	// TODO: handle overflow
	RContRBNode *node = _find_entry_submap_node (bank, &fake_sm);
	memset (buf, io->Oxff, len);
	RIOSubMap *sm = node ? (RIOSubMap *)node->data : NULL;
	while (sm && r_io_submap_overlap ((&fake_sm), sm)) {
		RIOMap *map = r_io_map_get_by_ref (io, &sm->mapref);
		if (!map) {
			// mapref doesn't belong to map
			return false;
		}
		if (!(map->perm & R_PERM_R)) {
			continue;
		}
		const ut64 buf_off = addr - R_MAX (addr, r_io_submap_from (sm));
		const int read_len = R_MIN (r_io_submap_to ((&fake_sm)),
					     r_io_submap_to (sm)) - buf_off + 1;
		const ut64 paddr = addr + buf_off - r_io_map_from (map) + map->delta;
		r_io_fd_read_at (io, map->fd, paddr, &buf[buf_off], read_len);
		// check return value here?
		node = r_rbtree_cont_node_next (node);
		sm = node ? (RIOSubMap *)node->data : NULL;
	}
	return true;
}

R_API bool r_io_bank_write_at(RIO *io, const ut32 bankid, ut64 addr, ut8 *buf, int len) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	r_return_val_if_fail (io && bank, false);
	RIOSubMap fake_sm;
	memset (&fake_sm, 0x00, sizeof(RIOSubMap));
	fake_sm.itv.addr = addr;
	fake_sm.itv.size = len;
	// TODO: handle overflow
	RContRBNode *node = _find_entry_submap_node (bank, &fake_sm);
	RIOSubMap *sm = node ? (RIOSubMap *)node->data : NULL;
	while (sm && r_io_submap_overlap ((&fake_sm), sm)) {
		RIOMap *map = r_io_map_get_by_ref (io, &sm->mapref);
		if (!map) {
			// mapref doesn't belong to map
			return false;
		}
		if (!(map->perm & R_PERM_W)) {
			continue;
		}
		const ut64 buf_off = addr - R_MAX (addr, r_io_submap_from (sm));
		const int read_len = R_MIN (r_io_submap_to ((&fake_sm)),
					     r_io_submap_to (sm)) - buf_off + 1;
		const ut64 paddr = addr + buf_off - r_io_map_from (map) + map->delta;
		r_io_fd_write_at (io, map->fd, paddr, &buf[buf_off], read_len);
		// check return value here?
		node = r_rbtree_cont_node_next (node);
		sm = node ? (RIOSubMap *)node->data : NULL;
	}
	return true;
}

R_API void r_io_bank_delete_map (RIO *io, const ut32 bankid, const ut32 mapid) {
//no need to check for mapref here, since this is "just" deleting
	RIOBank *bank = r_io_bank_get (io, bankid);
	RIOMap *map = r_io_map_get (io, mapid);
	r_return_if_fail (bank && map);
	RListIter *iter;
	RIOMapRef *mapref = NULL;
	// first try to find the corresponding mapref in the bank
	r_list_foreach_prev (bank->maprefs, iter, mapref) {
		if (mapref->id == map->id) {
			goto found;
		}
	}
	// map is not referenced by this bank; nothing to do
	return;
found:
	// TODO: make sm stack located
	// not now -.- i am tired
	;RIOSubMap *sm = r_io_submap_new (io, mapref);
	RContRBNode *entry = _find_entry_submap_node (bank, sm);
	RIOSubMap *bd = (RIOSubMap *)entry->data;
	while (bd && r_io_submap_overlap (bd, sm)) {
		// this loop deletes all affected submaps from the rbtree
		// and also enqueues them in bank->todo
		RContRBNode *next = r_rbtree_cont_node_next (entry);
		if (bd->mapref.id == mapid) {
			// TODO: create a different struct, that fits better to this than RIOSubMap
			r_queue_enqueue (bank->todo, R_NEWCOPY (RIOSubMap, bd));
			r_rbtree_cont_delete (bank->submaps, bd, _find_sm_by_vaddr_cb, NULL);
		}
		entry = next;
		bd = entry ? (RIOSubMap *)entry->data : NULL;
	}
	free (sm);
	while (!r_queue_is_empty (bank->todo)) {
		// now check for each deleted submap if a lower map intersects with it
		// and create new submaps accordingly, and fill the gaps
		sm = r_queue_dequeue (bank->todo);
		RListIter *ator = r_list_iter_get_prev (iter);
		while (ator) {
			map = r_io_map_get_by_ref (io, (RIOMapRef *)ator->data);
			ator = r_list_iter_get_prev (ator);
			if (!map) {
				// if this happens, something is fucked up, and no submap should be inserted
				continue;
			}
			// if the map and sm intersect, the intersecting submap needs to be inserted in the tree
			// there are 5 cases to consider here
			// 1. no intersection: just continue to the next iteration
			// 2. map overlaps sm on both ends: insert submap for map with boundaries of sm
			// 3. map overlaps sm on the upper end: insert submap for map accordingly and adjust sm boundaries
			// 4. map overlaps sm on the lower end: insert submap for map accordingly and adjust sm boundaries
			// 5. sm overlaps sm on both ends: split sm into 2 submaps and enqueue new one in banks->todo; insert submap for map; adjust sm boundaries
			if (r_io_submap_to (sm) < r_io_map_from (map) || r_io_submap_from (sm) > r_io_map_to (map)) {
				// case 1
				continue;
			}
			mapref = _mapref_from_map (map);
			bd = r_io_submap_new (io, mapref);
			free (mapref);
			if (r_io_submap_from (sm) >= r_io_map_from (map)) {
				// case 4 and 2
				r_io_submap_set_from (bd, r_io_submap_from (sm));
				r_rbtree_cont_insert (bank->submaps, bd, _find_sm_by_vaddr_cb, NULL);
				if (r_io_submap_to (sm) <= r_io_map_to (map)) {
					// case 2
					r_io_submap_set_to (bd, r_io_submap_to (sm));
					break;
				}
				// case 4
				r_io_submap_set_from (sm, r_io_submap_to (bd) + 1);
				continue;
			}
			if (r_io_submap_to (sm) <= r_io_map_to (map)) {
				// case 3
				r_io_submap_set_to (bd, r_io_submap_to (sm));
				r_io_submap_set_to (sm, r_io_submap_from (bd) - 1);
				r_rbtree_cont_insert (bank->submaps, bd, _find_sm_by_vaddr_cb, NULL);
				continue;
			}
			// case 5 because all other cases are already handled
			RIOSubMap *bdsm = R_NEWCOPY (RIOSubMap, sm);
			r_io_submap_set_to (sm, r_io_submap_from (bd) - 1);
			r_io_submap_set_from (bdsm, r_io_submap_to (bd) + 1);
			r_rbtree_cont_insert (bank->submaps, bd, _find_sm_by_vaddr_cb, NULL);
			r_queue_enqueue (bank->todo, bdsm);
		}
		free (sm);
	}
	// finally remove the mapref/iter from the map
	r_list_delete (bank->maprefs, iter);
}

// merges nearby submaps, that have a map ref to the same map, and free unneeded tree nodes
R_API void r_io_bank_drain (RIO *io, const ut32 bankid) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	r_return_if_fail (bank);
	RContRBNode *node = r_rbtree_cont_node_first (bank->submaps);
	RContRBNode *next = NULL;
	while (node) {
		next = r_rbtree_cont_node_next (node);
		if (next) {
			RIOSubMap *bd, *sm;
			bd = (RIOSubMap *)node->data;
			sm = (RIOSubMap *)next->data;
			if (!memcmp (&bd->mapref, &sm->mapref, sizeof(RIOMapRef))) {
				r_io_submap_set_to (bd, r_io_submap_to (sm));
				r_rbtree_cont_delete (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL);
				continue;
			}
		}
		node = next;
	}
}
