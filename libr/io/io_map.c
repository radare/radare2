/* radare2 - LGPL - Copyright 2017-2021 - condret, MaskRay */

#include <r_io.h>
#include <stdlib.h>
#include <sdb.h>
#include "r_binheap.h"
#include "r_util.h"
#include "r_vector.h"

#define END_OF_MAP_IDS UT32_MAX

// Store map parts that are not covered by others into io->map_skyline
static void io_map_calculate_skyline(RIO *io) {
	r_skyline_clear (&io->map_skyline);
	// Last map has highest priority (it shadows previous maps)
	void **it;
	r_pvector_foreach (&io->maps, it) {
		RIOMap *map = (RIOMap *)*it;
		r_skyline_add (&io->map_skyline, map->itv, map);
	}
}

RIOMap* io_map_new(RIO* io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	if (!size || !io || !io->map_ids) {
		return NULL;
	}
	RIOMap* map = R_NEW0 (RIOMap);
	if (!map || !io->map_ids || !r_id_pool_grab_id (io->map_ids, &map->id)) {
		free (map);
		return NULL;
	}
	map->fd = fd;
	map->delta = delta;
	map->ts = r_time_now ();
	if ((UT64_MAX - size + 1) < addr) {
		/// XXX: this is leaking a map!!!
		io_map_new (io, fd, perm, delta - addr, 0LL, size + addr);
		size = -(st64)addr;
	}
	// RIOMap describes an interval of addresses
	// r_io_map_begin (map) -> r_io_map_to (map)
	map->itv = (RInterval){ addr, size };
	map->perm = perm;
	map->delta = delta;
	// new map lives on the top, being top the list's tail
	r_pvector_push (&io->maps, map);
	r_skyline_add (&io->map_skyline, map->itv, map);
	return map;
}

R_API RIOMap *r_io_map_new(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_new (io, fd, perm, delta, addr, size);
}

R_API bool r_io_map_remap(RIO *io, ut32 id, ut64 addr) {
	RIOMap *map = r_io_map_get (io, id);
	if (map) {
		ut64 size = r_io_map_size (map);
		r_io_map_set_begin (map, addr);
		if (UT64_MAX - size + 1 < addr) {
			r_io_map_set_size (map, -addr);
			r_io_map_new (io, map->fd, map->perm, map->delta - addr, 0, size + addr);
		}
		io_map_calculate_skyline (io);
		return true;
	}
	return false;
}

R_API bool r_io_map_remap_fd(RIO *io, int fd, ut64 addr) {
	RIOMap *map;
	bool retval = false;
	RList *maps = r_io_map_get_by_fd (io, fd);
	if (maps) {
		map = r_list_get_n (maps, 0);
		if (map) {
			retval = r_io_map_remap (io, map->id, addr);
		}
		r_list_free (maps);
	}
	return retval;
}

static void _map_free(void* p) {
	RIOMap* map = (RIOMap*) p;
	if (map) {
		free (map->name);
		free (map);
	}
}

R_API void r_io_map_init(RIO* io) {
	r_return_if_fail (io);
	r_pvector_init (&io->maps, _map_free);
	if (io->map_ids) {
		r_id_pool_free (io->map_ids);
	}
	io->map_ids = r_id_pool_new (1, END_OF_MAP_IDS);
}

// check if a map with exact the same properties exists
R_API bool r_io_map_exists(RIO *io, RIOMap *map) {
	r_return_val_if_fail (io && map, false);
	void **it;
	r_pvector_foreach (&io->maps, it) {
		RIOMap *m = *it;
		if (!memcmp (m, map, sizeof (RIOMap))) {
			return true;
		}
	}
	return false;
}

// check if a map with specified id exists
R_API bool r_io_map_exists_for_id(RIO* io, ut32 id) {
	return r_io_map_get (io, id) != NULL;
}

R_API RIOMap* r_io_map_get(RIO *io, ut32 id) {
	r_return_val_if_fail (io, false);
	void **it;
	r_pvector_foreach (&io->maps, it) {
		RIOMap *map = *it;
		if (map->id == id) {
			return map;
		}
	}
	return NULL;
}

RIOMap* io_map_add(RIO* io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	//check if desc exists
	RIODesc* desc = r_io_desc_get (io, fd);
	if (desc) {
		//a map cannot have higher permissions than the desc belonging to it
		return io_map_new (io, fd, (perm & desc->perm) | (perm & R_PERM_X),
				delta, addr, size);
	}
	return NULL;
}

R_API RIOMap *r_io_map_add(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_add (io, fd, perm, delta, addr, size);
}

R_API RIOMap *r_io_map_add_batch(RIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_add (io, fd, perm, delta, addr, size);
}

R_API void r_io_update(RIO *io) {
	io_map_calculate_skyline (io);
}

R_API RIOMap* r_io_map_get_paddr(RIO* io, ut64 paddr) {
	r_return_val_if_fail (io, NULL);
	void **it;
	r_pvector_foreach_prev (&io->maps, it) {
		RIOMap *map = *it;
		if (map->delta <= paddr && paddr < map->delta + r_io_map_size (map)) {
			return map;
		}
	}
	return NULL;
}

// gets first map where addr fits in
R_API RIOMap *r_io_map_get_at(RIO* io, ut64 addr) {
	r_return_val_if_fail (io, NULL);
	return r_skyline_get (&io->map_skyline, addr);
}

R_API bool r_io_map_is_mapped(RIO* io, ut64 addr) {
	r_return_val_if_fail (io, false);
	return (bool)r_io_map_get_at (io, addr);
}

R_API void r_io_map_reset(RIO* io) {
	r_io_map_fini (io);
	r_io_map_init (io);
	io_map_calculate_skyline (io);
}

R_API bool r_io_map_del(RIO *io, ut32 id) {
	r_return_val_if_fail (io, false);
	size_t i;
	for (i = 0; i < r_pvector_len (&io->maps); i++) {
		RIOMap *map = r_pvector_at (&io->maps, i);
		if (map->id == id) {
			r_pvector_remove_at (&io->maps, i);
			_map_free (map);
			r_id_pool_kick_id (io->map_ids, id);
			io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

//delete all maps with specified fd
R_API bool r_io_map_del_for_fd(RIO* io, int fd) {
	r_return_val_if_fail (io, false);
	bool ret = false;
	size_t i;
	for (i = 0; i < r_pvector_len (&io->maps);) {
		RIOMap *map = r_pvector_at (&io->maps, i);
		if (!map) {
			r_pvector_remove_at (&io->maps, i);
		} else if (map->fd == fd) {
			r_id_pool_kick_id (io->map_ids, map->id);
			//delete iter and map
			r_pvector_remove_at (&io->maps, i);
			_map_free (map);
			ret = true;
		} else {
			i++;
		}
	}
	if (ret) {
		io_map_calculate_skyline (io);
	}
	return ret;
}

//brings map with specified id to the tail of of the list
//return a boolean denoting whether is was possible to priorized
R_API bool r_io_map_priorize(RIO* io, ut32 id) {
	r_return_val_if_fail (io, false);
	size_t i;
	for (i = 0; i < r_pvector_len (&io->maps); i++) {
		RIOMap *map = r_pvector_at (&io->maps, i);
		// search for iter with the correct map
		if (map->id == id) {
			r_pvector_remove_at (&io->maps, i);
			r_pvector_push (&io->maps, map);
			io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

R_API bool r_io_map_depriorize(RIO* io, ut32 id) {
	r_return_val_if_fail (io, false);
	size_t i;
	for (i = 0; i < r_pvector_len (&io->maps); i++) {
		RIOMap *map = r_pvector_at (&io->maps, i);
		// search for iter with the correct map
		if (map->id == id) {
			r_pvector_remove_at (&io->maps, i);
			r_pvector_push_front (&io->maps, map);
			io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

R_API bool r_io_map_priorize_for_fd(RIO *io, int fd) {
	r_return_val_if_fail (io, false);
	//we need a clean list for this, or this becomes a segfault-field
	r_io_map_cleanup (io);
	RPVector temp;
	r_pvector_init (&temp, NULL);
	size_t i;
	for (i = 0; i < r_pvector_len (&io->maps);) {
		RIOMap *map = r_pvector_at (&io->maps, i);
		if (map->fd == fd) {
			r_pvector_push (&temp, map);
			r_pvector_remove_at (&io->maps, i);
			continue;
		}
		i++;
	}
	r_pvector_insert_range (&io->maps, r_pvector_len (&io->maps), temp.v.a, r_pvector_len (&temp));
	r_pvector_clear (&temp);
	io_map_calculate_skyline (io);
	return true;
}

//may fix some inconsistencies in io->maps
R_API void r_io_map_cleanup(RIO* io) {
	r_return_if_fail (io);
	//remove all maps if no descs exist
	if (!io->files) {
		r_io_map_fini (io);
		r_io_map_init (io);
		return;
	}
	bool del = false;
	size_t i;
	for (i = 0; i < r_pvector_len (&io->maps);) {
		RIOMap *map = r_pvector_at (&io->maps, i);
		if (!map) {
			// remove iter if the map is a null-ptr, this may fix some segfaults. This should never happen.
			r_warn_if_reached ();
			r_pvector_remove_at (&io->maps, i);
			del = true;
		} else if (!r_io_desc_get (io, map->fd)) {
			//delete map and iter if no desc exists for map->fd in io->files
			r_id_pool_kick_id (io->map_ids, map->id);
			map = r_pvector_remove_at (&io->maps, i);
			_map_free (map);
			del = true;
		} else {
			i++;
		}
	}
	if (del) {
		io_map_calculate_skyline (io);
	}
}

R_API void r_io_map_fini(RIO* io) {
	r_return_if_fail (io);
	r_pvector_clear (&io->maps);
	r_id_pool_free (io->map_ids);
	io->map_ids = NULL;
	r_skyline_clear (&io->map_skyline);
}

R_API void r_io_map_set_name(RIOMap* map, const char* name) {
	r_return_if_fail (map && name);
	free (map->name);
	map->name = strdup (name);
}

R_API void r_io_map_del_name(RIOMap* map) {
	if (map) {
		R_FREE (map->name);
	}
}

// TODO: very similar to r_io_map_next_address, decide which one to use
R_API ut64 r_io_map_next_available(RIO* io, ut64 addr, ut64 size, ut64 load_align) {
	if (load_align == 0) {
		load_align = 1;
	}
	ut64 next_addr = addr,
	end_addr = next_addr + size;
	void **it;
	r_pvector_foreach (&io->maps, it) {
		RIOMap *map = *it;
		ut64 to = r_io_map_end (map);
		next_addr = R_MAX (next_addr, to + (load_align - (to % load_align)) % load_align);
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		// adding the check for the map's fd to see if this removes contention for
		// memory mapping with multiple files. infinite loop ahead?
		if ((r_io_map_begin (map) <= next_addr && next_addr < to) || r_io_map_contain (map, end_addr)) {
			next_addr = to + (load_align - (to % load_align)) % load_align;
			if (next_addr == addr) {
				return UT64_MAX;
			}
			return r_io_map_next_available (io, next_addr, size, load_align);
		}
		break;
	}
	return next_addr;
}

// TODO: very similar to r_io_map_next_available. decide which one to use
R_API ut64 r_io_map_next_address(RIO* io, ut64 addr) {
	ut64 lowest = UT64_MAX;
	void **it;
	r_pvector_foreach (&io->maps, it) {
		RIOMap *map = *it;
		ut64 from = r_io_map_begin (map);
		if (from > addr && addr < lowest) {
			lowest = from;
		}
		ut64 to = r_io_map_end (map);
		if (to > addr && to < lowest) {
			lowest = to;
		}
	}
	return lowest;
}

R_API RList* r_io_map_get_by_fd(RIO* io, int fd) {
	RList* map_list = r_list_newf (NULL);
	if (!map_list) {
		return NULL;
	}
	void **it;
	r_pvector_foreach (&io->maps, it) {
		RIOMap *map = *it;
		if (map && map->fd == fd) {
			r_list_append (map_list, map);
		}
	}
	return map_list;
}

R_API bool r_io_map_resize(RIO *io, ut32 id, ut64 newsize) {
	RIOMap *map;
	if (!newsize || !(map = r_io_map_get (io, id))) {
		return false;
	}
	ut64 addr = r_io_map_begin (map);
	if (UT64_MAX - newsize + 1 < addr) {
		r_io_map_set_size (map, -addr);
		r_io_map_new (io, map->fd, map->perm, map->delta - addr, 0, newsize + addr);
		return true;
	}
	r_io_map_set_size (map, newsize);
	io_map_calculate_skyline (io);
	return true;
}

// find a location that can hold enough bytes without overlapping
// XXX this function is buggy and doesnt works as expected, but i need it for a PoC for now
R_API ut64 r_io_map_location(RIO *io, ut64 size) {
	ut64 base = (io->bits == 64)? 0x60000000000LL: 0x60000000;
	while (r_io_map_get_at (io, base)) {
		base += 0x200000;
	}
	return base;
}

R_API RIOMap *r_io_map_get_by_ref(RIO *io, RIOMapRef *ref) {
	r_return_val_if_fail (io && ref, NULL);
	RIOMap *map = r_io_map_get (io, ref->id);
	if (!map) {
		return NULL;
	}
	if (map->ts != ref->ts) {
		//trigger cleanup here?
		return NULL;
	}
	return map;
}
