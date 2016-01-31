/* libgdbr - LGPL - Copyright 2014-2016 - defragger */

#include "packet.h"

#define DELTA_CHECK 0

char get_next_token(parsing_object_t* po) {
	return po->buffer[po->position++];
}

void handle_escape(parsing_object_t* po) {
	char token;
	if (po->position >= po->length) return;
	token = get_next_token (po);
	if (token == '}') handle_data (po);
	else handle_escape (po);
}

void handle_chk(parsing_object_t* po) {
	char checksum[3];
	if (po->position >= po->length) return;
	checksum[0] = get_next_token (po);
	checksum[1] = get_next_token (po);
	checksum[2] = '\0';
	po->checksum = (uint8_t) strtol (checksum, NULL, 16);
}

void handle_data(parsing_object_t* po) {
	char token;
	if (po->position >= po->length) return;
	token = get_next_token (po);
	if (token == '#') {
		po->end = po->position - 1; // subtract 2 cause of # itself and the incremented position after getNextToken
		handle_chk (po);
	} else if (token == '{') {
		handle_escape (po);
	} else handle_data (po);
}

void handle_packet(parsing_object_t* po) {
	char token;
	if (po->position >= po->length) return;
	token = get_next_token (po);
	if (token == '$') {
		po->start = po->position;
		handle_data (po);
	}
	else if	(token == '+') {
		po->acks++;
		handle_packet (po);
	}
}

/**
 * helper function that should unpack
 * run-length encoded streams of data
 */
int unpack_data(char* dst, char* src, uint64_t len) {
	int i = 0;
	char last = 0;
	int ret_len = 0;
	char* p_dst = dst;
	while (i < len) {
		if (src[i] == '*') {
			if (++i >= len) {
				eprintf ("Runlength decoding error\n");
			}
			char size = src[i++];
			uint8_t runlength = size - 29;
			ret_len += runlength - 2;
			while (i < len && runlength-- > 0) {
				*(p_dst++) = last;
			}
			continue;
		}
		last = src[i++];
		*(p_dst++) = last;
	}
	return ret_len;
}

int parse_packet(libgdbr_t* g, int data_offset) {
	int runlength;
	uint64_t po_size, target_pos = 0;
	parsing_object_t new;
	memset (&new, 0, sizeof (parsing_object_t));
	new.length = g->read_len;
	new.buffer = g->read_buff;
	while (new.position < new.length) {
		handle_packet (&new);
		new.start += data_offset;
		po_size = new.end - new.start;
#if DELTA_CHECK
		if (po_size + target_pos > 4096) {
			po_size = 4096 - target_pos;
			if (po_size > 4096) break;
		}
#endif
		runlength = unpack_data (g->data + target_pos,
			new.buffer + new.start, po_size);
		target_pos += po_size + runlength;
	}
	g->data_len = target_pos; // setting the resulting length
	g->read_len = 0; // reset the read_buf len
	return 0;
}

int send_packet(libgdbr_t* g) {
	if (!g) {
		eprintf ("Initialize libgdbr_t first\n");
		return -1;
	}
	return r_socket_write (g->sock, g->send_buff, g->send_len);
}


// XXX hardcoded 4096 buff size
int read_packet(libgdbr_t* g) {
	int rc, po_size = 0;
	if (!g) {
		eprintf ("Initialize libgdbr_t first\n");
		return -1;
	}
	while (r_socket_ready (g->sock, 0, 250 * 1000) > 0) {
		int szdelta = (int)((st64)g->read_max - (st64)po_size);
#if DELTA_CHECK
		if (szdelta < 1) {
			break;
		}
		if (po_size + szdelta > 4096) {
			if (po_size < 4096) {
				szdelta = g->read_max - po_size;
			} else {
				szdelta = -1;
			}
			if (szdelta < 1) {
				break;
			}
		}
		rc = r_socket_read (g->sock,
			((ut8*)g->read_buff + po_size), szdelta);
		//if (rc < 1) break;
		po_size += rc;
		if (po_size > g_read_max) {
			break;
		}
#else
		po_size += r_socket_read (g->sock,
			((ut8*)g->read_buff + po_size), szdelta);

		if (po_size > 3 && g->read_buff[po_size - 3] == '#')
			break;
#endif
	}
	g->read_len = po_size;
	return po_size;
}
