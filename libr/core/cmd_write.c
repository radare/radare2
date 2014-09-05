/* radare - LGPL - Copyright 2009-2014 - pancake */

#include "../util/debruijn.c"

static void cmd_write_bits(RCore *core, int set, ut64 val) {
	ut64 ret, orig;
	// used to set/unset bit in current address
	r_core_read_at (core, core->offset, (ut8*)&orig, sizeof (orig));
	if (set) {
		ret = orig | val;
	} else {
		ret = orig & (~(val));
	}
	r_core_write_at (core, core->offset,
		(const ut8*)&ret, sizeof (ret));
}

static void cmd_write_inc(RCore *core, int size, st64 num) {
	ut64 *v64;
	ut32 *v32;
	ut16 *v16;
	ut8 *v8;
	switch (size) {
	case 1: v8 = (ut8*)core->block; *v8 += num; break;
	case 2: v16 = (ut16*)core->block; *v16 += num; break;
	case 4: v32 = (ut32*)core->block; *v32 += num; break;
	case 8: v64 = (ut64*)core->block; *v64 += num; break;
	}
	// TODO: obey endian here
        r_core_write_at (core, core->offset, core->block, size);
}

/* TODO: simplify using r_write */
static int cmd_write(void *data, const char *input) {
	int wseek, i, size, len = strlen (input);
	RCore *core = (RCore *)data;
	char *tmp, *str, *ostr;
	const char *arg, *filename;
	char _fn[32];
	ut64 off;
	ut8 *buf;
	st64 num;

	#define WSEEK(x,y) if (wseek)r_core_seek_delta (x,y)
	wseek = r_config_get_i (core->config, "cfg.wseek");
	str = ostr = strdup (input+1);
	_fn[0] = 0;

	switch (*input) {
	case 'B':
		switch (input[1]) {
		case ' ':
			cmd_write_bits (core, 1, r_num_math (core->num, input+2));
			break;
		case '-':
			cmd_write_bits (core, 0, r_num_math (core->num, input+2));
			break;
		default:
			eprintf ("Usage: wB 0x2000  # or wB-0x2000\n");
			break;
		}
		break;
	case '1':
	case '2':
	case '4':
	case '8':
		if (input[1]==input[2]) {
			num = 1;
		} else num = r_num_math (core->num, input+2);
		switch (input[1]) {
		case '+':
			cmd_write_inc (core, *input-'0', num);
			break;
		case '-':
			cmd_write_inc (core, *input-'0', -num);
			break;
		default:
			eprintf ("Usage: w[1248][+-][num]   # inc/dec byte/word/..\n");
		}
		break;
	case 'h':
		{
		char *p = strchr (input, ' ');
		if (p) {
			while (*p==' ') p++;
			p = r_file_path (p);
			if (p) {
				r_cons_printf ("%s\n", p);
				free (p);
			}
		}
		}
		break;
	case 'e':
		{
		ut64 addr = 0, len = 0, b_size = 0;
		st64 dist = 0;
		ut8* bytes = NULL;
		int cmd_suc = R_FALSE;
		char *input_shadow = NULL, *p = NULL;

		switch (input[1]) {
			case 'n':
				if (input[2] == ' ') {
					len = *input ? r_num_math (
						core->num, input+3) : 0;
					if (len > 0){
						ut64 cur_off = core->offset;
						cmd_suc = r_core_extend_at (core, core->offset, len);
						core->offset = cur_off;
						r_core_block_read (core, 0);
					}
				}
				break;
			case 'N':
				if (input[2] == ' ') {
					input += 3;
					while (*input && *input == ' ') input++;
					addr = r_num_math (core->num, input);
					while (*input && *input != ' ') input++;
					input++;
					len = *input ? r_num_math (core->num, input) : 0;
					if (len > 0){
						ut64 cur_off = core->offset;
						cmd_suc = r_core_extend_at (core, addr, len);
						cmd_suc = r_core_seek (core, cur_off, 1);
						core->offset = addr;
						r_core_block_read (core, 0);
					}
				}
				break;
			case 'x':
				if (input[2] == ' ') {
					input+=2;
					len = *input ? strlen (input) : 0;
					bytes = len > 1? malloc (len+1) : NULL;
					len = bytes ? r_hex_str2bin (input, bytes) : 0;
					if (len > 0) {
						ut64 cur_off = core->offset;
						cmd_suc = r_core_extend_at (core, cur_off, len);
						if (cmd_suc) {
							r_core_write_at (core, cur_off, bytes, len);
						}
						core->offset = cur_off;
						r_core_block_read (core, 0);
					}
					free (bytes);
				}
				break;
			case 'X':
				if (input[2] == ' ') {
					addr = r_num_math (core->num, input+3);
					input += 3;
					while (*input && *input != ' ') input++;
					input++;
					len = *input ? strlen (input) : 0;
					bytes = len > 1? malloc (len+1) : NULL;
					len = bytes ? r_hex_str2bin (input, bytes) : 0;
					if (len > 0) {
						//ut64 cur_off = core->offset;
						cmd_suc = r_core_extend_at (core, addr, len);
						if (cmd_suc) {
							r_core_write_at (core, addr, bytes, len);
						}
						core->offset = addr;
						r_core_block_read (core, 0);
					}
					free (bytes);
				}
				break;
			case 's':
				input +=  3;
				while (*input && *input == ' ') input++;
				len = strlen (input);
				input_shadow = len > 0? malloc (len+1): 0;

				// since the distance can be negative,
				// the r_num_math will perform an unwanted operation
				// the solution is to tokenize the string :/
				if (input_shadow) {
					strncpy (input_shadow, input, len+1);
					p = strtok (input_shadow, " ");
					addr = p && *p ? r_num_math (core->num, p) : 0;

					p = strtok (NULL, " ");
					dist = p && *p ? r_num_math (core->num, p) : 0;

					p = strtok (NULL, " ");
					b_size = p && *p ? r_num_math (core->num, p) : 0;
					if (dist != 0){
						r_core_shift_block (core, addr, b_size, dist);
						r_core_seek (core, addr, 1);
						cmd_suc = R_TRUE;
					}
				}
				free (input_shadow);
				break;
			case '?':
			default:
				cmd_suc = R_FALSE;
		}


		if (cmd_suc == R_FALSE) {
			r_cons_printf ("|Usage: write extend\n"
			"wen <num>               insert num null bytes at current offset\n"
			"wex <hex_bytes>         insert bytes at current offset\n"
			"weN <addr> <len>        insert bytes at address\n"
			"weX <addr> <hex_bytes>  insert bytes at address\n"
			"wes <addr>  <dist> <block_size>   shift a blocksize left or write in the editor\n"
			);
		}
		}
		break;
	case 'p':
		if (input[1]=='-' || (input[1]==' '&&input[2]=='-')) {
			const char *tmpfile = ".tmp";
			char *out = r_core_editor (core, NULL);
			if (out) {
				// XXX hacky .. patch should support str, not only file
				r_file_dump (tmpfile, (ut8*)out, strlen (out));
				r_core_patch (core, tmpfile);
				r_file_rm (tmpfile);
				free (out);
			}
		} else {
			if (input[1]==' ' && input[2]) {
				r_core_patch (core, input+2);
			} else {
				eprintf ("Usage: wp [-|r2patch-file]\n"
			         "TODO: rapatch format documentation here\n");
			}
		}
		break;
	case 'u':
		// TODO: implement it in an API RCore.write_unified_hexpatch() is ETOOLONG
		if (input[1]==' ') {
			char *data = r_file_slurp (input+2, NULL);
			if (data) {
				char sign = ' ';
				int line = 0, offs = 0, hexa = 0;
				int newline = 1;
				for (i=0; data[i]; i++) {
					switch (data[i]) {
					case '+':
						if (newline)
							sign = 1;
						break;
					case '-':
						if (newline) {
							sign = 0;
							offs = i + ((data[i+1]==' ')?2:1);
						}
						break;
					case ' ':
						data[i] = 0;
						if (sign) {
							if (!line) line = i+1;
							else
							if (!hexa) hexa = i+1;
						}
						break;
					case '\r':
						break;
					case '\n':
						newline = 1;
						if (sign == -1) {
							offs = 0;
							line = 0;
							hexa = 0;
						} else if (sign) {
							if (offs && hexa) {
								r_cons_printf ("wx %s @ %s\n", data+hexa, data+offs);
							} else eprintf ("food\n");
							offs = 0;
							line = 0;
						} else hexa = 0;
						sign = -1;
						continue;
					}
					newline = 0;
				}
				free (data);
			}
		} else {
			eprintf ("|Usage: wu [unified-diff-patch]    # see 'cu'\n");
		}
		break;
	case 'r':
		off = r_num_math (core->num, input+1);
		len = (int)off;
		if (len>0) {
			buf = malloc (len);
			if (buf != NULL) {
				r_num_irand ();
				for (i=0; i<len; i++)
					buf[i] = r_num_rand (256);
				r_core_write_at (core, core->offset, buf, len);
				WSEEK (core, len);
				free (buf);
			} else eprintf ("Cannot allocate %d bytes\n", len);
		}
		break;
	case 'A':
		switch (input[1]) {
		case ' ':
			if (input[2] && input[3]==' ') {
				r_asm_set_pc (core->assembler, core->offset);
				eprintf ("modify (%c)=%s\n", input[2], input+4);
				len = r_asm_modify (core->assembler, core->block, input[2],
					r_num_math (core->num, input+4));
				eprintf ("len=%d\n", len);
				if (len>0) {
					r_core_write_at (core, core->offset, core->block, len);
					WSEEK (core, len);
				} else eprintf ("r_asm_modify = %d\n", len);
			} else eprintf ("Usage: wA [type] [value]\n");
			break;
		case '?':
		default:
			r_cons_printf ("|Usage: wA [type] [value]\n"
			"|Types:\n"
			"| r   raw write value\n"
			"| v   set value (taking care of current address)\n"
			"| d   destination register\n"
			"| 0   1st src register\n"
			"| 1   2nd src register\n"
			"|Example: wA r 0 # e800000000\n");
			break;
		}
		break;
	case 'c':
		switch (input[1]) {
		case 'i':
			r_io_cache_commit (core->io);
			r_core_block_read (core, 0);
			break;
		case 'r':
			r_io_cache_reset (core->io, R_TRUE);
			/* Before loading the core block we have to make sure that if
			 * the cache wrote past the original EOF these changes are no
			 * longer displayed. */
			memset (core->block, 0xff, core->blocksize);
			r_core_block_read (core, 0);
			break;
		case '-':
			if (input[2]=='*') {
				r_io_cache_reset (core->io, R_TRUE);
			} else if (input[2]==' ') {
				char *p = strchr (input+3, ' ');
				ut64 to, from = core->offset;
				if (p) {
					*p = 0;
					from = r_num_math (core->num, input+3);
					to = r_num_math (core->num, input+3);
					if (to<from) {
						eprintf ("Invalid range (from>to)\n");
						return 0;
					}
				} else {
					from = r_num_math (core->num, input+3);
					to = from + core->blocksize;
				}
				r_io_cache_invalidate (core->io, from, to);
			} else {
				eprintf ("Invalidate write cache at 0x%08"PFMT64x"\n", core->offset);
				r_io_cache_invalidate (core->io, core->offset, core->offset+core->blocksize);
			}
			/* See 'r' above. */
			memset (core->block, 0xff, core->blocksize);
			r_core_block_read (core, 0);
			break;
		case '?':
	{
                const char* help_msg[] = {
			"Usage:", "wc[ir*?]","  # Note: requires io.cache=true",
			"wc","","list all write changes",
			"wc-"," [a] [b]","remove write op at curseek or given addr",
			"wc*","","\"\" in radare commands",
			"wcr","","reset all write changes in cache",
			"wci","","commit write cache",
                        NULL
                        };
                        r_core_cmd_help(core, help_msg);
        }
			break;
		case '*':
			r_io_cache_list (core->io, R_TRUE);
			break;
		case '\0':
			if (!r_config_get_i (core->config, "io.cache"))
				eprintf ("[warning] e io.cache must be true\n");
			r_io_cache_list (core->io, R_FALSE);
			break;
		}
		break;
	case ' ':
		/* write string */
		len = r_str_unescape (str);
		r_core_write_at (core, core->offset, (const ut8*)str, len);
#if 0
		r_io_use_desc (core->io, core->file->desc);
		r_io_write_at (core->io, core->offset, (const ut8*)str, len);
#endif
		WSEEK (core, len);
		r_core_block_read (core, 0);
		break;
	case 't':
		if (*str == '?') {
			eprintf ("Usage: wt file [size]\n");
			return 0;
		} else
		if (*str != ' ') {
			const char* prefix = r_config_get (core->config, "cfg.prefixdump");
			snprintf(_fn, sizeof(_fn), "%s.0x%08"PFMT64x, prefix, core->offset);
			filename = _fn;
		}  else filename = str+1;
		tmp = strchr (str+1, ' ');
		if (tmp) {
			st64 sz = (st64) r_num_math (core->num, tmp+1);
			*tmp = 0;
			if (sz<1) eprintf ("Invalid length\n");
			else r_core_dump (core, filename, core->offset, (ut64)sz);
		} else r_file_dump (filename, core->block, core->blocksize);
		eprintf ("Dump %d bytes from 0x%08"PFMT64x" into %s\n",
			core->blocksize, core->offset, filename);
		break;
	case 'T':
		eprintf ("TODO: wT // why?\n");
		break;
	case 'f':
		arg = (const char *)(input+((input[1]==' ')?2:1));
		if (!strcmp (arg, "-")) {
			char *out = r_core_editor (core, NULL);
			if (out) {
				r_io_write_at (core->io, core->offset,
					(ut8*)out, strlen (out));
				free (out);
			}
		} else
		if ((buf = (ut8*) r_file_slurp (arg, &size))) {
			r_io_use_desc (core->io, core->file->desc);
			r_io_write_at (core->io, core->offset, buf, size);
			WSEEK (core, size);
			free (buf);
			r_core_block_read (core, 0);
		} else eprintf ("Cannot open file '%s'\n", arg);
		break;
	case 'F':
		arg = (const char *)(input+((input[1]==' ')?2:1));
		if (!strcmp (arg, "-")) {
			int len;
			ut8 *out;
			char *in = r_core_editor (core, NULL);
			if (in) {
				out = (ut8 *)strdup (in);
				if (out) {
					len = r_hex_str2bin (in, out);
					if (len>0)
						r_io_write_at (core->io, core->offset, out, len);
					free (out);
				}
				free (in);
			}
		} else
		if ((buf = r_file_slurp_hexpairs (arg, &size))) {
			r_io_use_desc (core->io, core->file->desc);
			r_io_write_at (core->io, core->offset, buf, size);
			WSEEK (core, size);
			free (buf);
			r_core_block_read (core, 0);
		} else eprintf ("Cannot open file '%s'\n", arg);
		break;
	case 'w':
		str++;
		len = (len-1)<<1;
		if (len>0) tmp = malloc (len+1);
		else tmp = NULL;
		if (tmp) {
			for (i=0; i<len; i++) {
				if (i%2) tmp[i] = 0;
				else tmp[i] = str[i>>1];
			}
			str = tmp;
			r_io_use_desc (core->io, core->file->desc);
			r_io_write_at (core->io, core->offset, (const ut8*)str, len);
			WSEEK (core, len);
			r_core_block_read (core, 0);
			free (tmp);
		} else eprintf ("Cannot malloc %d\n", len);
		break;
	case 'x':
		{
		int b, len = strlen (input);
		ut8 *buf = malloc (len+1);
		len = r_hex_str2bin (input+1, buf);
		if (len != 0) {
			if (len<0) len = -len+1;
			if (len<core->blocksize) {
				b = core->block[len]&0xf;
				b |= (buf[len]&0xf0);
			} else b = buf[len];
			buf[len] = b;
			r_core_write_at (core, core->offset, buf, len);
			WSEEK (core, len);
			r_core_block_read (core, 0);
		} else eprintf ("Error: invalid hexpair string\n");
		free (buf);
		}
		break;
	case 'a':
		switch (input[1]) {
		case 'o':
			if (input[2] == ' ')
				r_core_hack (core, input+3);
			else r_core_hack_help (core);
			break;
		case ' ':
		case '*':
			{ const char *file = input[1]=='*'? input+2: input+1;
			RAsmCode *acode;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, file);
			if (acode) {
				if (input[1]=='*') {
					r_cons_printf ("wx %s\n", acode->buf_hex);
				} else {
					if (r_config_get_i (core->config, "scr.prompt"))
						eprintf ("Written %d bytes (%s) = wx %s\n", acode->len, input+2, acode->buf_hex);
					r_core_write_at (core, core->offset, acode->buf, acode->len);
					WSEEK (core, acode->len);
					r_core_block_read (core, 0);
				}
				r_asm_code_free (acode);
			}
			} break;
		case 'f':
			if ((input[2]==' '||input[2]=='*')) {
				const char *file = input[2]=='*'? input+4: input+3;
				RAsmCode *acode;
				r_asm_set_pc (core->assembler, core->offset);
				acode = r_asm_assemble_file (core->assembler, file);
				if (acode) {
					if (input[2]=='*') {
						r_cons_printf ("wx %s\n", acode->buf_hex);
					} else {
						if (r_config_get_i (core->config, "scr.prompt"))
						eprintf ("Written %d bytes (%s)=wx %s\n", acode->len, input+1, acode->buf_hex);
						r_core_write_at (core, core->offset, acode->buf, acode->len);
						WSEEK (core, acode->len);
						r_core_block_read (core, 0);
					}
					r_asm_code_free (acode);
				} else eprintf ("Cannot assemble file\n");
			} else eprintf ("Wrong argument\n");
			break;
		default:
			r_cons_printf ("|Usage: wa[of*] [arg]\n"
				"| wa nop           : write nopcode using asm.arch and asm.bits\n"
				"| wa* mov eax, 33  : show 'wx' op with hexpair bytes of sassembled opcode\n"
				"| \"wa nop;nop\"     : assemble more than one instruction (note the quotes)\n"
				"| waf foo.asm      : assemble file and write bytes\n"
				"| wao nop          : convert current opcode into nops\n"
				"| wao?             : show help for assembler operation on current opcode (hack)\n");
			break;
		}
		break;
	case 'b':
		{
		int len = strlen (input);
		ut8 *buf = malloc (len+1);
		if (buf) {
			len = r_hex_str2bin (input+1, buf);
			if (len > 0) {
				r_mem_copyloop (core->block, buf, core->blocksize, len);
				r_core_write_at (core, core->offset, core->block, core->blocksize);
				WSEEK (core, core->blocksize);
				r_core_block_read (core, 0);
			} else eprintf ("Wrong argument\n");
			free (buf);
		} else eprintf ("Cannot malloc %d\n", len+1);
		}
		break;
	case 'm':
		size = r_hex_str2bin (input+1, (ut8*)str);
		switch (input[1]) {
		case '\0':
			eprintf ("Current write mask: TODO\n");
			// TODO
			break;
		case '?':
			break;
		case '-':
			r_io_set_write_mask (core->io, 0, 0);
			eprintf ("Write mask disabled\n");
			break;
		case ' ':
			if (size>0) {
				r_io_use_desc (core->io, core->file->desc);
				r_io_set_write_mask (core->io, (const ut8*)str, size);
				WSEEK (core, size);
				eprintf ("Write mask set to '");
				for (i=0; i<size; i++)
					eprintf ("%02x", str[i]);
				eprintf ("'\n");
			} else eprintf ("Invalid string\n");
			break;
		}
		break;
	case 'v':
		{
			int type = 0;
			ut8 addr1;
			ut16 addr2;
			ut32 addr4, addr4_;
			ut64 addr8;

			switch (input[1]) {
			case '?':
				r_cons_printf ("|Usage: wv[size] [value]    # write value of given size\n"
					"|  wv1 234      # write one byte with this value\n"
					"|  wv 0x834002  # write dword with this value\n"
					"|Supported sizes are: 1, 2, 4, 8\n");
				free (ostr);
				return 0;
			case '1': type = 1; break;
			case '2': type = 2; break;
			case '4': type = 4; break;
			case '8': type = 8; break;
			}
			off = r_num_math (core->num, input+2);
			r_io_use_desc (core->io, core->file->desc);
			r_io_seek (core->io, core->offset, R_IO_SEEK_SET);
			if (type == 0)
				type = (off&UT64_32U)? 8: 4;
			switch (type) {
			case 1:
				addr1 = (ut8)off;
				r_io_write (core->io, (const ut8 *)&addr1, 1);
				WSEEK (core, 1);
				break;
			case 2:
				addr2 = (ut16)off;
				r_io_write (core->io, (const ut8 *)&addr2, 2);
				WSEEK (core, 2);
				break;
			case 4:
				addr4_ = (ut32)off;
				//drop_endian((ut8*)&addr4_, (ut8*)&addr4, 4); /* addr4_ = addr4 */
				//endian_memcpy((ut8*)&addr4, (ut8*)&addr4_, 4); /* addr4 = addr4_ */
				memcpy ((ut8*)&addr4, (ut8*)&addr4_, 4); // XXX needs endian here too
				r_io_write (core->io, (const ut8 *)&addr4, 4);
				WSEEK (core, 4);
				break;
			case 8:
				/* 8 byte addr */
				memcpy ((ut8*)&addr8, (ut8*)&off, 8); // XXX needs endian here
			//	endian_memcpy((ut8*)&addr8, (ut8*)&off, 8);
				r_io_write (core->io, (const ut8 *)&addr8, 8);
				WSEEK (core, 8);
				break;
			}
			r_core_block_read (core, 0);
		}
		break;
	case 'o':
		switch (input[1]) {
			case 'a':
			case 's':
			case 'e':
			case 'A':
			case 'x':
			case 'r':
			case 'l':
			case 'm':
			case 'd':
			case 'o':
			case 'w':
				if (input[2]!=' ') {
					if (input[1]=='e') r_cons_printf (
						"Usage: 'woe from-to step'\n");
					else r_cons_printf (
						"Usage: 'wo%c 00 11 22'\n", input[1]);
					free (ostr);
					return 0;
				}
			case '2':
			case '4':
				r_core_write_op (core, input+3, input[1]);
				r_core_block_read (core, 0);
				break;
			case 'R':
				r_core_cmd0 (core, "wr $b");
				break;
			case 'n':
				r_core_write_op (core, "ff", 'x');
				r_core_block_read (core, 0);
				break;
      case 'D':
        if (input[2] != ' ') {
          r_cons_printf("Usage: woD length @ address\n");
          free(ostr);
          return 0;
        }
        off = r_num_math(core->num, input + 2);
        len = (int)off;
        if (len > 0) {
          char* buf = cyclic_pattern(len, 0, debruijn_charset);
          printf("%s\n", buf);
          if (buf != NULL) {
            r_core_write_at(core, core->offset, (const ut8 *)buf, len);
            WSEEK(core, len);
            free(buf);
          } else {
            eprintf("Couldn't generate pattern of length %d\n", len);
          }
        }
        break;
      case 'O':
        if (input[2] != ' ') {
          r_cons_printf("Usage: woO value\n");
          free(ostr);
          return 0;
        }
        off = r_num_math(core->num, input + 2);
        len = (int)off;
        int guest_endian = r_bin_get_info(core->bin)->big_endian ? 0 : 1;
        int offset = cyclic_pattern_offset(len, guest_endian);
        printf("%d\n", offset);
        break;
			case '\0':
			case '?':
			default:
				r_cons_printf (
					"|Usage: wo[asmdxoArl24] [hexpairs] @ addr[:bsize]\n"
					"|Example:\n"
					"|  wox 0x90   ; xor cur block with 0x90\n"
					"|  wox 90     ; xor cur block with 0x90\n"
					"|  wox 0x0203 ; xor cur block with 0203\n"
					"|  woa 02 03  ; add [0203][0203][...] to curblk\n"
					"|  woe 02 03  \n"
					"|Supported operations:\n"
					"|  wow  ==  write looped value (alias for 'wb')\n"
					"|  woa  +=  addition\n"
					"|  wos  -=  substraction\n"
					"|  wom  *=  multiply\n"
					"|  wod  /=  divide\n"
					"|  wox  ^=  xor\n"
					"|  woo  |=  or\n"
					"|  woA  &=  and\n"
					"|  woR  random bytes (alias for 'wr $b'\n"
					"|  wor  >>= shift right\n"
					"|  wol  <<= shift left\n"
					"|  wo2  2=  2 byte endian swap\n"
					"|  wo4  4=  4 byte endian swap\n"
          "|  woD  De Bruijn Pattern (syntax woD length @ addr)\n"
          "|  woO  De Bruijn Pattern Offset (syntax: woO value)\n"
						);
				break;
		}
		break;
	case 'd':
		if (input[1]==' ') {
			char *arg, *inp = strdup (input+2);
			arg = strchr (inp, ' ');
			if (arg) {
				*arg = 0;
				ut64 addr = r_num_math (core->num, input+2);
				ut64 len = r_num_math (core->num, arg+1);
				ut8 *data = malloc (len);
				r_io_read_at (core->io, addr, data, len);
				r_io_write_at (core->io, core->offset, data, len);
				free (data);
			} else eprintf ("See wd?\n");
			free (inp);
		} else eprintf ("Usage: wd [source-offset] [length] @ [dest-offset]\n");
		break;
	case 's':
		{
			ut8 ulen;
			len = r_str_unescape (str+1);
			if (len>255) {
				eprintf ("Too large\n");
			} else {
				ulen = (ut8)len;
				r_core_write_at (core, core->offset, &ulen, 1);
				r_core_write_at (core, core->offset+1, (const ut8*)str+1, len);
				WSEEK (core, len);
				r_core_block_read (core, 0);
			}
		}
		break;
	default:
	case '?':
		if (core->oobi) {
			eprintf ("Writing oobi buffer!\n");
			r_io_use_desc (core->io, core->file->desc);
			r_io_write (core->io, core->oobi, core->oobi_len);
			WSEEK (core, core->oobi_len);
			r_core_block_read (core, 0);
		} else {

                const char* help_msg[] = {
			"Usage:","w[x] [str] [<file] [<<EOF] [@addr]","",
			"wc","","list all write changes",
			"w","[1248][+-][n]","increment/decrement byte,word..",
			"w"," foobar","write string 'foobar'",
			"wh"," r2","whereis/which shell command",
			"wr"," 10","write 10 random bytes",
			"ww"," foobar","write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'",
			"wa"," push ebp","write opcode, separated by ';' (use '\"' around the command)",
			"waf"," file","assemble file and write bytes",
			"wA"," r 0","alter/modify opcode at current seek (see wA?)",
			"wb"," 010203","fill current block with cyclic hexpairs",
			"wc","[ir*?]","write cache undo/commit/reset/list (io.cache)",
			"wd"," [off] [n]","duplicate N bytes from offset at current seek (memcpy) (see y?)",
			"wx"," 9090","write two intel nops",
			"wv"," eip+34","write 32-64 bit value",
			"wo?"," hex","write in block with operation. 'wo?' fmi",
			"wm"," f0ff","set binary mask hexpair to be used as cyclic write mask",
			"ws"," pstring","write 1 byte for length and then the string",
			"wf"," -|file","write contents of file at current offset",
			"wF"," -|file","write contents of hexpairs file here",
			"wp"," -|file","apply radare patch file. See wp? fmi",
			"wt"," file [sz]","write to file (from current seek, blocksize or sz bytes)",
                        NULL
                        };
                        r_core_cmd_help(core, help_msg);
        }
		break;
	}
	free (ostr);
	return 0;
}

