/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"

R_API RArchSessionPool *r_arch_sessionpool_new(RArch *arch) {
	RArchSessionPool *sp = R_NEW0(RArchSessionPool);
	sp->arch = arch;
	return sp;
}

R_API RArchSession *r_arch_sessionpool_get_session(RArchSessionPool *asp, RArchSetup *setup) {
	RArchSession *as = r_arch_session_new (asp->arch, setup);
	//  TODO: implement cache 
	// r_htpp_insert (asp->pool, as);
	return as;
}

