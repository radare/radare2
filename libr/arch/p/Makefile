include ../../config.mk
include ../../../mk/platform.mk

CFLAGS+=-I$(TOP)/shlr -I../../include -I../arch/ -I../arch/include
CFLAGS+=-Wall -shared ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
LDFLAGS+=-L../../util -L../../flag
ifeq ($(CC),cccl)
LDFLAGS+=${LINK} -llibr_flag -llibr_util
else
LDFLAGS+=${LINK} -lr_flag -lr_util
endif

CURDIR=

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=

# TODO: rename to enabled plugins
ARCH_PLUGINS=bf

include $(subst $,.mk,$(ARCH_PLUGINS))

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
