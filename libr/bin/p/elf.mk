OBJ_ELF=bin_elf.o bin_dbginfo_elf.o bin_write_elf.o
OBJ_ELF+=../format/elf/elf.o ../format/elf/elf_write.o

STATIC_OBJ+=${OBJ_ELF}
TARGET_ELF=bin_elf.${EXT_SO}
LDFLAGS+=-lr_db -L../../db

ALL_TARGETS+=${TARGET_ELF}

${TARGET_ELF}: ${OBJ_ELF}
	-${CC} $(call libname,bin_elf) ${CFLAGS} $(LDFLAGS) ${OBJ_ELF}
