-include config-user.mk
include global.mk

R2R=radare2-regressions
R2R_URL=$(shell doc/repo REGRESSIONS)
R2BINS=$(shell cd binr ; echo r*2 r2agent r2pm)
DATADIRS=libr/cons/d libr/bin/d libr/asm/d libr/syscall/d libr/magic/d
R2VC=$(shell git rev-list --all --count)
USE_ZIP=YES
ZIP=zip
ifeq ($(R2VC),)
R2VC=9999999
endif
STRIP?=strip
ifneq ($(shell xz --help 2>/dev/null | grep improve),)
TAR=tar -cvf
TAREXT=tar.xz
CZ=xz -f
else
TAR=bsdtar cvf
TAREXT=tar.gz
CZ=gzip -f
endif
PWD=$(shell pwd)

all: plugins.cfg libr/include/r_version.h
	${MAKE} -C shlr/zip
	${MAKE} -C libr/util
	${MAKE} -C libr/socket
	${MAKE} -C shlr
	${MAKE} -C libr
	${MAKE} -C binr

.PHONY: libr/include/r_version.h
GIT_TAP=$(shell git describe --tags 2>/dev/null || echo $(VERSION))
GIT_TIP=$(shell git rev-parse HEAD 2>/dev/null || echo HEAD)
GIT_NOW=$(shell date +%Y-%m-%d)

libr/include/r_version.h:
	echo "#ifndef R_VERSION_H" > $@
	echo "#define R_VERSION_H 1" >> $@
	echo "#define R2_VERSION_COMMIT $(R2VC)" >> $@
	echo '#define R2_GITTAP "$(GIT_TAP)"' >> $@
	echo '#define R2_GITTIP "$(GIT_TIP)"' >> $@
	echo '#define R2_BIRTH "$(GIT_NOW)"' >> $@
	echo '#endif' >> $@

plugins.cfg:
	@if [ ! -e config-user.mk ]; then echo ; \
	echo "  Please, run ./configure first" ; echo ; exit 1 ; fi
	./configure-plugins

w32:
	sys/mingw32.sh

depgraph.png:
	cd libr ; perl depgraph.pl | dot -Tpng -odepgraph.png

android:
	@if [ -z "$(NDK_ARCH)" ]; then echo "Set NDK_ARCH=[arm|mips|x86]" ; false; fi
	sys/android-${NDK_ARCH}.sh

w32dist:
	${MAKE} windist WINBITS=w32

w64dist:
	${MAKE} windist WINBITS=w64

WINDIST=${WINBITS}dist

windist:
	[ -n "${WINBITS}" ] || exit 1
	rm -rf "radare2-${WINBITS}-${VERSION}" "${WINDIST}"
	mkdir "${WINDIST}"
	for FILE in `find libr | grep -e dll$$`; do cp "$$FILE" "${WINDIST}" ; done
	for FILE in `find binr | grep -e exe$$`; do cp "$$FILE" "${WINDIST}" ; done
	rm -f "${WINDIST}/plugin.dll"
	mkdir -p "${WINDIST}/www"
	cp -rf shlr/www/* "${WINDIST}/www"
	mkdir -p "${WINDIST}/radare2/${VERSION}/magic"
	cp -f libr/magic/d/default/* "${WINDIST}/radare2/${VERSION}/magic"
	mkdir -p "${WINDIST}/radare2/${VERSION}/syscall"
	cp -f libr/syscall/d/*.sdb "${WINDIST}/radare2/${VERSION}/syscall"
	mkdir -p "${WINDIST}/radare2/${VERSION}/opcodes"
	cp -f libr/asm/d/*.sdb "${WINDIST}/radare2/${VERSION}/opcodes"
	mkdir -p "${WINDIST}/share/doc/radare2"
	mkdir -p "${WINDIST}/include/libr/sdb"
	cp -f libr/include/sdb/*.h "${WINDIST}/include/libr/sdb/"
	cp -f libr/include/*.h "${WINDIST}/include/libr"
	#mkdir -p "${WINDIST}/include/libr/sflib"
	cp -f doc/fortunes.* "${WINDIST}/share/doc/radare2"
	mkdir -p "${WINDIST}/share/radare2/${VERSION}/cons"
	cp -f libr/cons/d/* "${WINDIST}/share/radare2/${VERSION}/cons"
	mkdir -p "${WINDIST}/radare2/${VERSION}/hud"
	cp -f doc/hud "${WINDIST}/radare2/${VERSION}/hud/main"
	mv "${WINDIST}" "radare2-${WINBITS}-${VERSION}"
	rm -f "radare2-${WINBITS}-${VERSION}.zip"
ifneq ($(USE_ZIP),NO)
	$(ZIP) -r "radare2-${WINBITS}-${VERSION}.zip" "radare2-${WINBITS}-${VERSION}"
endif

clean: rmd
	for DIR in shlr libr binr ; do (cd "$$DIR" ; ${MAKE} clean) ; done

distclean mrproper:
	-rm -f `find . -type f -name '*.d'`
	for DIR in libr binr shlr ; do ( cd "$$DIR" ; ${MAKE} mrproper) ; done
	rm -f config-user.mk plugins.cfg libr/config.h
	rm -f libr/include/r_userconf.h libr/config.mk
	rm -f pkgcfg/*.pc

pkgcfg:
	cd libr && ${MAKE} pkgcfg

install-man:
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	for FILE in man/*.1 ; do ${INSTALL_MAN} "$$FILE" "${DESTDIR}${MANDIR}/man1" ; done
	cd "${DESTDIR}${MANDIR}/man1" && ln -fs radare2.1 r2.1

install-man-symlink:
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	cd man && for FILE in *.1 ; do \
		ln -fs "${PWD}/man/$$FILE" "${DESTDIR}${MANDIR}/man1/$$FILE" ; done
	cd "${DESTDIR}${MANDIR}/man1" && ln -fs radare2.1 r2.1

install-doc:
	${INSTALL_DIR} "${DESTDIR}${DATADIR}/doc/radare2"
	for FILE in doc/* ; do ${INSTALL_DATA} $$FILE "${DESTDIR}${DATADIR}/doc/radare2" ; done

install-doc-symlink:
	${INSTALL_DIR} "${DESTDIR}${DATADIR}/doc/radare2"
	cd doc ; for FILE in * ; do \
		ln -fs "${PWD}/doc/$$FILE" "${DESTDIR}${DATADIR}/doc/radare2" ; done

install love: install-doc install-man install-www
	cd libr && ${MAKE} install PARENT=1
	cd binr && ${MAKE} install
	cd shlr && ${MAKE} install
	for DIR in ${DATADIRS} ; do \
		(cd "$$DIR" ; ${MAKE} install ); \
	done
	rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}/hud"
	mkdir -p "${DESTDIR}${LIBDIR}/radare2/${VERSION}/hud"
	cp -f doc/hud "${DESTDIR}${LIBDIR}/radare2/${VERSION}/hud/main"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/"
	sys/ldconfig.sh

# Remove make .d files. fixes build when .c files are removed
rmd:
	rm -f `find . -type f -iname '*.d'`

install-www:
	rm -rf "${DESTDIR}${WWWROOT}"
	rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}/www" # old dir
	mkdir -p "${DESTDIR}${WWWROOT}"
	cp -rf shlr/www/* "${DESTDIR}${WWWROOT}"


symstall-www:
	rm -rf "${DESTDIR}${WWWROOT}"
	rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}/www" # old dir
	mkdir -p "${DESTDIR}${WWWROOT}"
	cd "${DESTDIR}${WWWROOT}" ; \
		for FILE in "${PWD}/shlr/www/"* ; do \
			ln -fs "$$FILE" "$(DESTDIR)$(WWWROOT)" ; done

install-pkgconfig-symlink:
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	cd pkgcfg ; for FILE in *.pc ; do \
		ln -fs "$${PWD}/$$FILE" "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; done


symstall install-symlink: install-man-symlink install-doc-symlink install-pkgconfig-symlink symstall-www
	cd libr && ${MAKE} install-symlink
	cd binr && ${MAKE} install-symlink
	cd shlr && ${MAKE} install-symlink
	for DIR in ${DATADIRS} ; do (\
		cd "$$DIR" ; \
		echo "$$DIR" ; \
		${MAKE} install-symlink ); \
	done
	mkdir -p "${DESTDIR}${LIBDIR}/radare2/${VERSION}/hud"
	cd "$(DESTDIR)$(LIBDIR)/radare2/" ;\
		rm -f last ; ln -fs $(VERSION) last
	cd "$(DESTDIR)$(PREFIX)/share/radare2/" ;\
		rm -f last ; ln -fs $(VERSION) last
	ln -fs "${PWD}/doc/hud" "${DESTDIR}${LIBDIR}/radare2/${VERSION}/hud/main"
	mkdir -p "${DESTDIR}${DATADIR}/radare2/${VERSION}/"
	sys/ldconfig.sh

deinstall uninstall:
	cd libr && ${MAKE} uninstall PARENT=1
	cd binr && ${MAKE} uninstall PARENT=1
	cd shlr && ${MAKE} uninstall PARENT=1
	cd libr/syscall/d && ${MAKE} uninstall PARENT=1
	@echo
	@echo "Run 'make purge' to also remove installed files from previous versions of r2"
	@echo

purge-doc:
	rm -rf "${DESTDIR}${DATADIR}/doc/radare2"
	cd man ; for FILE in *.1 ; do rm -f "${DESTDIR}${MANDIR}/man1/$$FILE" ; done
	rm -f "${DESTDIR}${MANDIR}/man1/r2.1"

user-wrap=echo "\#!/bin/sh" > ~/bin/"$1" \
; echo "${PWD}/env.sh '${PREFIX}' '$1' \$$@" >> ~/bin/"$1" \
; chmod +x ~/bin/"$1" ;

user-install:
	mkdir -p ~/bin
	$(foreach mod,$(R2BINS),$(call user-wrap,$(mod)))
	cd ~/bin ; ln -fs radare2 r2

user-uninstall:
	$(foreach mod,$(R2BINS),rm -f ~/bin/"$(mod)")
	rm -f ~/bin/r2
	-rmdir ~/bin

purge-dev:
	rm -f "${DESTDIR}${LIBDIR}/libr_"*".${EXT_AR}"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/r_"*.pc
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr"
	rm -f "${DESTDIR}${LIBDIR}/radare2/${VERSION}/-"*

strip:
	-for FILE in ${R2BINS} ; do ${STRIP} -s "${DESTDIR}${BINDIR}/$$FILE" 2> /dev/null ; done
	-for FILE in "${DESTDIR}${LIBDIR}/libr_"*".${EXT_SO}" "${DESTDIR}${LIBDIR}/libr2.${EXT_SO}" ; do \
		 ${STRIP} -s "$$FILE" ; done

purge: purge-doc purge-dev
	for FILE in ${R2BINS} ; do rm -f "${DESTDIR}${BINDIR}/$$FILE" ; done
	rm -f "${DESTDIR}${BINDIR}/ragg2-cc"
	rm -f "${DESTDIR}${BINDIR}/r2"
	rm -f "${DESTDIR}${LIBDIR}/libr_"*
	rm -f "${DESTDIR}${LIBDIR}/libr2.${EXT_SO}"
	rm -rf "${DESTDIR}${LIBDIR}/radare2"
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr"

dist:
	-[ configure -nt config-user.mk ] && ./configure "--prefix=${PREFIX}"
	git log $$(git show-ref `git tag |tail -n1`)..HEAD > ChangeLog
	cd shlr && ${MAKE} capstone-sync
	DIR=`basename "$$PWD"` ; \
	FILES=`git ls-files | sed -e "s,^,radare2-${VERSION}/,"` ; \
	CS_FILES=`cd shlr/capstone ; git ls-files | grep -v pdf | grep -v xcode | grep -v msvc | grep -v suite | grep -v bindings | grep -v tests | sed -e "s,^,radare2-${VERSION}/shlr/capstone/,"` ; \
	cd .. && mv "$${DIR}" "radare2-${VERSION}" && \
	${TAR} "radare2-${VERSION}.tar" $${FILES} $${CS_FILES} "radare2-${VERSION}/ChangeLog" ;\
	${CZ} "radare2-${VERSION}.tar" ; \
	mv "radare2-${VERSION}" "$${DIR}"

shot:
	DATE=`date '+%Y%m%d'` ; \
	FILES=`git ls-files | sed -e "s,^,radare2-${DATE}/,"` ; \
	cd .. && mv radare2 "radare2-$${DATE}" && \
	${TAR} "radare2-$${DATE}.tar" $${FILES} ;\
	${CZ} "radare2-$${DATE}.tar" ;\
	mv "radare2-$${DATE}" radare2 && \
	scp "radare2-$${DATE}.${TAREXT}" \
		radare.org:/srv/http/radareorg/get/shot

tests:
	@if [ -d $(R2R) ]; then \
		cd $(R2R) ; git clean -xdf ; git pull ; \
	else \
		git clone --depth 1 "${R2R_URL}" "$(R2R)"; \
	fi
	cd $(R2R) ; ${MAKE}

osx-sign:
	$(MAKE) -C binr/radare2 osx-sign
osx-sign-libs:
	$(MAKE) -C binr/radare2 osx-sign-libs

quality:
	./sys/shellcheck.sh

include ${MKPLUGINS}

.PHONY: all clean distclean mrproper install symstall uninstall deinstall strip
.PHONY: libr binr install-man w32dist tests dist shot pkgcfg depgraph.png love
