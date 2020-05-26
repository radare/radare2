BIN=radare2
BINDEPS=r_core r_parse r_search r_cons r_config
BINDEPS+=r_bin r_debug r_anal r_reg r_bp r_io r_fs
BINDEPS+=r_lang r_asm r_syscall r_hash r_main r_arch
BINDEPS+=r_magic r_socket r_flag r_egg r_crypto r_util

include ../../config-user.mk

# Apple Sign #
CERTID?=org.radare.radare2
BUNDLE=org.radare.radare2
MACSDK=macosx10.10
ENTITL=radare2.xcent
#ENTITL=radare2_ios.xml
#CFLAGS+=-flto
#LDFLAGS+=-flto

ifeq (${COMPILER},emscripten)
# https://kripken.github.io/emscripten-site/docs/optimizing/Optimizing-Code.html
# -s INLINING_LIMIT=1
# --memory-init-file 0
CFLAGS+=-s EXPORTED_FUNCTIONS='["_r_core_new", "_r_core_free", "_r_cmd_str"]'
CFLAGS+=-s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap", "addOnInit"]'
CFLAGS+=-s TOTAL_MEMORY=33554432
CFLAGS+=-s ALLOW_MEMORY_GROWTH=1
CFLAGS+=-s ABORTING_MALLOC=0
#CFLAGS+=-Oz --memory-init-file 0
endif

FOOD_LIBS=$(addprefix ../../libr/,$(subst r_,,$(BINDEPS)))
SIGN_LIBS=$(addsuffix /libr_*.dylib,$(FOOD_LIBS))

include ../rules.mk
#IOS_CERTID?=org.radare.radare2

ios:
	$(MAKE) -C ../../libr/io
	$(MAKE) -C ../../libr/debug
	rm -f radare2
	$(MAKE)
	$(MAKE) ios-sign

ifeq ($(shell uname),Darwin)
sign: macos-sign
else
sign: ios-sign
endif

ios-sign iossign:
	xcrun --sdk iphoneos codesign \
		-s- --entitlements radare2_ios.xml radare2
	# -f -s "$$IOS_CERTID" --entitlements radare2_ios.xml radare2
	#ldid -Sradare2_ios.xml radare2

ios_sdk_sign:
	-codesign -s- --entitlements radare2_ios.xml radare2

macos-sign macossign:
	rm -f radare2
	${CC} radare2.c ${CFLAGS} ${LDFLAGS} ${LINK} -o radare2 \
		-sectcreate __TEXT __info_plist Info.plist \
		-framework Security -framework CoreFoundation
	#xcrun --sdk $(MACSDK) codesign -f -s ${CERTID} --entitlements radare2_macos.xml radare2
	codesign -dvvv --deep -f -s ${CERTID} -i ${BUNDLE} --entitlements radare2_macos.xml radare2
	#sudo chown root:_developer radare2
#	sudo chown root:procmod radare2
	#sudo chmod g+s radare2
#	sudo chmod 4755 radare2

macos-sign-libs:
	for LIB in ${SIGN_LIBS} ; do \
		echo Signing $$LIB ; \
		codesign -f -s ${CERTID} $$LIB ; \
	done
#	xcrun --sdk $(MACSDK) codesign -f -s ${CERTID} --entitlements $(ENTITL) radare2
#	xcrun --sdk $(MACSDK) codesign -f -s ${CERTID} radare2
#	codesign -dvvv -s $(XNUCERT) ./radare2
#	sudo chown root:procmod radare2
#	sudo chmod g+s radare2

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
LDFLAGS+=../../shlr/capstone/libcapstone.a
endif

include ../../libr/socket/deps.mk
include ../../libr/magic/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/grub/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/yxml/deps.mk
LDFLAGS+=$(LINK)
