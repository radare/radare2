@ECHO OFF
IF EXIST shlr\capstone GOTO START
ECHO [ R2 MESON CLONING CAPSTONE ]
git clone -b next --depth 10 http://github.com/aquynh/capstone.git shlr\capstone
:START
IF "%1"=="-p" GOTO BUILDPROJECT
IF "%1"=="-r" GOTO REBUILD
IF EXIST build GOTO BUILD
python meson.py --prefix=%CD% build
:BUILD
ECHO [ R2 MESON NINJA BUILD ]
copy shlr\spp\config.def.h shlr\spp\config.h
ninja -C build
GOTO EXIT
:BUILDPROJECT
ECHO [ R2 MESON BUILDING VS2015 SLN]
IF EXIST build rd /s /q build
python meson.py --prefix=%CD% build --backend=vs2015
GOTO EXIT
:REBUILD
python.exe meson.py --internal regenerate %CD% "%CD%\build" --backend ninja
:EXIT