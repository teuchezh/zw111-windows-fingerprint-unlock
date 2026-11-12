# Cross-build with mingw-w64 (Linux) or MSYS2/mingw on Windows:  make
# Output: build/ZwCredProv.dll, build/zwsetup.exe  (x64)
CXX      = x86_64-w64-mingw32-g++
WINDRES  = x86_64-w64-mingw32-windres
CXXFLAGS ?= -O2 -std=c++17 -municode -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0A00 -Wall -Wno-unknown-pragmas
LDFLAGS  ?= -static -static-libgcc -static-libstdc++
LIBS      = -lole32 -loleaut32 -luuid -lsecur32 -ladvapi32 -lcrypt32 -lbcrypt -lsetupapi -lshlwapi -lgdi32 -lshell32 -lcredui

COMMON   = common/serial.cpp common/config.cpp common/proto.cpp
CP_SRC   = credprov/Dll.cpp credprov/Provider.cpp credprov/Credential.cpp credprov/helpers.cpp

all: build/ZwCredProv.dll build/zwsetup.exe build/zwsetup-gui.exe

build:
	mkdir -p build

build/ZwCredProv.dll: $(CP_SRC) $(COMMON) credprov/ZwCredProv.def | build
	$(CXX) $(CXXFLAGS) -shared -o $@ $(CP_SRC) $(COMMON) credprov/ZwCredProv.def $(LDFLAGS) $(LIBS)

build/zwsetup.exe: setup/zwsetup.cpp $(COMMON) | build
	$(CXX) $(CXXFLAGS) -o $@ setup/zwsetup.cpp $(COMMON) $(LDFLAGS) $(LIBS)

build/zwsetup-gui.exe: gui/main.cpp gui/zwsetup-gui.rc gui/zwsetup-gui.manifest gui/resource.h $(COMMON) | build
	$(WINDRES) -c 65001 -I gui -o build/gui_res.o gui/zwsetup-gui.rc
	$(CXX) $(CXXFLAGS) -mwindows -o $@ gui/main.cpp $(COMMON) build/gui_res.o $(LDFLAGS) $(LIBS) -lcomctl32 -luser32
	rm -f build/gui_res.o

clean:
	rm -rf build
