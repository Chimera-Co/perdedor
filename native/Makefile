# Perdedor native agent.
#   make            -> linux + win64 + win32 (whatever toolchains are installed)
#   make linux | win64 | win32 | test
# Every .cpp under src/core, src/common and src/<platform> is compiled; new
# check files are picked up without editing this Makefile.

CXXSTD   := -std=c++17
WARN     := -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
OPT      := -O2
BUILD    := build

CORE     := $(wildcard src/core/*.cpp)
COMMON   := $(wildcard src/common/*.cpp)
LINUXSRC := $(wildcard src/linux/*.cpp)
WINSRC   := $(wildcard src/windows/*.cpp)

LINUX_CXX ?= g++
WIN64_CXX ?= x86_64-w64-mingw32-g++
WIN32_CXX ?= i686-w64-mingw32-g++

WINLIBS  := -lole32 -loleaut32 -lwbemuuid -luuid -liphlpapi -lws2_32 -ladvapi32 -lsetupapi -lpsapi \
            -lversion -lshlwapi -lpowrprof -lcfgmgr32 -luser32 -lgdi32 -ldnsapi -lwinhttp -lshell32 \
            -lwtsapi32 -lnetapi32 -lwintrust -lcrypt32 -lbcrypt -lntdll
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: test-linux all linux win64 win32 test clean
all: $(if $(shell command -v $(LINUX_CXX)),linux) $(if $(shell command -v $(WIN64_CXX)),win64) $(if $(shell command -v $(WIN32_CXX)),win32)

linux: $(BUILD)/perdedor-linux-x86_64
win64: $(BUILD)/perdedor-windows-x64.exe
win32: $(BUILD)/perdedor-windows-x86.exe

$(BUILD)/perdedor-linux-x86_64: $(CORE) $(COMMON) $(LINUXSRC) $(wildcard src/*/*.hpp)
	@mkdir -p $(BUILD)
	$(LINUX_CXX) $(CXXSTD) $(OPT) $(WARN) -DPERDEDOR_BUILD=\"$(VERSION)\" -static -pthread -o $@ $(CORE) $(COMMON) $(LINUXSRC)

$(BUILD)/perdedor-windows-x64.exe: $(CORE) $(COMMON) $(WINSRC) $(wildcard src/*/*.hpp)
	@mkdir -p $(BUILD)
	$(WIN64_CXX) $(CXXSTD) $(OPT) $(WARN) -DPERDEDOR_BUILD=\"$(VERSION)\" -D_WIN32_WINNT=0x0601 -DUNICODE -D_UNICODE \
	  -static -static-libgcc -static-libstdc++ -o $@ $(CORE) $(COMMON) $(WINSRC) $(WINLIBS)

$(BUILD)/perdedor-windows-x86.exe: $(CORE) $(COMMON) $(WINSRC) $(wildcard src/*/*.hpp)
	@mkdir -p $(BUILD)
	$(WIN32_CXX) $(CXXSTD) $(OPT) $(WARN) -DPERDEDOR_BUILD=\"$(VERSION)\" -D_WIN32_WINNT=0x0601 -DUNICODE -D_UNICODE \
	  -static -static-libgcc -static-libstdc++ -o $@ $(CORE) $(COMMON) $(WINSRC) $(WINLIBS)

# Host unit tests for the platform-independent core (selection, glob, JSON, summary).
$(BUILD)/core_tests: $(CORE) tests/core_tests.cpp tests/fake_platform.cpp
	@mkdir -p $(BUILD)
	$(LINUX_CXX) $(CXXSTD) -O0 -g $(WARN) -pthread -o $@ $(filter-out src/core/main.cpp,$(CORE)) tests/core_tests.cpp tests/fake_platform.cpp

test: $(BUILD)/core_tests linux test-linux
	./$(BUILD)/core_tests
	./$(BUILD)/perdedor-linux-x86_64 --list-checks > /dev/null

# Linux agent against fixture root trees (tests/fixtures/linux/*.json).
test-linux: linux
	python3 tests/linux_fixtures.py ./$(BUILD)/perdedor-linux-x86_64

clean:
	$(RM) -r $(BUILD)
