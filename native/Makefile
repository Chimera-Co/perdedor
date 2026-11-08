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

.PHONY: all linux win64 win32 test clean
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

test: $(BUILD)/core_tests linux test-lowlevel
	./$(BUILD)/core_tests
	./$(BUILD)/perdedor-linux-x86_64 --list-checks > /dev/null

# Low-level fixtures use the real guard and statistics, with no privileged setup.
LOWLEVEL_TEST_SRC := tests/lowlevel_tests.cpp src/common/guard.cpp src/common/lowlevel.cpp \
                     $(filter-out src/core/main.cpp,$(CORE)) tests/fake_platform.cpp
LOWLEVEL_TEST_HEADERS := $(wildcard src/common/*.hpp) src/linux/lowlevel_parsers.hpp

$(BUILD)/lowlevel_tests: $(LOWLEVEL_TEST_SRC) $(LOWLEVEL_TEST_HEADERS)
	@mkdir -p $(BUILD)
	$(LINUX_CXX) $(CXXSTD) $(OPT) $(WARN) -Werror -pthread -o $@ $(LOWLEVEL_TEST_SRC)

$(BUILD)/lowlevel-tests-win64.exe: $(LOWLEVEL_TEST_SRC) $(LOWLEVEL_TEST_HEADERS)
	@mkdir -p $(BUILD)
	$(WIN64_CXX) $(CXXSTD) $(OPT) $(WARN) -Werror -D_WIN32_WINNT=0x0601 -static -o $@ $(LOWLEVEL_TEST_SRC)

$(BUILD)/lowlevel-tests-win32.exe: $(LOWLEVEL_TEST_SRC) $(LOWLEVEL_TEST_HEADERS)
	@mkdir -p $(BUILD)
	$(WIN32_CXX) $(CXXSTD) $(OPT) $(WARN) -Werror -D_WIN32_WINNT=0x0601 -static -o $@ $(LOWLEVEL_TEST_SRC)

.PHONY: test-lowlevel
test-lowlevel: $(BUILD)/lowlevel_tests linux
	./$(BUILD)/lowlevel_tests
	python3 tests/lowlevel_smoke.py ./$(BUILD)/perdedor-linux-x86_64

clean:
	$(RM) -r $(BUILD)
