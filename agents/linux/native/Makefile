CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
TARGET  := cpuid_rdtsc

.PHONY: all clean
all: $(TARGET)

$(TARGET): cpuid_rdtsc.c
	$(CC) $(CFLAGS) -o $(TARGET) cpuid_rdtsc.c

clean:
	rm -f $(TARGET)
