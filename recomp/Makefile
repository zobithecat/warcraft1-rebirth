# Native arm64 build of the lifted code and the intro-frame viewer.
#
#   make            build/blitview (+ the lifted C it links)
#   make frames     work/demo/intro.wcf from captures in work/frames
#   make check      decode every frame natively and verify against DOSBox-X
#   make run        open the viewer window
#
# Python runs only at build time (to generate C from war.exe and to pack
# captured frames); build/blitview itself is a plain arm64 executable.

PYTHON  ?= python3
CC      ?= clang
# Where DOS/4GW loads war.exe's objects; tools/capture.py prints these.
BASES   ?= 1=0x1CB000,2=0x1FD000
CFLAGS  ?= -O2 -arch arm64 -Wall -Wextra -Wno-unused-parameter
SDL_CFLAGS := $(shell sdl2-config --cflags)
SDL_LIBS   := $(shell sdl2-config --libs)

WAREXE  := work/exe/war.exe
LIFTED  := build/lifted_rt.c
FRAMES  := work/demo/intro.wcf

.PHONY: all frames check run clean

all: build/blitview

$(LIFTED): $(WAREXE) tools/lift.py tools/disasm.py tools/le.py
	@mkdir -p build
	$(PYTHON) tools/lift.py $@ --all-leaf --bases $(BASES)

build/blitview: viewer/blitview.c runtime/entry.c runtime/x86.h $(LIFTED)
	$(CC) $(CFLAGS) -Iruntime $(SDL_CFLAGS) viewer/blitview.c runtime/entry.c $(LIFTED) $(SDL_LIBS) -o $@

$(WAREXE):
	$(PYTHON) tools/extract.py

frames: $(FRAMES)

$(FRAMES): tools/pack_frames.py
	$(PYTHON) tools/pack_frames.py work/frames $@

check: build/blitview $(FRAMES)
	./build/blitview --check $(FRAMES)

run: build/blitview $(FRAMES)
	./build/blitview $(FRAMES)

clean:
	rm -f build/blitview $(LIFTED)
