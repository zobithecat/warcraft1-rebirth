# Worms (DOS, 1995) recompiled: same lifter and CPU core as ../recomp.
#   make            native build (build/worms)
#   make run        run it (C: = work/game, D: = work/cd)
# work/ comes from tools/extract.py (your own CD image).
PYTHON  ?= python3
CC      ?= clang
RECOMP  := ../recomp
CFLAGS  ?= -O2 -arch arm64 -Wall -Wextra -Wno-unused-parameter
GAME_CFLAGS ?= $(CFLAGS) -DX86_HAVE_MMIO $(GAME_DEFS)
SDL_CFLAGS := $(shell sdl2-config --cflags)
SDL_LIBS   := $(shell sdl2-config --libs)

EXE     := work/game/WRMS.EXE
# Object 2 (data + BSS, 2.1MB) would cover the VGA window at 0xA0000 at its
# preferred base 0x50000; DOS/4GW loads it above 1MB as well.
BASES   := 1=0x10000,2=0x110000
GAME_C  := build/game.c
IMAGE   := build/image.bin

.PHONY: all run clean

all: build/worms

$(GAME_C): $(EXE) Makefile tools/profile.py $(RECOMP)/tools/lift.py $(RECOMP)/tools/disasm.py $(RECOMP)/tools/le.py
	@mkdir -p build
	$(PYTHON) $(RECOMP)/tools/lift.py $@ --exe $(EXE) --profile tools/profile.py --bases $(BASES) --all

$(IMAGE): $(EXE) Makefile $(RECOMP)/tools/mkimage.py $(RECOMP)/tools/le.py
	@mkdir -p build
	$(PYTHON) $(RECOMP)/tools/mkimage.py $@ $(EXE) --bases $(BASES)

build/game.o: $(GAME_C) $(RECOMP)/runtime/x86.h
	$(CC) $(GAME_CFLAGS) -I$(RECOMP)/runtime -c $(GAME_C) -o $@

build/worms: runtime/host.c $(RECOMP)/runtime/x86.h build/game.o $(IMAGE)
	$(CC) $(GAME_CFLAGS) -I$(RECOMP)/runtime $(SDL_CFLAGS) runtime/host.c build/game.o $(SDL_LIBS) -o $@

run: build/worms
	build/worms work/game work/cd $(IMAGE)

clean:
	rm -f build/game.o build/worms
