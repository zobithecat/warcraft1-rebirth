# Native arm64 build of the lifted code and the intro-frame viewer.
#
#   make play       build and run the game (build/war)
#   make            build/war and build/blitview
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

.PHONY: all frames check run clean war play

all: build/blitview build/war

# ---- the game: whole program lifted to C + native DOS/DPMI/VGA runtime ----
GAME_C  := build/game.c
IMAGE   := build/image.bin
GAME_CFLAGS ?= -O2 -arch arm64 -Wall -Wextra -Wno-unused-parameter $(GAME_DEFS)

$(GAME_C): $(WAREXE) tools/lift.py tools/disasm.py tools/le.py
	@mkdir -p build
	$(PYTHON) tools/lift.py $@ --all

build/game.o: $(GAME_C) runtime/x86.h
	$(CC) $(GAME_CFLAGS) -Iruntime -c $(GAME_C) -o $@

$(IMAGE): $(WAREXE) tools/mkimage.py tools/le.py
	$(PYTHON) tools/mkimage.py $@

build/war: runtime/game.c runtime/x86.h build/game.o $(IMAGE)
	$(CC) $(GAME_CFLAGS) -Iruntime $(SDL_CFLAGS) runtime/game.c build/game.o $(SDL_LIBS) -o $@

war: build/war

work/game/WAR.EXE: $(WAREXE)
	cd tools && $(PYTHON) -c "import capture; capture.prepare()"

play: build/war work/game/WAR.EXE
	./build/war work/game $(IMAGE)

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
	rm -f build/blitview $(LIFTED) build/war build/game.o $(GAME_C) $(IMAGE)
