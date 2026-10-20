# Native arm64 build of the lifted code and the intro-frame viewer.
#
#   make play       build and run the game (build/war)
#   make wasm       browser build in build/web (Emscripten); make serve to play it
#   make deploy     upload build/web to S3 + CloudFront behind a password (AWS CLI)
#   make hooks      deploy automatically on every push of master (git pre-push hook)
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

.PHONY: all frames check run clean war play wasm serve wasm-test deploy hooks

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

RUNTIME := runtime/game.c runtime/sound.c
RUNTIME_H := runtime/x86.h runtime/sound.h

build/war: $(RUNTIME) $(RUNTIME_H) build/game.o $(IMAGE)
	$(CC) $(GAME_CFLAGS) -Iruntime $(SDL_CFLAGS) $(RUNTIME) build/game.o $(SDL_LIBS) -o $@

war: build/war

# Offline sound checks against DOSBox-X (tools/soundtest.c, tools/soundcmp.py)
build/soundtest: tools/soundtest.c runtime/sound.c runtime/sound.h
	$(CC) -O2 -Wall -Iruntime -DSOUND_TRACE tools/soundtest.c runtime/sound.c -o $@

work/game/WAR.EXE: $(WAREXE)
	cd tools && $(PYTHON) -c "import capture; capture.prepare()"

play: build/war work/game/WAR.EXE
	./build/war work/game $(IMAGE)

# ---- the same game for the browser: Emscripten, game loop in a Web Worker ----
# build/web/war.data packs the local game folder; it is build output, never published.
EMCC       ?= emcc
WEB_CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
WEB_LDFLAGS := -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=96MB -sSTACK_SIZE=8MB -sEXIT_RUNTIME=1 \
               --pre-js web/env.js
WEB_FILES  := build/web/index.html build/web/worker.js build/web/audio.js

build/web/game.o: $(GAME_C) runtime/x86.h
	@mkdir -p build/web
	$(EMCC) $(WEB_CFLAGS) -Iruntime -c $(GAME_C) -o $@

build/web/war.js: $(RUNTIME) $(RUNTIME_H) web/env.js build/web/game.o $(IMAGE) work/game/WAR.EXE
	$(EMCC) $(WEB_CFLAGS) -Iruntime $(RUNTIME) build/web/game.o $(WEB_LDFLAGS) -sENVIRONMENT=worker \
	  --preload-file work/game@/game --preload-file $(IMAGE)@/image.bin -o $@

build/web/%: web/%
	@mkdir -p build/web
	cp $< $@

wasm: build/web/war.js $(WEB_FILES)

serve: wasm
	$(PYTHON) tools/serve.py build/web

deploy: wasm
	$(PYTHON) tools/deploy_aws.py

hooks:
	git config core.hooksPath recomp/tools/git-hooks

# The same wasm under Node with the real file system: headless runs with
# WAR_INPUT/WAR_SNAPSHOT, like build/war.  make wasm-test boots into the first
# mission and moves a grunt (select, Move button, destination).
build/web/war-node.js: $(RUNTIME) $(RUNTIME_H) web/env.js build/web/game.o
	$(EMCC) $(WEB_CFLAGS) -Iruntime $(RUNTIME) build/web/game.o $(WEB_LDFLAGS) -sENVIRONMENT=node -sNODERAWFS=1 -o $@

BOOT_INPUT := 6:esc,8:return,10:return,12:return,15:click@160,100,18:space,21:return,25:click@130,130,27.5:click@18,127,29.5:click@200,150,33:snap

wasm-test: build/web/war-node.js $(IMAGE) work/game/WAR.EXE
	WAR_INPUT="$(BOOT_INPUT)" WAR_SNAPSHOT=34 node build/web/war-node.js work/game $(IMAGE)

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
	rm -rf build/web build/web-deploy
