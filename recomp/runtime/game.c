/* Native host for the recompiled war.exe.
 *
 * Plays the part of DOS + DOS/4GW + the PC hardware for the lifted code:
 * loads the relocated image, builds a PSP/environment, answers the INT 21h
 * (DOS), INT 31h (DPMI), INT 10h (video) and INT 33h (mouse) calls the game
 * makes, emulates the few I/O ports it touches (VGA DAC, retrace, keyboard),
 * shows mode 13h through SDL2 and feeds keyboard/mouse events to the game's
 * own interrupt handlers.
 *
 *   war [GAME_DIR [IMAGE]]      defaults: work/game build/image.bin
 *   WAR_TRACE=1 war ...         log every interrupt
 *
 * Built with Emscripten (make wasm) the same code runs in a browser Web
 * Worker: the game loop never yields, so frames go out by postMessage and
 * input comes back through a SharedArrayBuffer ring (web/worker.js).
 */
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#else
#include <SDL.h>
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "x86.h"

typedef struct { uint32_t addr; void (*fn)(Cpu *); } LiftedEntry;
extern const LiftedEntry lifted_table[];
extern const unsigned lifted_table_len;

/* ---- guest layout --------------------------------------------------------- */
#define MEM_SIZE      (64u << 20)
#define ENV_BASE      0x00000u     /* environment at linear 0: see LIFTER.md (implicit DS) */
#define PSP_BASE      0x01000u
#define DOS_POOL      0x02000u     /* DPMI 0100h "conventional" allocations */
#define DOS_POOL_END  0x9F000u
#define VGA_BASE      0xA0000u
#define HEAP_BASE     0x00400000u  /* INT 21h 48h allocations */
#define CALLBACK_RET  0xFFFFFFF0u  /* return address used when the host calls guest code */

#define SEL_CODE 0x0008
#define SEL_DATA 0x0010
#define SEL_PSP  0x0018
#define SEL_ENV  0x0020
#define SEL_BIOS 0x0040
#define SEL_FIRST_FREE 0x0080
#define MAX_SEL  1024

#define SCALE 3

typedef struct {
    uint32_t base[MAX_SEL];
    uint8_t used[MAX_SEL];
} Ldt;

typedef struct {
    FILE *fp;
} Handle;

typedef struct {
    const char *game_dir;
    Ldt ldt;
    uint32_t pm_vector[256];      /* handlers the game installed */
    uint32_t heap_top, dos_top;
    Handle files[64];
    /* video */
    int mode;
    uint8_t dac[768];
    int dac_w, dac_wc, dac_r, dac_rc;
    uint32_t retrace;
    int video_on;
#ifndef __EMSCRIPTEN__
    SDL_Window *win;
    SDL_Renderer *ren;
    SDL_Texture *tex;
#endif
    uint64_t last_present;
    /* input */
    uint8_t keys[64];
    int key_head, key_tail;
    uint8_t last_scan;
    uint32_t mouse_handler, mouse_mask;
    int mouse_x, mouse_y, mouse_buttons;
    int mx_min, mx_max, my_min, my_max;
    int in_callback;
    int trace;
    int drive;                    /* current drive, 0 = A: (C: = game folder, D: = "CD") */
    uint64_t start_ns;
    uint64_t snapshot_ms;
} Host;

static Host H;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static uint64_t now_ms(void) { return (now_ns() - H.start_ns) / 1000000ull; }

static void die(Cpu *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "war: ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n  eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x\n",
            c->r[EAX], c->r[ECX], c->r[EDX], c->r[EBX], c->r[ESP], c->r[EBP], c->r[ESI], c->r[EDI]);
    x86_stop(c, STOP_TRAP, 0);
}

/* ---- registers --------------------------------------------------------------- */
#define AL(c) ((c)->r[EAX] & 0xFF)
#define AH(c) (((c)->r[EAX] >> 8) & 0xFF)
#define AX(c) ((c)->r[EAX] & 0xFFFF)
#define BL(c) ((c)->r[EBX] & 0xFF)
#define BX(c) ((c)->r[EBX] & 0xFFFF)
#define CX(c) ((c)->r[ECX] & 0xFFFF)
#define DX(c) ((c)->r[EDX] & 0xFFFF)
#define SI(c) ((c)->r[ESI] & 0xFFFF)
#define DI(c) ((c)->r[EDI] & 0xFFFF)
static void set16(Cpu *c, int r, uint32_t v) { c->r[r] = (c->r[r] & 0xFFFF0000u) | (v & 0xFFFF); }
static void set_al(Cpu *c, uint32_t v) { c->r[EAX] = (c->r[EAX] & ~0xFFu) | (v & 0xFF); }
static void set_ah(Cpu *c, uint32_t v) { c->r[EAX] = (c->r[EAX] & ~0xFF00u) | ((v & 0xFF) << 8); }
static void ok(Cpu *c) { c->f.cf = 0; }
static void fail(Cpu *c, uint32_t code) { c->f.cf = 1; set16(c, EAX, code); }

static uint8_t *G(Cpu *c, uint32_t a) { return c->mem + a; }

/* ---- selectors ------------------------------------------------------------- */
static uint32_t sel_base(Cpu *c, uint16_t sel) {
    (void)c;
    uint32_t i = sel >> 3;
    return i < MAX_SEL ? H.ldt.base[i] : 0;
}
static uint16_t sel_alloc(uint32_t base) {
    for (uint32_t i = SEL_FIRST_FREE >> 3; i < MAX_SEL; i++)
        if (!H.ldt.used[i]) { H.ldt.used[i] = 1; H.ldt.base[i] = base; return (uint16_t)(i << 3 | 7); }
    return 0;
}
static void sel_fixed(uint16_t sel, uint32_t base) { H.ldt.used[sel >> 3] = 1; H.ldt.base[sel >> 3] = base; }

/* ---- calling guest code from the host ---------------------------------------- */
static void dispatch(Cpu *c, uint32_t target, uint32_t at);

/* Run a guest handler like the hardware/DPMI host would: iret frame or far call. */
static void call_guest(Cpu *c, uint32_t handler, int iret_frame) {
    uint32_t save[8];
    memcpy(save, c->r, sizeof save);
    Flags save_f = c->f;
    uint32_t esp = c->r[ESP];
    if (iret_frame) { esp -= 4; wr32(c, esp, x86_pack_flags(&c->f)); }
    esp -= 4; wr32(c, esp, SEL_CODE);
    esp -= 4; wr32(c, esp, CALLBACK_RET);
    c->r[ESP] = esp;
    H.in_callback++;
    dispatch(c, handler, 0);
    H.in_callback--;
    memcpy(c->r, save, sizeof save);
    c->f = save_f;
}

/* ---- video ------------------------------------------------------------------- */
#ifdef __EMSCRIPTEN__
/* worker.js: send a 320x200 RGBA frame to the page */
EM_JS(void, web_present, (const uint32_t *px), {
    if (typeof postMessage !== "function") return;
    const f = HEAPU8.slice(px, px + 320 * 200 * 4);
    postMessage({ frame: f.buffer }, [f.buffer]);
});
/* worker.js: next input event from the page's ring, as {type, a, b, c} */
EM_JS(int, web_poll, (int32_t *ev), {
    const r = globalThis.warRing;
    if (!r) return 0;
    const tail = Atomics.load(r, 1);
    if (Atomics.load(r, 0) === tail) return 0;
    const at = 2 + (tail & 255) * 4;
    for (let i = 0; i < 4; i++) HEAP32[(ev >> 2) + i] = r[at + i];
    Atomics.store(r, 1, tail + 1);
    return 1;
});
#define PIXEL(r, g, b) (0xFF000000u | (uint32_t)(b) << 16 | (uint32_t)(g) << 8 | (uint32_t)(r))   /* RGBA bytes */

static void video_init(void) { H.video_on = 1; }
#else
#define PIXEL(r, g, b) (0xFF000000u | (uint32_t)(r) << 16 | (uint32_t)(g) << 8 | (uint32_t)(b))   /* ARGB8888 */

static void video_init(void) {
    if (H.video_on) return;
    H.video_on = 1;
    if (SDL_Init(SDL_INIT_VIDEO) != 0) { fprintf(stderr, "SDL_Init: %s\n", SDL_GetError()); exit(1); }
    H.win = SDL_CreateWindow("WarCraft (native arm64)", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                             320 * SCALE, 200 * SCALE, SDL_WINDOW_ALLOW_HIGHDPI);
    H.ren = SDL_CreateRenderer(H.win, -1, SDL_RENDERER_ACCELERATED);
    H.tex = SDL_CreateTexture(H.ren, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, 320, 200);
    SDL_ShowCursor(SDL_DISABLE);
}
#endif

/* Rubber-band selection in progress (see "modern controls" below): drawn over the frame. */
static struct { int active, x0, y0, x1, y1; } drag;      /* 320x200 screen coordinates */
#define DRAG_MIN 4                                         /* smaller boxes are clicks */

static void draw_drag_box(uint32_t *px) {
    int x0 = drag.x0 < drag.x1 ? drag.x0 : drag.x1, x1 = drag.x0 < drag.x1 ? drag.x1 : drag.x0;
    int y0 = drag.y0 < drag.y1 ? drag.y0 : drag.y1, y1 = drag.y0 < drag.y1 ? drag.y1 : drag.y0;
    if (!drag.active || (x1 - x0 < DRAG_MIN && y1 - y0 < DRAG_MIN)) return;
    uint32_t green = PIXEL(0, 255, 0);
    for (int x = x0; x <= x1; x++) px[y0 * 320 + x] = px[y1 * 320 + x] = green;
    for (int y = y0; y <= y1; y++) px[y * 320 + x0] = px[y * 320 + x1] = green;
}

static void present(Cpu *c) {
    if (!H.video_on) return;
    static uint32_t px[320 * 200];
    uint32_t lut[256];
    for (int i = 0; i < 256; i++) {
        const uint8_t *d = H.dac + i * 3;
        lut[i] = PIXEL(d[0] * 255 / 63, d[1] * 255 / 63, d[2] * 255 / 63);
    }
    const uint8_t *vram = G(c, VGA_BASE);
    for (int i = 0; i < 320 * 200; i++) px[i] = lut[vram[i]];
    draw_drag_box(px);
#ifdef __EMSCRIPTEN__
    web_present(px);
#else
    SDL_UpdateTexture(H.tex, NULL, px, 320 * 4);
    SDL_RenderClear(H.ren);
    SDL_RenderCopy(H.ren, H.tex, NULL, NULL);
    SDL_RenderPresent(H.ren);
#endif
}

/* ---- input -------------------------------------------------------------------- */
#ifndef __EMSCRIPTEN__
static uint8_t pc_scancode(SDL_Scancode s) {
    switch (s) {
    case SDL_SCANCODE_ESCAPE: return 0x01;
    case SDL_SCANCODE_1: return 0x02; case SDL_SCANCODE_2: return 0x03; case SDL_SCANCODE_3: return 0x04;
    case SDL_SCANCODE_4: return 0x05; case SDL_SCANCODE_5: return 0x06; case SDL_SCANCODE_6: return 0x07;
    case SDL_SCANCODE_7: return 0x08; case SDL_SCANCODE_8: return 0x09; case SDL_SCANCODE_9: return 0x0A;
    case SDL_SCANCODE_0: return 0x0B; case SDL_SCANCODE_MINUS: return 0x0C; case SDL_SCANCODE_EQUALS: return 0x0D;
    case SDL_SCANCODE_BACKSPACE: return 0x0E; case SDL_SCANCODE_TAB: return 0x0F;
    case SDL_SCANCODE_Q: return 0x10; case SDL_SCANCODE_W: return 0x11; case SDL_SCANCODE_E: return 0x12;
    case SDL_SCANCODE_R: return 0x13; case SDL_SCANCODE_T: return 0x14; case SDL_SCANCODE_Y: return 0x15;
    case SDL_SCANCODE_U: return 0x16; case SDL_SCANCODE_I: return 0x17; case SDL_SCANCODE_O: return 0x18;
    case SDL_SCANCODE_P: return 0x19; case SDL_SCANCODE_LEFTBRACKET: return 0x1A; case SDL_SCANCODE_RIGHTBRACKET: return 0x1B;
    case SDL_SCANCODE_RETURN: return 0x1C; case SDL_SCANCODE_LCTRL: case SDL_SCANCODE_RCTRL: return 0x1D;
    case SDL_SCANCODE_A: return 0x1E; case SDL_SCANCODE_S: return 0x1F; case SDL_SCANCODE_D: return 0x20;
    case SDL_SCANCODE_F: return 0x21; case SDL_SCANCODE_G: return 0x22; case SDL_SCANCODE_H: return 0x23;
    case SDL_SCANCODE_J: return 0x24; case SDL_SCANCODE_K: return 0x25; case SDL_SCANCODE_L: return 0x26;
    case SDL_SCANCODE_SEMICOLON: return 0x27; case SDL_SCANCODE_APOSTROPHE: return 0x28; case SDL_SCANCODE_GRAVE: return 0x29;
    case SDL_SCANCODE_LSHIFT: return 0x2A; case SDL_SCANCODE_BACKSLASH: return 0x2B;
    case SDL_SCANCODE_Z: return 0x2C; case SDL_SCANCODE_X: return 0x2D; case SDL_SCANCODE_C: return 0x2E;
    case SDL_SCANCODE_V: return 0x2F; case SDL_SCANCODE_B: return 0x30; case SDL_SCANCODE_N: return 0x31;
    case SDL_SCANCODE_M: return 0x32; case SDL_SCANCODE_COMMA: return 0x33; case SDL_SCANCODE_PERIOD: return 0x34;
    case SDL_SCANCODE_SLASH: return 0x35; case SDL_SCANCODE_RSHIFT: return 0x36;
    case SDL_SCANCODE_LALT: case SDL_SCANCODE_RALT: return 0x38; case SDL_SCANCODE_SPACE: return 0x39;
    case SDL_SCANCODE_F1: return 0x3B; case SDL_SCANCODE_F2: return 0x3C; case SDL_SCANCODE_F3: return 0x3D;
    case SDL_SCANCODE_F4: return 0x3E; case SDL_SCANCODE_F5: return 0x3F; case SDL_SCANCODE_F6: return 0x40;
    case SDL_SCANCODE_F7: return 0x41; case SDL_SCANCODE_F8: return 0x42; case SDL_SCANCODE_F9: return 0x43;
    case SDL_SCANCODE_F10: return 0x44;
    case SDL_SCANCODE_UP: return 0x48; case SDL_SCANCODE_LEFT: return 0x4B;
    case SDL_SCANCODE_RIGHT: return 0x4D; case SDL_SCANCODE_DOWN: return 0x50;
    case SDL_SCANCODE_PAGEUP: return 0x49; case SDL_SCANCODE_PAGEDOWN: return 0x51;
    case SDL_SCANCODE_HOME: return 0x47; case SDL_SCANCODE_END: return 0x4F;
    case SDL_SCANCODE_INSERT: return 0x52; case SDL_SCANCODE_DELETE: return 0x53;
    default: return 0;
    }
}
#endif

static void key_event(Cpu *c, uint8_t scan) {
    H.last_scan = scan;
    if (H.pm_vector[9]) call_guest(c, H.pm_vector[9], 1);      /* the game's own keyboard ISR */
}

static void mouse_event(Cpu *c, uint32_t mask) {
    if (!H.mouse_handler || !(H.mouse_mask & mask) || H.in_callback) return;
    uint32_t save[8];
    memcpy(save, c->r, sizeof save);
    c->r[EAX] = mask;
    c->r[EBX] = (uint32_t)H.mouse_buttons;
    c->r[ECX] = (uint32_t)H.mouse_x;
    c->r[EDX] = (uint32_t)H.mouse_y;
    c->r[ESI] = c->r[EDI] = 0;
    call_guest(c, H.mouse_handler, 0);
    memcpy(c->r, save, sizeof save);
}

/* ---- modern controls -------------------------------------------------------------
 * WarCraft (1994) has neither drag-box selection nor right-click orders: the
 * right button recenters the map, and an order is a command button followed
 * by a click on the target.  These add both through the game's own code:
 *   right click with own units selected: attack an enemy, harvest a gold mine
 *     or forest (peons), otherwise move.  Calls the game's order function
 *     0x2E384 exactly as a target click after a command button does.
 *   left drag over the map: select own units in the box (up to 4; shift adds
 *     to the selection) with the game's set-selection function 0x25C50, which
 *     a click and shift-clicks end in (0x2E2B0).
 * Both run inside the game's input handlers (lift.py WRAP), not in the mouse
 * interrupt, so they change game state where the game itself does.  The
 * addresses come from memory dumps (WAR_INPUT "dump") and the code using them. */
#define MAP_X0 72                 /* map viewport on screen: 15 x 11 tiles of 16 pixels */
#define MAP_Y0 12
#define MAP_X1 311
#define MAP_Y1 187
#define G_VIEW_X      0x500D0u    /* u16 top-left tile of the viewport */
#define G_VIEW_Y      0x500D2u
#define G_ALLIANCE    0x5008Cu    /* u8 per player: 1 = enemy of the human player */
#define G_TILE_FLAGS  0x5828Cu    /* -> u16[64][64] */
#define G_CURSOR_X    0x59138u    /* u16 screen position the game acts on */
#define G_CURSOR_Y    0x5913Au
#define G_FRAME_HOOK  0x59134u    /* per-frame input handler; 0x1A0F0 while playing a map */
#define G_SELECTION   0x59E00u    /* unit *[4] */
#define G_GROUPABLE   0x51C04u    /* u16 per unit type: may be selected together with others */
#define G_UNITS       0x5A1A0u    /* unit *[], 0-terminated: units in play */
#define G_HOVER       0x5A4CCu    /* unit under the cursor */
#define G_COMMAND     0x5A4D4u    /* u16 order for the next target: 3 move, 4 attack, 10 harvest */
#define G_LSHIFT      0x61848u    /* u16 key down; key table at 0x617F4 by scancode */
#define G_RSHIFT      0x61860u
#define U_X           0x00        /* unit: u16 pixel position of the 16x16 sprite */
#define U_Y           0x02
#define U_TYPE        0x1B        /* u8: 2/3 peasant/peon, 0x20.. buildings, 0x32 gold mine */
#define U_OWNER       0x1E        /* u8: 0 = the human player */
#define TILE_FOREST   0x80
#define CMD_MOVE      3
#define CMD_ATTACK    4
#define CMD_HARVEST   10

static struct { int pending, mx0, my0, sx1, sy1; } box;   /* a finished drag, for the next left-up */
/* A selection sent by box_select that the game has not applied yet (it goes
 * through the game's command queue, ahead of any order given right after). */
static struct { uint32_t unit[4]; int n; uint64_t ms; } sent;

static int in_map(int x, int y) { return x >= MAP_X0 && x <= MAP_X1 && y >= MAP_Y0 && y <= MAP_Y1; }
static int clampi(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }
static int is_worker(uint32_t type) { return type == 2 || type == 3; }

/* Call a lifted function from a hook: Watcom register arguments, our registers kept. */
static void call_near(Cpu *c, uint32_t func, uint32_t eax, uint32_t edx, uint32_t ebx) {
    uint32_t save[8];
    memcpy(save, c->r, sizeof save);
    Flags save_f = c->f;
    c->r[ESP] -= 4;
    wr32(c, c->r[ESP], CALLBACK_RET);
    c->r[EAX] = eax;
    c->r[EDX] = edx;
    c->r[EBX] = ebx;
    dispatch(c, func, 0);
    memcpy(c->r, save, sizeof save);
    c->f = save_f;
}

/* The selection an order given now applies to. */
static int current_selection(Cpu *c, uint32_t out[4]) {
    int n = 0, same = 1;
    for (int i = 0; i < 4; i++) {
        uint32_t u = rd32(c, G_SELECTION + 4 * i);
        if (u) out[n++] = u;
    }
    for (int i = 0; i < sent.n; i++) same &= i < n && out[i] == sent.unit[i];
    if (sent.n && (same || now_ms() > sent.ms + 1000)) sent.n = 0;     /* applied (or lost) */
    if (!sent.n) return n;
    memcpy(out, sent.unit, sizeof sent.unit);
    return sent.n;
}

/* Right click on the map (0x1B468).  Returns 0 to keep the original recentering. */
static int right_click_order(Cpu *c) {
    int workers = 0, others = 0;
    uint32_t sel[4];
    int n = current_selection(c, sel);
    for (int i = 0; i < n; i++) {
        uint32_t u = sel[i];
        uint32_t type = rd8(c, u + U_TYPE);
        if (rd8(c, u + U_OWNER) != 0 || type >= 0x20) return 0;    /* enemy or building selected */
        if (is_worker(type)) workers++; else others++;
    }
    if (!workers && !others) return 0;
    int tx = ((int)rd16(c, G_CURSOR_X) - MAP_X0) / 16 + (int)rd16(c, G_VIEW_X);
    int ty = ((int)rd16(c, G_CURSOR_Y) - MAP_Y0) / 16 + (int)rd16(c, G_VIEW_Y);
    if (tx < 0 || tx > 63 || ty < 0 || ty > 63) return 0;
    uint32_t target = rd32(c, G_HOVER), cmd = CMD_MOVE;
    if (target) {
        if (others && rd8(c, G_ALLIANCE + rd8(c, target + U_OWNER)) == 1) cmd = CMD_ATTACK;
        else if (workers && rd8(c, target + U_TYPE) == 0x32) cmd = CMD_HARVEST;
    } else if (workers && rd16(c, rd32(c, G_TILE_FLAGS) + 2u * (uint32_t)(ty * 64 + tx)) & TILE_FOREST) {
        cmd = CMD_HARVEST;
    }
    wr16(c, G_COMMAND, cmd);
    call_near(c, 0x2E384, (uint32_t)tx, (uint32_t)ty, target);
    return 1;
}

/* Left button released (0x1A2B0) after a drag: select own units in the box. */
static int selectable(Cpu *c, uint32_t u) {
    uint32_t type = rd8(c, u + U_TYPE);
    return rd8(c, u + U_OWNER) == 0 && type < 0x20 && rd16(c, G_GROUPABLE + 2 * type) != 0;
}

static void box_select(Cpu *c) {
    int mx1 = box.sx1 - MAP_X0 + 16 * (int)rd16(c, G_VIEW_X), my1 = box.sy1 - MAP_Y0 + 16 * (int)rd16(c, G_VIEW_Y);
    int x0 = box.mx0 < mx1 ? box.mx0 : mx1, x1 = box.mx0 < mx1 ? mx1 : box.mx0;
    int y0 = box.my0 < my1 ? box.my0 : my1, y1 = box.my0 < my1 ? my1 : box.my0;
    uint32_t pick[4];
    int n = 0, found = 0;
    if (rd16(c, G_LSHIFT) || rd16(c, G_RSHIFT)) {           /* shift-drag adds to the selection */
        uint32_t cur[4];
        int k = current_selection(c, cur);
        for (int i = 0; i < k; i++)
            if (selectable(c, cur[i])) pick[n++] = cur[i];
    }
    for (uint32_t p = G_UNITS; n < 4 && p < G_UNITS + 4 * 1024; p += 4) {
        uint32_t u = rd32(c, p);
        if (!u) break;
        if (!selectable(c, u)) continue;
        int cx = (int)rd16(c, u + U_X) + 8, cy = (int)rd16(c, u + U_Y) + 8;
        if (cx < x0 || cx > x1 || cy < y0 || cy > y1) continue;
        int dup = 0;
        for (int i = 0; i < n; i++) dup |= pick[i] == u;
        if (!dup) pick[n++] = u;
        found = 1;
    }
    if (!found) return;
    c->r[ESP] -= 16;                                          /* the array lives on the guest stack */
    uint32_t arr = c->r[ESP];
    for (int i = 0; i < n; i++) wr32(c, arr + 4u * (uint32_t)i, pick[i]);
    call_near(c, 0x25C50, (uint32_t)n, arr, 0);
    c->r[ESP] += 16;
    memcpy(sent.unit, pick, sizeof pick);
    sent.n = n;
    sent.ms = now_ms();
}

/* Runs in the mouse "interrupt": only tracks the drag; the game state is changed in box_select. */
static void track_drag(Cpu *c, int button, int down) {
    int sx = H.mouse_x >> 1, sy = H.mouse_y;                  /* the game halves the driver's x */
    if (button == 1 && down) {
        drag.active = in_map(sx, sy) && rd32(c, G_FRAME_HOOK) == 0x1A0F0 && rd16(c, G_COMMAND) == 0;
        drag.x0 = drag.x1 = sx;
        drag.y0 = drag.y1 = sy;
        box.mx0 = sx - MAP_X0 + 16 * (int)rd16(c, G_VIEW_X);
        box.my0 = sy - MAP_Y0 + 16 * (int)rd16(c, G_VIEW_Y);
        return;
    }
    if (!drag.active) return;
    drag.x1 = clampi(sx, MAP_X0, MAP_X1);
    drag.y1 = clampi(sy, MAP_Y0, MAP_Y1);
    if (button == 1 && !down) {
        drag.active = 0;
        if (abs(drag.x1 - drag.x0) >= DRAG_MIN || abs(drag.y1 - drag.y0) >= DRAG_MIN) {
            box.pending = 1;
            box.sx1 = drag.x1;
            box.sy1 = drag.y1;
        }
    }
}

static int on_wrap(Cpu *c, uint32_t func) {
    switch (func) {
    case 0x1B468:                                   /* right click on the map */
        if (!right_click_order(c)) return 0;
        c->ret_to = rd32(c, c->r[ESP]);             /* the original's `ret` */
        c->r[ESP] += 4;
        return 1;
    case 0x1A2B0:                                   /* left button released */
        if (box.pending) { box.pending = 0; box_select(c); }
        return 0;
    }
    return 0;
}

/* Pointer at (fx, fy) in 1/65536ths of the window; button: 0 = move, 1/2/4 = left/right/middle. */
static void mouse_input(Cpu *c, uint32_t fx, uint32_t fy, int button, int down) {
    int span_x = H.mx_max - H.mx_min, span_y = H.my_max - H.my_min;
    H.mouse_x = H.mx_min + (int)((uint64_t)fx * (uint32_t)(span_x + 1) >> 16);
    H.mouse_y = H.my_min + (int)((uint64_t)fy * (uint32_t)(span_y + 1) >> 16);
    if (H.mouse_x > H.mx_max) H.mouse_x = H.mx_max;
    if (H.mouse_y > H.my_max) H.mouse_y = H.my_max;
    uint32_t mask = 1;
    if (button) {
        if (down) { H.mouse_buttons |= button; mask = button == 1 ? 2 : button == 2 ? 8 : 32; }
        else { H.mouse_buttons &= ~button; mask = button == 1 ? 4 : button == 2 ? 16 : 64; }
    }
    track_drag(c, button, down);
    mouse_event(c, mask);
}

/* Input from the window (or the page) in one form for both builds. */
typedef struct {
    int32_t type;          /* 1: key, a = PC scancode (| 0x80 released); 2: mouse; 3: quit */
    int32_t a, b, c;       /* mouse: a, b = position as in mouse_input, c = button | down << 3 */
} InputEvent;

/* The game queues a button event with the cursor position it last drew
 * (0x617ea), not the one the mouse driver just reported, and acts on the
 * queue once per game cycle.  A press needs the cursor already in place, and
 * a press and release inside one cycle do not register: releases are held
 * back until the button has been down MIN_CLICK_MS.  Scripted clicks move
 * first and press MIN_CLICK_MS later, like a hand on a real mouse. */
#define MIN_CLICK_MS 100
#define MAX_TIMED 32
static struct { InputEvent ev; uint64_t due; } timed[MAX_TIMED];   /* in due order */
static int timed_len;
static uint64_t pressed_at[8];

static void defer_input(InputEvent ev, uint64_t due) {
    if (timed_len == MAX_TIMED) return;
    int i = timed_len++;
    for (; i > 0 && timed[i - 1].due > due; i--) timed[i] = timed[i - 1];   /* stable: equal times keep order */
    timed[i].ev = ev;
    timed[i].due = due;
}

static void handle_input(Cpu *c, const InputEvent *ev, uint64_t now) {
    if (ev->type == 1) key_event(c, (uint8_t)ev->a);
    else if (ev->type == 3) x86_stop(c, STOP_EXIT, 0);
    else if (ev->type == 2) {
        int button = ev->c & 7, down = ev->c >> 3 & 1;
        if (button && down) pressed_at[button] = now;
        mouse_input(c, (uint32_t)ev->a, (uint32_t)ev->b, button, down);
    }
}

/* Feed input to the game in order; anything behind an event that is not due yet stays queued. */
/* A press waits (up to MIN_CLICK_MS) for the game to draw its cursor where the
 * pointer is: a quick flick-and-click would otherwise act on the old spot. */
#define G_DRAWN_CURSOR 0x617EAu   /* u16 x (halved), y */
static InputEvent press_wait;
static uint64_t press_since;
static int press_waiting;

static int cursor_caught_up(Cpu *c) {
    return rd16(c, G_DRAWN_CURSOR) == (uint32_t)(H.mouse_x >> 1) && rd16(c, G_DRAWN_CURSOR + 2) == (uint32_t)H.mouse_y;
}

static void feed_input(Cpu *c, uint64_t now, int (*next)(InputEvent *)) {
    InputEvent ev;
    for (;;) {
        int waited = 0;
        if (press_waiting) {
            if (!cursor_caught_up(c) && now < press_since + MIN_CLICK_MS) return;
            ev = press_wait;
            press_waiting = 0;
            waited = 1;
        } else if (timed_len) {
            if (now < timed[0].due) return;
            ev = timed[0].ev;
            memmove(timed, timed + 1, (size_t)--timed_len * sizeof timed[0]);
        } else if (!next(&ev)) {
            return;
        } else if (ev.type == 2 && (ev.c & 7) && !(ev.c & 8) && now < pressed_at[ev.c & 7] + MIN_CLICK_MS) {
            defer_input(ev, pressed_at[ev.c & 7] + MIN_CLICK_MS);
            return;
        }
        if (!waited && ev.type == 2 && (ev.c & 8)) {
            mouse_input(c, (uint32_t)ev.a, (uint32_t)ev.b, 0, 0);      /* the pointer gets there first */
            if (!cursor_caught_up(c)) {
                press_wait = ev;
                press_since = now;
                press_waiting = 1;
                return;
            }
        }
        handle_input(c, &ev, now);
    }
}

/* Scripted input for unattended runs: WAR_INPUT="5:esc,9:return,12:click@160,100,20:snap"
 * (seconds since start; keys by name, left/right clicks (click@, rclick@) in 320x200 coordinates). */
typedef struct { uint64_t ms; char what[32]; } ScriptStep;
static ScriptStep script[64];
static int script_len, script_pos;

/* A step ends at the comma that starts the next "time:" step, so click@x,y and
 * drag@x1,y1,x2,y2 keep their own commas. */
static const char *next_step(const char *s) {
    for (const char *p = strchr(s, ','); p; p = strchr(p + 1, ',')) {
        const char *q = p + 1;
        while ((*q >= '0' && *q <= '9') || *q == '.') q++;
        if (q > p + 1 && *q == ':') return p;
    }
    return NULL;
}

static void parse_script(const char *s) {
    while (s && *s && script_len < 64) {
        ScriptStep *st = &script[script_len++];
        st->ms = (uint64_t)(atof(s) * 1000);
        const char *colon = strchr(s, ':');
        if (!colon) break;
        const char *end = next_step(colon + 1);
        size_t n = end ? (size_t)(end - colon - 1) : strlen(colon + 1);
        snprintf(st->what, sizeof st->what, "%.*s", (int)n, colon + 1);
        s = end ? end + 1 : NULL;
    }
}

static void snapshot(Cpu *c, const char *path);

static void run_script(Cpu *c, uint64_t now) {
    static const struct { const char *name; uint8_t scan; } keys[] = {
        {"esc", 0x01}, {"return", 0x1C}, {"space", 0x39}, {"up", 0x48}, {"down", 0x50},
        {"left", 0x4B}, {"right", 0x4D}, {"n", 0x31}, {"y", 0x15}, {"s", 0x1F}, {"h", 0x23}, {"o", 0x18},
        {"c", 0x2E}, {"l", 0x26}, {"q", 0x10}, {"x", 0x2D}, {"e", 0x12}, {"t", 0x14}, {"m", 0x32},
        {"a", 0x1E}, {"g", 0x22}, {"b", 0x30}, {"r", 0x13},
    };
    while (script_pos < script_len && now >= script[script_pos].ms) {
        const char *w = script[script_pos++].what;
        int shift = strncmp(w, "shift+", 6) == 0;     /* shift+click@x,y: left shift held over the click */
        if (shift) {
            w += 6;
            defer_input((InputEvent){ 1, 0x2A, 0, 0 }, now);
            defer_input((InputEvent){ 1, 0xAA, 0, 0 }, now + 3 * MIN_CLICK_MS);
        }
        if (strcmp(w, "snap") == 0) {
            char path[64];
            snprintf(path, sizeof path, "build/screen_%llu.ppm", (unsigned long long)(now / 1000));
            snapshot(c, path);
            fprintf(stderr, "war: saved %s\n", path);
        } else if (strncmp(w, "click@", 6) == 0 || strncmp(w, "rclick@", 7) == 0) {
            int x = 0, y = 0, button = w[0] == 'r' ? 2 : 1;
            sscanf(strchr(w, '@') + 1, "%d,%d", &x, &y);
            InputEvent ev = { 2, x * 65536 / 320, y * 65536 / 200, 0 };
            defer_input(ev, now);
            ev.c = button | 8;
            defer_input(ev, now + MIN_CLICK_MS);
            ev.c = button;
            defer_input(ev, now + 2 * MIN_CLICK_MS);
        } else if (strncmp(w, "move@", 5) == 0) {         /* move@x,y: pointer only */
            int x = 0, y = 0;
            sscanf(w + 5, "%d,%d", &x, &y);
            defer_input((InputEvent){ 2, x * 65536 / 320, y * 65536 / 200, 0 }, now);
        } else if (strncmp(w, "fastdrag@", 9) == 0) {     /* all at once, like a synthetic drag */
            int x1 = 0, y1 = 0, x2 = 0, y2 = 0;
            sscanf(w + 9, "%d,%d,%d,%d", &x1, &y1, &x2, &y2);
            InputEvent ev = { 2, x1 * 65536 / 320, y1 * 65536 / 200, 1 | 8 };
            defer_input(ev, now);
            ev.c = 0;
            for (int k = 1; k <= 4; k++) {
                ev.a = (x1 + (x2 - x1) * k / 4) * 65536 / 320;
                ev.b = (y1 + (y2 - y1) * k / 4) * 65536 / 200;
                defer_input(ev, now);
            }
            ev.c = 1;
            defer_input(ev, now);
        } else if (strncmp(w, "drag@", 5) == 0) {         /* drag@x1,y1,x2,y2: left button down from 1 to 2 */
            int x1 = 0, y1 = 0, x2 = 0, y2 = 0;
            sscanf(w + 5, "%d,%d,%d,%d", &x1, &y1, &x2, &y2);
            InputEvent ev = { 2, x1 * 65536 / 320, y1 * 65536 / 200, 0 };
            defer_input(ev, now);
            ev.c = 1 | 8;
            defer_input(ev, now + MIN_CLICK_MS);
            ev.c = 0;
            ev.a = (x1 + x2) / 2 * 65536 / 320; ev.b = (y1 + y2) / 2 * 65536 / 200;
            defer_input(ev, now + 2 * MIN_CLICK_MS);
            ev.a = x2 * 65536 / 320; ev.b = y2 * 65536 / 200;
            defer_input(ev, now + 3 * MIN_CLICK_MS);
            ev.c = 1;
            defer_input(ev, now + 4 * MIN_CLICK_MS);
        } else if (strcmp(w, "dump") == 0) {            /* all guest memory, for finding game state */
            char path[64];
            snprintf(path, sizeof path, "build/mem_%llu.bin", (unsigned long long)(now / 100));
            FILE *f = fopen(path, "wb");
            if (f) { fwrite(c->mem, 1, MEM_SIZE, f); fclose(f); fprintf(stderr, "war: saved %s\n", path); }
        } else if (strcmp(w, "quit") == 0) {
            x86_stop(c, STOP_EXIT, 0);
        } else {
            for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++)
                if (strcmp(w, keys[k].name) == 0) { key_event(c, keys[k].scan); key_event(c, keys[k].scan | 0x80); }
        }
    }
}

static void snapshot(Cpu *c, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fprintf(f, "P6\n320 200\n255\n");
    const uint8_t *vram = G(c, VGA_BASE);
    for (int i = 0; i < 320 * 200; i++) {
        const uint8_t *d = H.dac + vram[i] * 3;
        uint8_t rgb[3] = { (uint8_t)(d[0] * 255 / 63), (uint8_t)(d[1] * 255 / 63), (uint8_t)(d[2] * 255 / 63) };
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
}

#ifdef __EMSCRIPTEN__
static int next_input(InputEvent *ev) { return web_poll(&ev->type); }
#else
static int next_input(InputEvent *ev) {
    SDL_Event e;
    while (SDL_PollEvent(&e)) {
        switch (e.type) {
        case SDL_QUIT:
            *ev = (InputEvent){ 3, 0, 0, 0 };
            return 1;
        case SDL_KEYDOWN: case SDL_KEYUP: {
            if (e.key.repeat) break;
            uint8_t s = pc_scancode(e.key.keysym.scancode);
            if (!s) break;
            *ev = (InputEvent){ 1, e.type == SDL_KEYUP ? s | 0x80 : s, 0, 0 };
            return 1;
        }
        case SDL_MOUSEMOTION: case SDL_MOUSEBUTTONDOWN: case SDL_MOUSEBUTTONUP: {
            int wx, wy, ww, wh;
            SDL_GetMouseState(&wx, &wy);
            SDL_GetWindowSize(H.win, &ww, &wh);
            if (wx < 0) wx = 0;
            if (wy < 0) wy = 0;
            uint32_t fx = ww ? (uint32_t)((uint64_t)wx * 65536 / (uint32_t)ww) : 0;
            uint32_t fy = wh ? (uint32_t)((uint64_t)wy * 65536 / (uint32_t)wh) : 0;
            int bit = 0;
            if (e.type != SDL_MOUSEMOTION)
                bit = e.button.button == SDL_BUTTON_LEFT ? 1 : e.button.button == SDL_BUTTON_RIGHT ? 2 : 4;
            *ev = (InputEvent){ 2, (int32_t)fx, (int32_t)fy, bit | (e.type == SDL_MOUSEBUTTONDOWN) << 3 };
            return 1;
        }
        }
    }
    return 0;
}
#endif

/* Window events -> game; redraw at most ~60 times a second. */
static void pump(Cpu *c) {
    uint64_t now = now_ms();
    if (now - H.last_present < 16) return;
    H.last_present = now;
    run_script(c, now);
    if (H.snapshot_ms && now >= H.snapshot_ms) {     /* WAR_SNAPSHOT=seconds: save the screen and quit */
        snapshot(c, "build/screen.ppm");
        fprintf(stderr, "war: saved build/screen.ppm\n");
        x86_stop(c, STOP_EXIT, 0);
    }
    present(c);
    feed_input(c, now, next_input);
}

/* ---- files -------------------------------------------------------------------- */
/* DOS path -> host path inside the game folder, matching names case-insensitively. */
static int host_path(Cpu *c, uint32_t dos, char *out, size_t n) {
    char p[260];
    size_t k = 0;
    const char *s = (const char *)G(c, dos);
    if (s[0] && s[1] == ':') s += 2;
    while (*s == '\\' || *s == '/') s++;
    for (; *s && k + 1 < sizeof p; s++) p[k++] = *s == '\\' ? '/' : *s;
    p[k] = 0;
    /* resolve each component case-insensitively */
    char cur[1024];
    snprintf(cur, sizeof cur, "%s", H.game_dir);
    char *save = NULL;
    for (char *part = strtok_r(p, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        DIR *d = opendir(cur);
        char match[256] = "";
        if (d) {
            struct dirent *e;
            while ((e = readdir(d)))
                if (strcasecmp(e->d_name, part) == 0) { snprintf(match, sizeof match, "%s", e->d_name); break; }
            closedir(d);
        }
        size_t len = strlen(cur);
        snprintf(cur + len, sizeof cur - len, "/%s", match[0] ? match : part);
    }
    snprintf(out, n, "%s", cur);
    return 0;
}

/* Is this DOS path on the D: "CD" (explicitly, or relative while D: is current)? */
static int on_cd(Cpu *c, uint32_t dos) {
    const char *s = (const char *)G(c, dos);
    if (s[0] && s[1] == ':') return toupper((unsigned char)s[0]) == 'D';
    return H.drive == 3;
}

static int new_handle(FILE *fp) {
    for (int h = 5; h < 64; h++) if (!H.files[h].fp) { H.files[h].fp = fp; return h; }
    fclose(fp);
    return -1;
}

/* ---- INT 21h: DOS ---------------------------------------------------------------- */
static void int21(Cpu *c, uint32_t at) {
    char path[1024];
    switch (AH(c)) {
    case 0x30:                                     /* DOS version: 5.0 */
        c->r[EAX] = 0x0005;
        break;
    case 0xFF:                                     /* DOS/4GW presence check (AX=FF00h, DX=78h) */
        if (AX(c) == 0xFF00) { c->r[EAX] = 0xFFFF3447; x86_load_seg(c, SEG_GS, 0); break; }
        die(c, "int 21h AX=%04x at %x", AX(c), at);
        break;
    case 0x25:                                     /* set vector */
        H.pm_vector[AL(c)] = c->r[EDX];
        break;
    case 0x35:                                     /* get vector */
        x86_load_seg(c, SEG_ES, SEL_CODE);
        c->r[EBX] = H.pm_vector[AL(c)];
        break;
    case 0x2A: {                                   /* date */
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        set16(c, ECX, (uint32_t)tm.tm_year + 1900);
        set16(c, EDX, (uint32_t)((tm.tm_mon + 1) << 8 | tm.tm_mday));
        set_al(c, (uint32_t)tm.tm_wday);
        break;
    }
    case 0x2C: {                                   /* time: the game's clock() */
        pump(c);
        uint64_t cs = (now_ns() - H.start_ns) / 10000000ull + 12ull * 360000;
        uint32_t day = (uint32_t)(cs % 8640000ull);
        set16(c, ECX, (day / 360000) << 8 | (day / 6000) % 60);
        set16(c, EDX, ((day / 100) % 60) << 8 | day % 100);
        break;
    }
    case 0x19: set_al(c, (uint32_t)H.drive); break;   /* current drive */
    case 0x0E:                                     /* select drive: C: and the D: "CD" exist */
        if ((c->r[EDX] & 0xFF) == 2 || (c->r[EDX] & 0xFF) == 3) H.drive = c->r[EDX] & 0xFF;
        set_al(c, 26);
        break;
    case 0x3B: ok(c); break;                      /* chdir */
    case 0x47: G(c, c->r[ESI])[0] = 0; ok(c); break;   /* cwd: root */
    case 0x36: {                                   /* disk free; DL: 0 = current, 3 = C:, 4 = D: */
        int d = (c->r[EDX] & 0xFF) ? (int)(c->r[EDX] & 0xFF) - 1 : H.drive;
        if (d == 3) {                              /* the CD: full, 2K sectors */
            set16(c, EAX, 1); set16(c, EBX, 0); set16(c, ECX, 2048); set16(c, EDX, 0x8000);
        } else if (d == 2) {
            set16(c, EAX, 8); set16(c, EBX, 0xFFFF); set16(c, ECX, 512); set16(c, EDX, 0xFFFF);
        } else {
            set16(c, EAX, 0xFFFF);                 /* invalid drive */
        }
        break;
    }
    case 0x4A: ok(c); break;                       /* resize block */
    case 0x48: {                                   /* allocate: BX paragraphs */
        uint32_t bytes = BX(c) * 16u;
        if (H.heap_top + bytes > MEM_SIZE) { fail(c, 8); set16(c, EBX, 0); break; }
        uint16_t sel = sel_alloc(H.heap_top);
        H.heap_top = (H.heap_top + bytes + 15) & ~15u;
        set16(c, EAX, sel);
        ok(c);
        break;
    }
    case 0x49: ok(c); break;                       /* free */
    case 0x3C: case 0x3D: {                        /* create / open */
        host_path(c, c->r[EDX], path, sizeof path);
        const char *mode = AH(c) == 0x3C ? "w+b" : ((AL(c) & 3) == 0 ? "rb" : "r+b");
        FILE *fp = fopen(path, mode);
        if (!fp && AH(c) == 0x3D && strcasecmp(strrchr(path, '/') ? strrchr(path, '/') + 1 : path, "path.war") == 0) {
            /* INSTALL.EXE writes the CD's path here; without it, point at our D: "CD". */
            fp = tmpfile();
            if (fp) { fwrite("D:\\", 1, 4, fp); rewind(fp); }
        }
        if (H.trace) fprintf(stderr, "  open %s (%s) -> %s\n", (char *)G(c, c->r[EDX]), path, fp ? "ok" : "fail");
        if (!fp) { fail(c, 2); break; }
        int h = new_handle(fp);
        if (h < 0) { fail(c, 4); break; }
        c->r[EAX] = (uint32_t)h;
        ok(c);
        break;
    }
    case 0x3E:                                     /* close */
        if (BX(c) < 64 && H.files[BX(c)].fp) { fclose(H.files[BX(c)].fp); H.files[BX(c)].fp = NULL; }
        ok(c);
        break;
    case 0x3F: {                                   /* read */
        uint32_t h = BX(c), n = c->r[ECX];
        if (h >= 64 || !H.files[h].fp) {
            if (h == 0) { c->r[EAX] = 0; ok(c); break; }
            fail(c, 6); break;
        }
        c->r[EAX] = (uint32_t)fread(G(c, c->r[EDX]), 1, n, H.files[h].fp);
        ok(c);
        break;
    }
    case 0x40: {                                   /* write */
        uint32_t h = BX(c), n = c->r[ECX];
        if (h == 1 || h == 2) { fwrite(G(c, c->r[EDX]), 1, n, stderr); c->r[EAX] = n; ok(c); break; }
        if (h >= 64 || !H.files[h].fp) { fail(c, 6); break; }
        c->r[EAX] = (uint32_t)fwrite(G(c, c->r[EDX]), 1, n, H.files[h].fp);
        ok(c);
        break;
    }
    case 0x42: {                                   /* lseek */
        uint32_t h = BX(c);
        if (h >= 64 || !H.files[h].fp) { fail(c, 6); break; }
        long off = (long)(int32_t)(CX(c) << 16 | DX(c));
        int whence = AL(c) == 0 ? SEEK_SET : AL(c) == 1 ? SEEK_CUR : SEEK_END;
        if (fseek(H.files[h].fp, off, whence) != 0) { fail(c, 25); break; }
        long pos = ftell(H.files[h].fp);
        set16(c, EAX, (uint32_t)pos & 0xFFFF);
        set16(c, EDX, (uint32_t)pos >> 16);
        ok(c);
        break;
    }
    case 0x41:                                     /* delete */
        host_path(c, c->r[EDX], path, sizeof path);
        if (remove(path) != 0) fail(c, 2); else ok(c);
        break;
    case 0x43: {                                   /* attributes */
        host_path(c, c->r[EDX], path, sizeof path);
        struct stat st;
        if (stat(path, &st) != 0) { fail(c, 2); break; }
        if (AL(c) == 1) {                          /* set: the D: "CD" is read-only */
            if (on_cd(c, c->r[EDX])) fail(c, 5); else ok(c);
            break;
        }
        set16(c, ECX, S_ISDIR(st.st_mode) ? 0x10 : 0x20);
        ok(c);
        break;
    }
    case 0x44:                                     /* IOCTL: device information */
        if (AL(c) == 0) { set16(c, EDX, BX(c) < 5 ? 0x80D3 : 0x0002); ok(c); break; }
        fail(c, 1);
        break;
    case 0x06:                                     /* direct console input: nothing waiting */
        if ((c->r[EDX] & 0xFF) == 0xFF) { set_al(c, 0); c->f.zf = 1; }
        break;
    case 0x4C:
        x86_stop(c, STOP_EXIT, AL(c));
        break;
    default:
        die(c, "unhandled int 21h AH=%02x at %x", AH(c), at);
    }
}

/* ---- INT 31h: DPMI ------------------------------------------------------------- */
static void int31(Cpu *c, uint32_t at) {
    switch (AX(c)) {
    case 0x0000: {                                 /* allocate LDT descriptors */
        uint16_t first = 0;
        for (uint32_t k = 0; k < CX(c); k++) { uint16_t s = sel_alloc(0); if (!k) first = s; }
        set16(c, EAX, first); ok(c);
        break;
    }
    case 0x0001: H.ldt.used[BX(c) >> 3] = 0; ok(c); break;
    case 0x0003: set16(c, EAX, 8); ok(c); break;
    case 0x0006: {                                 /* get segment base */
        uint32_t b = sel_base(c, (uint16_t)BX(c));
        set16(c, ECX, b >> 16); set16(c, EDX, b & 0xFFFF); ok(c);
        break;
    }
    case 0x0007:                                   /* set segment base */
        H.ldt.used[BX(c) >> 3] = 1;
        H.ldt.base[BX(c) >> 3] = (uint32_t)CX(c) << 16 | DX(c);
        ok(c);
        break;
    case 0x0008: case 0x0009: ok(c); break;        /* limit / rights: everything is flat */
    case 0x0100: {                                 /* allocate DOS memory: BX paragraphs */
        uint32_t bytes = BX(c) * 16u;
        if (H.dos_top + bytes > DOS_POOL_END) { fail(c, 8); set16(c, EBX, (DOS_POOL_END - H.dos_top) / 16); break; }
        uint32_t base = H.dos_top;
        H.dos_top = (H.dos_top + bytes + 15) & ~15u;
        set16(c, EAX, base >> 4);
        set16(c, EDX, sel_alloc(base));
        ok(c);
        break;
    }
    case 0x0101: H.ldt.used[DX(c) >> 3] = 0; ok(c); break;
    case 0x0200: set16(c, ECX, 0); set16(c, EDX, 0); ok(c); break;
    case 0x0201: ok(c); break;
    case 0x0204: set16(c, ECX, SEL_CODE); c->r[EDX] = H.pm_vector[BL(c)]; ok(c); break;
    case 0x0205: H.pm_vector[BL(c)] = c->r[EDX]; ok(c); break;
    case 0x0300: case 0x0303: c->f.cf = 1; break; /* no real mode: IPX/callbacks unavailable */
    case 0x0304: ok(c); break;
    case 0x0400: set16(c, EAX, 0x005A); set16(c, EBX, 0x0005); set16(c, ECX, 3); set16(c, EDX, 0x0870); ok(c); break;
    case 0x0500: {                                 /* free memory information */
        uint8_t *info = G(c, c->r[EDI] + c->sbase[SEG_ES]);
        uint32_t free_bytes = MEM_SIZE - H.heap_top;
        memset(info, 0xFF, 48);
        memcpy(info, &free_bytes, 4);
        ok(c);
        break;
    }
    case 0x0002:                                   /* real-mode segment -> selector */
        set16(c, EAX, sel_alloc((uint32_t)BX(c) << 4));
        ok(c);
        break;
    case 0x0501: case 0x0503: {                    /* allocate / resize memory block: BX:CX bytes */
        uint32_t bytes = (uint32_t)BX(c) << 16 | CX(c);
        uint32_t base = (H.heap_top + 0xFFF) & ~0xFFFu;
        if (base + bytes > MEM_SIZE) { fail(c, 0x8013); break; }
        if (AX(c) == 0x0503) {                     /* resize: copy the old block (handle = its address) */
            uint32_t old = (uint32_t)SI(c) << 16 | DI(c);
            memmove(G(c, base), G(c, old), bytes);
        }
        H.heap_top = base + bytes;
        set16(c, EBX, base >> 16); set16(c, ECX, base & 0xFFFF);
        set16(c, ESI, base >> 16); set16(c, EDI, base & 0xFFFF);
        ok(c);
        break;
    }
    case 0x0502: ok(c); break;                     /* free memory block (bump allocator) */
    case 0x0600: case 0x0601: ok(c); break;        /* lock / unlock */
    default:
        die(c, "unhandled int 31h AX=%04x at %x", AX(c), at);
    }
}

/* ---- INT 10h: video, INT 33h: mouse --------------------------------------------- */
static void int10(Cpu *c, uint32_t at) {
    switch (AH(c)) {
    case 0x00:
        H.mode = AL(c) & 0x7F;
        if (H.mode == 0x13) { video_init(); if (!(AL(c) & 0x80)) memset(G(c, VGA_BASE), 0, 64000); }
        break;
    case 0x0F: set_al(c, (uint32_t)H.mode); set_ah(c, H.mode == 0x13 ? 40 : 80); c->r[EBX] &= ~0xFF00u; break;
    default:
        die(c, "unhandled int 10h AH=%02x at %x", AH(c), at);
    }
}

static void int33(Cpu *c, uint32_t at) {
    switch (AX(c)) {
    case 0x00: set16(c, EAX, 0xFFFF); set16(c, EBX, 2); break;
    case 0x01: case 0x02: break;
    case 0x03: pump(c); set16(c, EBX, (uint32_t)H.mouse_buttons); set16(c, ECX, (uint32_t)H.mouse_x); set16(c, EDX, (uint32_t)H.mouse_y); break;
    case 0x04: H.mouse_x = CX(c); H.mouse_y = DX(c); break;
    case 0x07: H.mx_min = (int16_t)CX(c); H.mx_max = (int16_t)DX(c); break;
    case 0x08: H.my_min = (int16_t)CX(c); H.my_max = (int16_t)DX(c); break;
    case 0x0C: H.mouse_mask = CX(c); H.mouse_handler = c->r[EDX]; break;
    case 0x0F: case 0x1A: case 0x1D: break;
    default:
        die(c, "unhandled int 33h AX=%04x at %x", AX(c), at);
    }
}

static void on_int(Cpu *c, int vec, uint32_t at) {
    if (H.trace) fprintf(stderr, "int %02xh ax=%04x bx=%04x cx=%04x dx=%04x at %x\n", vec, AX(c), BX(c), CX(c), DX(c), at);
    switch (vec) {
    case 0x21: int21(c, at); break;
    case 0x31: int31(c, at); break;
    case 0x10: int10(c, at); break;
    case 0x33: int33(c, at); break;
    case 0x2F: if (AX(c) == 0x1686) set16(c, EAX, 0); break;     /* DPMI present */
    default: die(c, "unhandled int %02xh at %x", vec, at);
    }
}

/* ---- ports --------------------------------------------------------------------- */
static uint32_t on_in(Cpu *c, uint32_t port, int bytes) {
    (void)bytes;
    switch (port) {
    case 0x3DA:                                    /* input status: alternate retrace */
        pump(c);
        H.retrace ^= 0x09;
        return H.retrace;
    case 0x3C9: {
        uint8_t v = H.dac[(H.dac_r * 3 + H.dac_rc) % 768];
        if (++H.dac_rc == 3) { H.dac_rc = 0; H.dac_r = (H.dac_r + 1) & 0xFF; }
        return v;
    }
    case 0x60: return H.last_scan;
    case 0x61: case 0x21: case 0xA1: return 0;
    default:
        if (H.trace) fprintf(stderr, "in %x\n", port);
        return 0xFF;
    }
}

static void on_out(Cpu *c, uint32_t port, uint32_t v, int bytes) {
    (void)c; (void)bytes;
    switch (port) {
    case 0x3C8: H.dac_w = v & 0xFF; H.dac_wc = 0; break;
    case 0x3C7: H.dac_r = v & 0xFF; H.dac_rc = 0; break;
    case 0x3C9:
        H.dac[(H.dac_w * 3 + H.dac_wc) % 768] = v & 63;
        if (++H.dac_wc == 3) { H.dac_wc = 0; H.dac_w = (H.dac_w + 1) & 0xFF; }
        break;
    default:
        if (H.trace) fprintf(stderr, "out %x <- %x\n", port, v);
    }
}

/* ---- indirect calls, traps ------------------------------------------------------ */
static void dispatch(Cpu *c, uint32_t target, uint32_t at) {
    unsigned lo = 0, hi = lifted_table_len;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (lifted_table[mid].addr < target) lo = mid + 1; else hi = mid;
    }
    if (lo < lifted_table_len && lifted_table[lo].addr == target) { lifted_table[lo].fn(c); return; }
    die(c, "call to %x (no lifted function) from %x", target, at);
}

static void on_trap(Cpu *c, uint32_t at, const char *what) {
    fprintf(stderr, "war: untranslated instruction at %x: %s\n", at, what);
    (void)c;
}

/* ---- functions replaced by the runtime (lift.py HLE) ------------------------- */
static void on_hle(Cpu *c, uint32_t func) {
    switch (func) {
    case 0x3CC50: {      /* int386x core: ESI = vector, EBX -> SREGS, EDI -> REGS in */
        uint32_t vec = c->r[ESI] & 0xFF, sregs = c->r[EBX], in = c->r[EDI];
        uint32_t ds = rd16(c, sregs + 6);
        x86_load_seg(c, SEG_ES, rd16(c, sregs));
        c->r[EBP] = (c->r[EBP] & 0xFFFF0000u) | ds;
        c->r[EAX] = rd32(c, in);
        c->r[EBX] = rd32(c, in + 4);
        c->r[ECX] = rd32(c, in + 8);
        c->r[EDX] = rd32(c, in + 12);
        c->r[ESI] = rd32(c, in + 16);
        c->r[EDI] = rd32(c, in + 20);
        x86_load_seg(c, SEG_DS, ds);
        on_int(c, (int)vec, func);
        c->ret_to = rd32(c, c->r[ESP]);           /* the stub's `ret` returns to our caller */
        c->r[ESP] += 4;
        break;
    }
    default:
        die(c, "no runtime implementation for %x", func);
    }
}

static const Hooks HOOKS = { on_int, on_in, on_out, dispatch, on_trap, sel_base, on_hle, on_wrap };

/* ---- checkpoint dumps (debugging; RECOMP_TRACE builds) ------------------------------ */
#ifdef RECOMP_TRACE
static unsigned dump_skip;

/* Entry state of c->dump_at: regs, flags, segments, then all guest memory.
 * tools/ckdiff.py replays it on Unicorn and on the lifted code. */
static void print_stack(Cpu *c) {
    fprintf(stderr, " call stack (innermost first):");
    for (uint32_t k = 0; k < 10 && k < c->depth; k++) fprintf(stderr, " %x", c->stack[(c->depth - 1 - k) & 255]);
    fprintf(stderr, "\n");
}

void x86_on_watch(Cpu *c, uint32_t addr, uint32_t n) {
    fprintf(stderr, "watch: write %u bytes at %x;", n, addr);
    print_stack(c);
}

void x86_on_enter(Cpu *c, uint32_t addr) {
    if (dump_skip) { dump_skip--; return; }
    char path[64];
    snprintf(path, sizeof path, "build/dump_%x.bin", addr);
    FILE *f = fopen(path, "wb");
    uint32_t hdr[4] = { 0x31504D44, addr, MEM_SIZE, x86_pack_flags(&c->f) };
    fwrite(hdr, 4, 4, f);
    fwrite(c->r, 4, 8, f);
    fwrite(c->sbase, 4, 6, f);
    fwrite(c->mem, 1, MEM_SIZE, f);
    fclose(f);
    fprintf(stderr, "war: dumped entry state of %x to %s\n", addr, path);
    x86_stop(c, STOP_EXIT, 0);
}
#endif

/* ---- boot -------------------------------------------------------------------------- */
static uint8_t *load_image(const char *path, uint32_t *entry, uint32_t *esp, uint8_t *mem, uint32_t *top) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    uint32_t hdr[7];
    if (fread(hdr, 4, 7, f) != 7 || hdr[0] != 0x314D4957) { fprintf(stderr, "%s: bad image\n", path); exit(1); }
    if (fread(mem + hdr[3], 1, hdr[4], f) != hdr[4]) { fprintf(stderr, "%s: truncated\n", path); exit(1); }
    fclose(f);
    *entry = hdr[1];
    *esp = hdr[2];
    *top = hdr[3] + hdr[4];
    return mem;
}

static void build_psp_env(uint8_t *mem) {
    static const char env[] = "PATH=C:\\\0COMSPEC=C:\\COMMAND.COM\0BLASTER=\0\0\x01\0C:\\WAR.EXE\0";
    memcpy(mem + ENV_BASE, env, sizeof env);
    uint8_t *psp = mem + PSP_BASE;
    psp[0] = 0xCD; psp[1] = 0x20;                  /* int 20h */
    uint16_t env_sel = SEL_ENV;
    memcpy(psp + 0x2C, &env_sel, 2);
    psp[0x80] = 0;                                 /* empty command tail */
    psp[0x81] = '\r';
}

int main(int argc, char *argv[]) {
    H.game_dir = argc > 1 ? argv[1] : "work/game";
    const char *image = argc > 2 ? argv[2] : "build/image.bin";
    H.trace = getenv("WAR_TRACE") != NULL;
    if (getenv("WAR_SNAPSHOT")) H.snapshot_ms = (uint64_t)(atof(getenv("WAR_SNAPSHOT")) * 1000);
    parse_script(getenv("WAR_INPUT"));
    H.start_ns = now_ns();
    H.mx_max = 639; H.my_max = 199;
    H.drive = 2;

    static Cpu c;
    memset(&c, 0, sizeof c);
    c.mem = calloc(1, MEM_SIZE);
    c.mem_size = MEM_SIZE;
    c.budget = INT64_MAX;
    c.hooks = &HOOKS;
    uint32_t entry, esp, top;
    load_image(image, &entry, &esp, c.mem, &top);
    build_psp_env(c.mem);
    H.heap_top = HEAP_BASE;
    H.dos_top = DOS_POOL;
    sel_fixed(SEL_CODE, 0);
    sel_fixed(SEL_DATA, 0);
    sel_fixed(SEL_PSP, PSP_BASE);
    sel_fixed(SEL_ENV, ENV_BASE);
    sel_fixed(SEL_BIOS, 0x400);

    /* registers as DOS/4GW hands them to a flat-model program */
    x86_load_seg(&c, SEG_CS, SEL_CODE);
    x86_load_seg(&c, SEG_DS, SEL_DATA);
    x86_load_seg(&c, SEG_SS, SEL_DATA);
    x86_load_seg(&c, SEG_ES, SEL_PSP);
    c.r[ESP] = esp - 4;
    wr32(&c, c.r[ESP], CALLBACK_RET);
    c.f.df = 0;

#ifdef RECOMP_TRACE
    if (getenv("WAR_DUMP_AT")) c.dump_at = (uint32_t)strtoul(getenv("WAR_DUMP_AT"), NULL, 16);
    if (getenv("WAR_DUMP_SKIP")) dump_skip = (unsigned)atoi(getenv("WAR_DUMP_SKIP"));
    if (getenv("WAR_WATCH")) {                     /* WAR_WATCH=addr[,len] */
        char *end;
        c.watch_lo = (uint32_t)strtoul(getenv("WAR_WATCH"), &end, 16);
        c.watch_hi = c.watch_lo + (*end == ',' ? (uint32_t)strtoul(end + 1, NULL, 16) : 1);
    }
#endif
    int why = setjmp(c.stop);
    if (why == 0) {
        dispatch(&c, entry, 0);
        fprintf(stderr, "war: entry point returned\n");
        return 0;
    }
    if (why == STOP_EXIT) return (int)c.fault_addr;
    const char *names[] = {"ok", "memory fault", "budget", "divide error", "bad return", "trap", "exit"};
    fprintf(stderr, "war: stopped (%s) at %x\n  eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x\n",
            names[why], c.fault_addr, c.r[EAX], c.r[ECX], c.r[EDX], c.r[EBX], c.r[ESP], c.r[EBP], c.r[ESI], c.r[EDI]);
    if (why == STOP_BADRET)
        fprintf(stderr, "  call at %x expected return to %x, got %x\n", c.bad_call, c.bad_expect, c.ret_to);
    fprintf(stderr, "  stack at last call:");
    for (int k = 0; k < 8 && c.r[ESP] + 4 * k + 4 <= MEM_SIZE; k++) fprintf(stderr, " %08x", rd32(&c, c.r[ESP] + 4 * k));
    fprintf(stderr, "\n");
#ifdef RECOMP_TRACE
    print_stack(&c);
    fprintf(stderr, "  recently entered:");
    for (uint32_t k = 0; k < 24 && k < c.trail_pos; k++) fprintf(stderr, " %x", c.trail[(c.trail_pos - 1 - k) & 63]);
    fprintf(stderr, "\n");
#endif
    return 1;
}
