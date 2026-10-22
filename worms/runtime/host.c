/* Native host for the recompiled WRMS.EXE (Worms, DOS, 1995).
 *
 * Forked from recomp/runtime/game.c (WarCraft) and plays the same part: DOS +
 * DOS/4GW + the PC hardware for the lifted code.  It loads the relocated
 * image, answers INT 21h (DOS), INT 31h (DPMI, with MSCDEX on real-mode
 * INT 2Fh for the CD), INT 10h and INT 33h, emulates the VGA (mode 13h and
 * unchained mode X with planar memory), the DAC, retrace, keyboard and the
 * PIT, runs the game's timer and keyboard handlers, shows the screen through
 * SDL2 and feeds keyboard/mouse events to the game.
 *
 *   worms [GAME_DIR [CD_DIR [IMAGE]]]   defaults: work/game work/cd build/image.bin
 *   WAR_TRACE=1 worms ...              log every interrupt
 *   WAR_SNAPSHOT=s, WAR_INPUT=...      unattended runs (see run_script)
 *
 * Not yet: Sound Blaster and CD audio (silence), the FMV player (skipped),
 * the browser build.
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
#define DOS_POOL_END  0x9C000u
#define VGA_BASE      0xA0000u
#define HEAP_BASE     0x00400000u  /* INT 21h 48h allocations */
#define CALLBACK_RET  0xFFFFFFF0u  /* return address used when the host calls guest code */
#define BIOS_IRET     0xFFFFFFE0u  /* "BIOS" handler behind every vector the game did not set */
#define ISR_STACK     0x0009FC00u  /* interrupts taken between instructions run on this stack */
#define TICK_BRANCHES 20000        /* backward branches between timer checks */

#define SEL_CODE 0x0008
#define SEL_DATA 0x0010
#define SEL_PSP  0x0018
#define SEL_ENV  0x0020
#define SEL_BIOS 0x0040
#define SEL_FIRST_FREE 0x0080
#define MAX_SEL  1024

#define SCALE 3
#define MAX_W 360
#define MAX_H 480

typedef struct {
    uint32_t base[MAX_SEL];
    uint8_t used[MAX_SEL];
} Ldt;

typedef struct {
    FILE *fp;
} Handle;

typedef struct {
    const char *game_dir, *cd_dir;
    Ldt ldt;
    uint32_t pm_vector[256];      /* handlers the game installed */
    /* PIT channel 0 (IRQ0) */
    uint32_t pit_div;             /* 0 = 65536 */
    int pit_lo_next;              /* the next port 40h write is the low byte */
    uint64_t pit_next_ns;
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
    int tex_w, tex_h;
#endif
    uint64_t last_present;
    /* input */
    uint8_t keys[64];
    int key_head, key_tail;
    uint8_t last_scan;
    uint32_t mouse_handler, mouse_mask;
    int mouse_x, mouse_y, mouse_buttons;
    int mx_min, mx_max, my_min, my_max;
    int set_x, set_y;             /* where the game last put the driver's position (int 33h 04h) */
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
    fprintf(stderr, "worms: ");
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
    H.win = SDL_CreateWindow("Worms (native arm64)", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                             320 * SCALE, 200 * SCALE, SDL_WINDOW_ALLOW_HIGHDPI);
    H.ren = SDL_CreateRenderer(H.win, -1, SDL_RENDERER_ACCELERATED);
    SDL_ShowCursor(SDL_DISABLE);
}
#endif

/* ---- VGA registers and planar memory ------------------------------------------
 * Mode 13h starts chained (chain-4: A0000 is plain linear memory in the guest).
 * Clearing chain-4 in sequencer register 4 switches to "mode X": the four
 * planes live here, and A0000-AFFFF becomes MMIO through vga_mem_read/write,
 * with the map mask, read map, write modes 0-3, logical ops, bit mask and
 * latches of a real VGA.  The picture is built from the planes using the CRTC
 * start address, offset and display size, so page flips and scrolling work. */
typedef struct {
    uint8_t seq_i, seq[8], gc_i, gc[16], crtc_i, crtc[32];
    uint8_t latch[4];
    int planar;
    uint8_t plane[4][65536];
} Vga;
static Vga V;

static void vga_mode13(Cpu *c) {
    static const uint8_t crtc13[25] = { 0x5F, 0x4F, 0x50, 0x82, 0x54, 0x80, 0xBF, 0x1F, 0x00, 0x41, 0, 0, 0, 0, 0, 0,
                                        0x9C, 0x0E, 0x8F, 0x28, 0x40, 0x96, 0xB9, 0xA3, 0xFF };
    memset(V.seq, 0, sizeof V.seq);
    memset(V.gc, 0, sizeof V.gc);
    memcpy(V.crtc, crtc13, sizeof crtc13);
    V.seq[1] = 0x01; V.seq[2] = 0x0F; V.seq[4] = 0x0E;
    V.gc[5] = 0x40; V.gc[6] = 0x05; V.gc[7] = 0x0F; V.gc[8] = 0xFF;
    V.planar = 0;
    c->mmio_lo = c->mmio_hi = 0;
}

/* chain-4 off: the planes take over A0000 (starting from what chained mode left there) */
static void vga_update_chain(Cpu *c) {
    int planar = !(V.seq[4] & 0x08);
    if (planar == V.planar) return;
    V.planar = planar;
    if (planar) {
        const uint8_t *lin = G(c, VGA_BASE);
        for (uint32_t i = 0; i < 65536; i++) V.plane[i & 3][i >> 2] = lin[i];
        c->mmio_lo = VGA_BASE; c->mmio_hi = VGA_BASE + 0x10000;
    } else {
        uint8_t *lin = G(c, VGA_BASE);
        for (uint32_t i = 0; i < 65536; i++) lin[i] = V.plane[i & 3][i >> 2];
        c->mmio_lo = c->mmio_hi = 0;
    }
}

static uint8_t vga_alu(uint8_t d, uint8_t latch) {
    switch (V.gc[3] >> 3 & 3) {
    case 1: return d & latch;
    case 2: return d | latch;
    case 3: return d ^ latch;
    default: return d;
    }
}

static void vga_write8(uint32_t off, uint8_t v) {
    uint8_t mask = V.gc[8], rot = V.gc[3] & 7;
    v = (uint8_t)(v >> rot | v << (8 - rot));
    for (int p = 0; p < 4; p++) {
        if (!(V.seq[2] >> p & 1)) continue;
        uint8_t d, m = mask;
        switch (V.gc[5] & 3) {
        case 0: d = (V.gc[1] >> p & 1) ? ((V.gc[0] >> p & 1) ? 0xFF : 0) : v; break;
        case 1: V.plane[p][off] = V.latch[p]; continue;
        case 2: d = (v >> p & 1) ? 0xFF : 0; break;
        default: d = (V.gc[0] >> p & 1) ? 0xFF : 0; m &= v; break;
        }
        d = vga_alu(d, V.latch[p]);
        V.plane[p][off] = (uint8_t)((d & m) | (V.latch[p] & ~m));
    }
}

static uint8_t vga_read8(uint32_t off) {
    for (int p = 0; p < 4; p++) V.latch[p] = V.plane[p][off];
    if (!(V.gc[5] & 0x08)) return V.plane[V.gc[4] & 3][off];
    uint8_t differ = 0;                            /* read mode 1: color compare */
    for (int p = 0; p < 4; p++)
        if (V.gc[7] >> p & 1) differ |= V.latch[p] ^ ((V.gc[2] >> p & 1) ? 0xFF : 0);
    return (uint8_t)~differ;
}

static uint32_t vga_mem_read(Cpu *c, uint32_t a, int bytes) {
    (void)c;
    uint32_t v = 0;
    for (int i = 0; i < bytes; i++) v |= (uint32_t)vga_read8((a + (uint32_t)i - VGA_BASE) & 0xFFFF) << (8 * i);
    return v;
}

static void vga_mem_write(Cpu *c, uint32_t a, uint32_t v, int bytes) {
    (void)c;
    for (int i = 0; i < bytes; i++) vga_write8((a + (uint32_t)i - VGA_BASE) & 0xFFFF, (uint8_t)(v >> (8 * i)));
}

/* Displayed size from the CRTC: 320x200 in mode 13h, 320x240 etc. in tweaked modes. */
static void vga_size(int *w, int *h) {
    int vde = V.crtc[0x12] | (V.crtc[7] & 0x02) << 7 | (V.crtc[7] & 0x40) << 3;
    int scan = (V.crtc[9] & 0x1F) + 1;
    if (V.crtc[9] & 0x80) scan *= 2;
    *w = (V.crtc[1] + 1) * 4;
    *h = (vde + 1) / scan;
    if (*w < 8 || *w > MAX_W) *w = 320;
    if (*h < 8 || *h > MAX_H) *h = 200;
}

/* The screen as palette indices. */
static void vga_scan(Cpu *c, uint8_t *out, int w, int h) {
    if (!V.planar) {
        memcpy(out, G(c, VGA_BASE), (size_t)(w * h) <= 65536 ? (size_t)(w * h) : 65536);
        return;
    }
    uint32_t start = (uint32_t)V.crtc[0x0C] << 8 | V.crtc[0x0D];
    uint32_t pitch = (uint32_t)V.crtc[0x13] * 2;
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++)
            out[y * w + x] = V.plane[x & 3][(start + (uint32_t)y * pitch + (uint32_t)(x >> 2)) & 0xFFFF];
}

static void present(Cpu *c) {
    if (!H.video_on) return;
    static uint8_t idx[MAX_W * MAX_H];
    static uint32_t px[MAX_W * MAX_H];
    int w, h;
    vga_size(&w, &h);
    vga_scan(c, idx, w, h);
    uint32_t lut[256];
    for (int i = 0; i < 256; i++) {
        const uint8_t *d = H.dac + i * 3;
        lut[i] = PIXEL(d[0] * 255 / 63, d[1] * 255 / 63, d[2] * 255 / 63);
    }
    for (int i = 0; i < w * h; i++) px[i] = lut[idx[i]];
#ifdef __EMSCRIPTEN__
    web_present(px);
#else
    if (w != H.tex_w || h != H.tex_h) {
        if (H.tex) SDL_DestroyTexture(H.tex);
        H.tex = SDL_CreateTexture(H.ren, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, w, h);
        H.tex_w = w; H.tex_h = h;
    }
    SDL_UpdateTexture(H.tex, NULL, px, w * 4);
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
    if (H.pm_vector[9] != BIOS_IRET) call_guest(c, H.pm_vector[9], 1);   /* the game's own keyboard ISR */
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

/* Pointer at (fx, fy) in 1/65536ths of the window; button: 0 = move, 1/2/4 = left/right/middle.
 * Worms reads the driver's position and puts it back in the middle every
 * frame (int 33h 03h/04h): only motion counts, one unit per screen pixel.
 * The driver reports the way from the game's own cursor to the pointer, so
 * the cursor lands on the pointer at the next read. */
#define G_CURSOR 0x11E6ECu        /* int32 x, y: the game's cursor on the screen */
static void mouse_input(Cpu *c, uint32_t fx, uint32_t fy, int button, int down) {
    int px = (int)(((uint64_t)fx * 320 + 32768) >> 16), py = (int)(((uint64_t)fy * 200 + 32768) >> 16);
    H.mouse_x = H.set_x + (px - (int32_t)rd32(c, G_CURSOR));
    H.mouse_y = H.set_y + (py - (int32_t)rd32(c, G_CURSOR + 4));
    if (H.mouse_x < H.mx_min) H.mouse_x = H.mx_min;
    if (H.mouse_y < H.my_min) H.mouse_y = H.my_min;
    if (H.mouse_x > H.mx_max) H.mouse_x = H.mx_max;
    if (H.mouse_y > H.my_max) H.mouse_y = H.my_max;
    uint32_t mask = 1;
    if (button) {
        if (down) { H.mouse_buttons |= button; mask = button == 1 ? 2 : button == 2 ? 8 : 32; }
        else { H.mouse_buttons &= ~button; mask = button == 1 ? 4 : button == 2 ? 16 : 64; }
    }
    mouse_event(c, mask);
}

/* Input from the window (or the page) in one form for both builds. */
typedef struct {
    int32_t type;          /* 1: key, a = PC scancode (| 0x80 released); 2: mouse; 3: quit */
    int32_t a, b, c;       /* mouse: a, b = position as in mouse_input, c = button | down << 3 */
} InputEvent;

/* The game polls the buttons once per frame, so a press and release inside
 * one frame would not register: releases are held back until the button has
 * been down MIN_CLICK_MS.  Scripted clicks move first and press MIN_CLICK_MS
 * later, like a hand on a real mouse. */
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
static void feed_input(Cpu *c, uint64_t now, int (*next)(InputEvent *)) {
    InputEvent ev;
    for (;;) {
        if (timed_len) {
            if (now < timed[0].due) return;
            ev = timed[0].ev;
            memmove(timed, timed + 1, (size_t)--timed_len * sizeof timed[0]);
        } else if (!next(&ev)) {
            return;
        } else if (ev.type == 2 && (ev.c & 7) && !(ev.c & 8) && now < pressed_at[ev.c & 7] + MIN_CLICK_MS) {
            defer_input(ev, pressed_at[ev.c & 7] + MIN_CLICK_MS);
            return;
        }
        handle_input(c, &ev, now);
    }
}

/* Scripted input for unattended runs: WAR_INPUT="5:esc,9:return,12:click@160,100,20:snap"
 * (seconds since start; keys by name or held with keyhold@name,ms; left/right
 * clicks (click@, rclick@) in 320x200 coordinates). */
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
            fprintf(stderr, "worms: saved %s\n", path);
        } else if (strncmp(w, "click@", 6) == 0 || strncmp(w, "rclick@", 7) == 0) {
            int x = 0, y = 0, button = w[0] == 'r' ? 2 : 1;
            sscanf(strchr(w, '@') + 1, "%d,%d", &x, &y);
            InputEvent ev = { 2, x * 65536 / 320, y * 65536 / 200, 0 };
            defer_input(ev, now);
            ev.c = button | 8;
            defer_input(ev, now + MIN_CLICK_MS);
            ev.c = button;
            defer_input(ev, now + 2 * MIN_CLICK_MS);
        } else if (strncmp(w, "hold@", 5) == 0) {         /* hold@x,y,ms: left button down for ms */
            int x = 0, y = 0, ms = 0;
            sscanf(w + 5, "%d,%d,%d", &x, &y, &ms);
            InputEvent ev = { 2, x * 65536 / 320, y * 65536 / 200, 0 };
            defer_input(ev, now);
            ev.c = 1 | 8;
            defer_input(ev, now + MIN_CLICK_MS);
            ev.c = 1;
            defer_input(ev, now + MIN_CLICK_MS + (uint64_t)ms);
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
        } else if (strncmp(w, "keyhold@", 8) == 0) {      /* keyhold@name,ms: key down for ms */
            char name[16] = "";
            int ms = 0;
            sscanf(w + 8, "%15[^,],%d", name, &ms);
            for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++)
                if (strcmp(name, keys[k].name) == 0) {
                    defer_input((InputEvent){ 1, keys[k].scan, 0, 0 }, now);
                    defer_input((InputEvent){ 1, keys[k].scan | 0x80, 0, 0 }, now + (uint64_t)ms);
                }
        } else if (strcmp(w, "dump") == 0) {            /* all guest memory, for finding game state */
            char path[64];
            snprintf(path, sizeof path, "build/mem_%llu.bin", (unsigned long long)(now / 100));
            FILE *f = fopen(path, "wb");
            if (f) { fwrite(c->mem, 1, MEM_SIZE, f); fclose(f); fprintf(stderr, "worms: saved %s\n", path); }
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
    static uint8_t idx[MAX_W * MAX_H];
    int w, h;
    vga_size(&w, &h);
    vga_scan(c, idx, w, h);
    fprintf(f, "P6\n%d %d\n255\n", w, h);
    for (int i = 0; i < w * h; i++) {
        const uint8_t *d = H.dac + idx[i] * 3;
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

/* ---- audio output -------------------------------------------------------------
 * sound.c renders as many frames as wall time asks for.  Native builds queue
 * them on an SDL audio device (none when the window is SDL's dummy driver, or
 * with WAR_MUTE); the browser build hands them to web/audio.js through a
 * SharedArrayBuffer ring.  WAR_WAV=file also records them, for checks. */
#define AUDIO_RATE 48000
static uint64_t audio_done;                       /* frames rendered so far */
static FILE *wav_out;
static uint32_t wav_frames;

#ifdef __EMSCRIPTEN__
EM_JS(void, web_audio, (const int16_t *pcm, int frames), {
    const a = globalThis.warAudio;
    if (!a) return;
    const cap = a.buf.length / 2, wr = Atomics.load(a.idx, 0), rd = Atomics.load(a.idx, 1);
    const n = Math.min(frames, cap - (wr - rd));
    for (let i = 0; i < n; i++) {
        const j = ((wr + i) % cap) * 2;
        a.buf[j] = HEAP16[(pcm >> 1) + 2 * i] / 32768;
        a.buf[j + 1] = HEAP16[(pcm >> 1) + 2 * i + 1] / 32768;
    }
    Atomics.store(a.idx, 0, wr + n);
});
static void audio_open(void) {}
static void audio_out(const int16_t *pcm, int frames) { web_audio(pcm, frames); }
#else
static SDL_AudioDeviceID audio_dev;

static void audio_open(void) {
    const char *vd = getenv("SDL_VIDEODRIVER");
    if (getenv("WAR_MUTE") || (vd && !strcmp(vd, "dummy"))) return;
    if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) { fprintf(stderr, "worms: no audio: %s\n", SDL_GetError()); return; }
    SDL_AudioSpec want, have;
    memset(&want, 0, sizeof want);
    want.freq = AUDIO_RATE;
    want.format = AUDIO_S16SYS;
    want.channels = 2;
    want.samples = 1024;
    audio_dev = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
    if (!audio_dev) { fprintf(stderr, "worms: no audio device: %s\n", SDL_GetError()); return; }
    static int16_t lead[2 * AUDIO_RATE / 16];       /* 60 ms of slack against irregular frames */
    SDL_QueueAudio(audio_dev, lead, sizeof lead);
    SDL_PauseAudioDevice(audio_dev, 0);
}

static void audio_out(const int16_t *pcm, int frames) {
    if (!audio_dev) return;
    if (SDL_GetQueuedAudioSize(audio_dev) > AUDIO_RATE * 4 / 4) return;   /* over 250 ms behind: drop */
    SDL_QueueAudio(audio_dev, pcm, (Uint32)frames * 4);
}
#endif

static void wav_close(void) {
    if (!wav_out) return;
    uint32_t hdr[11] = { 0x46464952, 36 + wav_frames * 4, 0x45564157, 0x20746D66, 16, 0x00020001,
                         AUDIO_RATE, AUDIO_RATE * 4, 0x00100004, 0x61746164, wav_frames * 4 };
    fseek(wav_out, 0, SEEK_SET);
    fwrite(hdr, 4, 11, wav_out);
    fclose(wav_out);
    wav_out = NULL;
}

static void audio_pump(uint64_t now) {
    static int16_t buf[2 * AUDIO_RATE / 4];
    uint64_t due = now * AUDIO_RATE / 1000;
    if (due <= audio_done) return;
    uint64_t n = due - audio_done;
    if (n > AUDIO_RATE / 4) { audio_done = due - AUDIO_RATE / 4; n = AUDIO_RATE / 4; }   /* after a stall */
    memset(buf, 0, (size_t)n * 4);                 /* TODO: Sound Blaster + CD audio mixer */
    audio_done += n;
    audio_out(buf, (int)n);
    if (wav_out) { fwrite(buf, 4, (size_t)n, wav_out); wav_frames += (uint32_t)n; }
}

/* IRQ0: run the game's timer handler for each PIT period that has passed. */
static void pit_poll(Cpu *c) {
    if (H.pm_vector[8] == BIOS_IRET || H.in_callback) return;
    uint64_t period = (uint64_t)(H.pit_div ? H.pit_div : 65536) * 1000000000ull / 1193182;
    uint64_t now = now_ns();
    if (!H.pit_next_ns) H.pit_next_ns = now + period;
    for (int n = 0; now >= H.pit_next_ns && n < 4; n++) {
        call_guest(c, H.pm_vector[8], 1);
        H.pit_next_ns += period;
    }
    if (now >= H.pit_next_ns) H.pit_next_ns = now + period;   /* far behind: drop ticks */
}

/* Window events -> game; redraw at most ~60 times a second. */
static void pump(Cpu *c) {
    pit_poll(c);
    uint64_t now = now_ms();
    if (now - H.last_present < 16) return;
    H.last_present = now;
    run_script(c, now);
    if (H.snapshot_ms && now >= H.snapshot_ms) {     /* WAR_SNAPSHOT=seconds: save the screen and quit */
        snapshot(c, "build/screen.ppm");
        fprintf(stderr, "worms: saved build/screen.ppm\n");
        x86_stop(c, STOP_EXIT, 0);
    }
    present(c);
    audio_pump(now);
    feed_input(c, now, next_input);
}

/* ---- files -------------------------------------------------------------------- */
/* DOS path -> host path inside the game folder, matching names case-insensitively. */
static int host_path(Cpu *c, uint32_t dos, char *out, size_t n) {
    char p[260];
    size_t k = 0;
    const char *s = (const char *)G(c, dos);
    int drive = H.drive;
    if (s[0] && s[1] == ':') { drive = toupper((unsigned char)s[0]) - 'A'; s += 2; }
    while (*s == '\\' || *s == '/') s++;
    for (; *s && k + 1 < sizeof p; s++) p[k++] = *s == '\\' ? '/' : *s;
    p[k] = 0;
    /* resolve each component case-insensitively */
    char cur[1024];
    snprintf(cur, sizeof cur, "%s", drive == 3 ? H.cd_dir : H.game_dir);
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

/* ---- CD-ROM (MSCDEX through DPMI 0300h) ------------------------------------------
 * D: is the data track (a folder); the audio tracks come from work/audio.json
 * (tools/extract.py).  Play/stop/resume keep the position so the game sees a
 * drive that plays for as long as the track lasts.  TODO: mix the audio. */
#define CD_MAX_TRACKS 32
static struct {
    int first, last;                               /* audio track numbers */
    uint32_t start[CD_MAX_TRACKS + 1], len[CD_MAX_TRACKS + 1];   /* LBA, by track number */
    uint32_t leadout;
    uint32_t play_lba, play_len;                   /* current request */
    uint64_t play_since;                           /* now_ns() at (re)start; 0 = not playing */
    uint32_t played;                               /* sectors played before a pause */
} CD;

static void cd_load(const char *json) {
    FILE *f = fopen(json, "r");
    CD.first = 2; CD.last = 1;
    if (!f) { fprintf(stderr, "worms: no %s: the CD has no audio tracks\n", json); return; }
    char line[256];
    int track = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned v;
        if (sscanf(line, " \"track\": %u", &v) == 1 && v <= CD_MAX_TRACKS) track = (int)v;
        else if (sscanf(line, " \"start\": %u", &v) == 1 && track) CD.start[track] = v;
        else if (sscanf(line, " \"sectors\": %u", &v) == 1 && track) {
            CD.len[track] = v;
            if (track > CD.last) CD.last = track;
            if (CD.start[track] + v > CD.leadout) CD.leadout = CD.start[track] + v;
        }
    }
    fclose(f);
    CD.start[1] = 0;
    CD.len[1] = CD.start[CD.first];
}

static uint32_t cd_position(void) {                /* sectors into the current request */
    uint32_t done = CD.played;
    if (CD.play_since) done += (uint32_t)((now_ns() - CD.play_since) * 75 / 1000000000ull);
    return done < CD.play_len ? done : CD.play_len;
}
static int cd_playing(void) { return CD.play_since && cd_position() < CD.play_len; }

/* Red Book address (frame, second, minute, 0) of an LBA */
static uint32_t cd_msf(uint32_t lba) {
    lba += 150;
    return (lba / 4500) << 16 | (lba / 75 % 60) << 8 | lba % 75;
}
static uint32_t cd_lba(uint32_t addr, int redbook) {
    if (!redbook) return addr;
    return ((addr >> 16 & 0xFF) * 60 + (addr >> 8 & 0xFF)) * 75 + (addr & 0xFF) - 150;
}

static uint8_t *rm_ptr(Cpu *c, uint32_t far) { return G(c, (far >> 16) * 16 + (far & 0xFFFF)); }

/* A device driver request (int 2Fh AX=1510h) at linear address req. */
static void cd_request(Cpu *c, uint8_t *req) {
    uint16_t status = 0x0100;                      /* done */
    switch (req[2]) {
    case 0x03: {                                   /* IOCTL input */
        uint32_t far;
        memcpy(&far, req + 0x0E, 4);
        uint8_t *cb = rm_ptr(c, far);
        uint32_t v;
        switch (cb[0]) {
        case 0x00: memset(cb + 1, 0, 4); break;    /* device header address */
        case 0x01:                                 /* head location */
            v = CD.play_lba + cd_position();
            if (cb[1]) v = cd_msf(v);
            memcpy(cb + 2, &v, 4);
            break;
        case 0x04:                                 /* audio channel info: channels 0-3 at full volume */
            for (int k = 0; k < 4; k++) { cb[1 + 2 * k] = (uint8_t)k; cb[2 + 2 * k] = 0xFF; }
            break;
        case 0x06: v = 0x00000310 | 0x200; memcpy(cb + 1, &v, 4); break;   /* door closed, audio, Red Book */
        case 0x07: cb[1] = 0; cb[2] = 0x08; break; /* sector size 2048 */
        case 0x08: memcpy(cb + 1, &CD.leadout, 4); break;
        case 0x09: cb[1] = 1; break;               /* media not changed */
        case 0x0A:                                 /* audio disk info */
            cb[1] = 1; cb[2] = (uint8_t)(CD.last >= CD.first ? CD.last : 1);
            v = cd_msf(CD.leadout); memcpy(cb + 3, &v, 4);
            break;
        case 0x0B: {                               /* audio track info */
            int t = cb[1];
            v = t >= 1 && t <= CD.last ? cd_msf(CD.start[t]) : 0;
            memcpy(cb + 2, &v, 4);
            cb[6] = t == 1 ? 0x40 : 0x00;          /* data / audio */
            break;
        }
        case 0x0C: {                               /* audio Q-channel */
            uint32_t lba = CD.play_lba + cd_position();
            int t = 1;
            for (int k = CD.first; k <= CD.last; k++) if (lba >= CD.start[k]) t = k;
            uint32_t r = lba - CD.start[t], abs = cd_msf(lba);   /* time in the track, on the disc */
            cb[1] = t == 1 ? 0x41 : 0x01;
            cb[2] = (uint8_t)((t / 10) << 4 | t % 10);
            cb[3] = 1;
            cb[4] = (uint8_t)(r / 4500); cb[5] = (uint8_t)(r / 75 % 60); cb[6] = (uint8_t)(r % 75);
            cb[7] = 0;
            cb[8] = (uint8_t)(abs >> 16); cb[9] = (uint8_t)(abs >> 8); cb[10] = (uint8_t)abs;
            break;
        }
        case 0x0F: {                               /* audio status */
            uint16_t paused = !CD.play_since && CD.played && CD.played < CD.play_len;
            memcpy(cb + 1, &paused, 2);
            v = cd_msf(CD.play_lba); memcpy(cb + 3, &v, 4);
            v = cd_msf(CD.play_lba + CD.play_len); memcpy(cb + 7, &v, 4);
            break;
        }
        default:
            if (H.trace) fprintf(stderr, "cd: IOCTL input %u\n", cb[0]);
        }
        break;
    }
    case 0x0C: case 0x0D: case 0x0E: case 0x83: break;   /* IOCTL output, open, close, seek */
    case 0x84: {                                   /* play audio */
        uint32_t start, n;
        memcpy(&start, req + 0x0E, 4);
        memcpy(&n, req + 0x12, 4);
        CD.play_lba = cd_lba(start, req[0x0D]);
        CD.play_len = n;
        CD.played = 0;
        CD.play_since = now_ns();
        if (H.trace) fprintf(stderr, "cd: play %u +%u\n", CD.play_lba, n);
        break;
    }
    case 0x85:                                     /* stop: first pauses, second resets */
        if (CD.play_since) { CD.played = cd_position(); CD.play_since = 0; }
        else CD.played = CD.play_len = 0;
        break;
    case 0x88:                                     /* resume */
        if (!CD.play_since && CD.played < CD.play_len) CD.play_since = now_ns();
        break;
    default:
        if (H.trace) fprintf(stderr, "cd: request %02x\n", req[2]);
        status = 0x8103;                           /* error: unknown command */
    }
    if (cd_playing()) status |= 0x0200;            /* busy */
    memcpy(req + 3, &status, 2);
}

/* DPMI 0300h: "real-mode" interrupt BL with the call structure at ES:EDI. */
static void rm_int(Cpu *c, uint32_t at) {
    uint8_t *rm = G(c, c->sbase[SEG_ES] + c->r[EDI]);
    uint32_t eax, ebx, ecx;
    uint16_t es, flags;
    memcpy(&eax, rm + 0x1C, 4);
    memcpy(&ebx, rm + 0x10, 4);
    memcpy(&ecx, rm + 0x18, 4);
    memcpy(&es, rm + 0x22, 2);
    memcpy(&flags, rm + 0x20, 2);
    flags &= (uint16_t)~1;
    if (BL(c) != 0x2F) die(c, "real-mode int %02xh AX=%04x at %x", BL(c), eax & 0xFFFF, at);
    switch (eax & 0xFFFF) {
    case 0x1500: ebx = 1; ecx = 3; break;          /* one CD drive, D: */
    case 0x150B: eax = (ecx & 0xFFFF) == 3; ebx = 0xADAD; break;
    case 0x150C: ebx = 0x020A; break;              /* MSCDEX 2.10 */
    case 0x150D: *G(c, es * 16u + (ebx & 0xFFFF)) = 3; break;
    case 0x1510: cd_request(c, G(c, es * 16u + (ebx & 0xFFFF))); break;
    default:
        if (H.trace) fprintf(stderr, "real-mode int 2Fh AX=%04x at %x: ignored\n", eax & 0xFFFF, at);
    }
    memcpy(rm + 0x1C, &eax, 4);
    memcpy(rm + 0x10, &ebx, 4);
    memcpy(rm + 0x18, &ecx, 4);
    memcpy(rm + 0x20, &flags, 2);
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
    case 0x0B: set_al(c, 0); break;                /* console input status: nothing waiting */
    case 0x4B:                                     /* exec (the FMV player via DOS/4GW): not run yet */
        if (H.trace) fprintf(stderr, "worms: exec %s: skipped\n", (const char *)G(c, c->r[EDX]));
        c->r[EAX] = 0;
        ok(c);
        break;
    case 0x4D: set16(c, EAX, 0); break;            /* its exit code: 0 */
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
    case 0x0300: rm_int(c, at); ok(c); break;
    case 0x0303: c->f.cf = 1; break;               /* no real-mode callbacks */
    case 0x0A00: fail(c, 0x8001); break;           /* no vendor API extensions */
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
        if (H.mode == 0x13) {
            video_init();
            vga_mode13(c);
            if (!(AL(c) & 0x80)) { memset(G(c, VGA_BASE), 0, 65536); memset(V.plane, 0, sizeof V.plane); }
        }
        break;
    case 0x10:                                     /* palette */
        switch (AL(c)) {
        case 0x00: case 0x01: case 0x02: case 0x03: break;    /* attribute controller, border */
        case 0x10: {
            uint8_t *d = H.dac + (BX(c) & 0xFF) * 3;
            d[0] = (c->r[EDX] >> 8) & 63; d[1] = (c->r[ECX] >> 8) & 63; d[2] = c->r[ECX] & 63;
            break;
        }
        case 0x12: case 0x17: {                    /* set / read a block of DAC entries at ES:EDX */
            uint32_t first = BX(c) & 0xFF, n = CX(c), at_buf = c->sbase[SEG_ES] + c->r[EDX];
            for (uint32_t k = 0; k < n * 3 && first * 3 + k < 768; k++) {
                if (AL(c) == 0x12) H.dac[first * 3 + k] = G(c, at_buf)[k] & 63;
                else G(c, at_buf)[k] = H.dac[first * 3 + k];
            }
            break;
        }
        default: die(c, "unhandled int 10h AX=%04x at %x", AX(c), at);
        }
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
    case 0x04: H.mouse_x = H.set_x = (int16_t)CX(c); H.mouse_y = H.set_y = (int16_t)DX(c); break;
    case 0x07: H.mx_min = (int16_t)CX(c); H.mx_max = (int16_t)DX(c); break;
    case 0x08: H.my_min = (int16_t)CX(c); H.my_max = (int16_t)DX(c); break;
    case 0x0C: H.mouse_mask = CX(c); H.mouse_handler = c->r[EDX]; break;
    case 0x0F: case 0x1A: case 0x1C: case 0x1D: break;
    default:
        die(c, "unhandled int 33h AX=%04x at %x", AX(c), at);
    }
}

/* INT 2Fh (multiplex) from protected mode */
static void int2f(Cpu *c, uint32_t at) {
    switch (AX(c)) {
    case 0x1686: set16(c, EAX, 0); break;          /* DPMI present */
    case 0x1600: set_al(c, 0); break;              /* no Windows enhanced mode */
    default:
        if (H.trace) fprintf(stderr, "int 2Fh AX=%04x at %x: ignored\n", AX(c), at);
    }
}

static void on_int(Cpu *c, int vec, uint32_t at) {
    if (H.trace) fprintf(stderr, "int %02xh ax=%04x bx=%04x cx=%04x dx=%04x at %x\n", vec, AX(c), BX(c), CX(c), DX(c), at);
    switch (vec) {
    case 0x21: int21(c, at); break;
    case 0x31: int31(c, at); break;
    case 0x10: int10(c, at); break;
    case 0x33: int33(c, at); break;
    case 0x2F: int2f(c, at); break;
    default: die(c, "unhandled int %02xh at %x", vec, at);
    }
}

/* ---- ports --------------------------------------------------------------------- */
static uint32_t on_in(Cpu *c, uint32_t port, int bytes) {
    (void)bytes;
    switch (port) {
    case 0x3DA: {                                  /* input status: retrace on a real 70 Hz clock */
        /* The game paces its frame loop (and with it the frame-counted
         * scroll delays) by waiting for vertical retrace.  Bit 3 is set for
         * the first tenth of each 1/70 s, like a VGA in mode 13h; bit 0
         * (display disabled) also flips on every read for horizontal waits. */
        pump(c);
        uint64_t phase = (now_ns() - H.start_ns) % (1000000000ull / 70);
        H.retrace ^= 0x01;
        return (H.retrace & 0x01) | (phase < 1000000000ull / 700 ? 0x09 : 0);
    }
    case 0x3C9: {
        uint8_t v = H.dac[(H.dac_r * 3 + H.dac_rc) % 768];
        if (++H.dac_rc == 3) { H.dac_rc = 0; H.dac_r = (H.dac_r + 1) & 0xFF; }
        return v;
    }
    case 0x60: return H.last_scan;
    case 0x61: case 0x21: case 0xA1: return 0;
    case 0x3C4: return V.seq_i;
    case 0x3C5: return V.seq[V.seq_i & 7];
    case 0x3CE: return V.gc_i;
    case 0x3CF: return V.gc[V.gc_i & 15];
    case 0x3D4: return V.crtc_i;
    case 0x3D5: return V.crtc[V.crtc_i & 31];
    case 0x3CC: return 0x63;                       /* misc output */
    default:
        if (H.trace) fprintf(stderr, "in %x\n", port);
        return 0xFF;
    }
}

static void on_out(Cpu *c, uint32_t port, uint32_t v, int bytes) {
    if (bytes == 2 && (port == 0x3C4 || port == 0x3CE || port == 0x3D4)) {   /* out dx, ax: index, data */
        on_out(c, port, v & 0xFF, 1);
        on_out(c, port + 1, v >> 8 & 0xFF, 1);
        return;
    }
    switch (port) {
    case 0x3C4: V.seq_i = v & 0xFF; break;
    case 0x3C5:
        V.seq[V.seq_i & 7] = v & 0xFF;
        if ((V.seq_i & 7) == 4) vga_update_chain(c);
        break;
    case 0x3CE: V.gc_i = v & 0xFF; break;
    case 0x3CF: V.gc[V.gc_i & 15] = v & 0xFF; break;
    case 0x3D4: V.crtc_i = v & 0xFF; break;
    case 0x3D5: V.crtc[V.crtc_i & 31] = v & 0xFF; break;
    case 0x3C0: case 0x3C2: break;                 /* attribute controller, misc output */
    case 0x43:                                     /* PIT mode: channel 0 lo/hi reload */
        if ((v & 0xC0) == 0) H.pit_lo_next = 1;
        break;
    case 0x40:
        if (H.pit_lo_next) H.pit_div = (H.pit_div & 0xFF00) | (v & 0xFF);
        else H.pit_div = (H.pit_div & 0x00FF) | (v & 0xFF) << 8;
        H.pit_lo_next = !H.pit_lo_next;
        break;
    case 0x20: break;                              /* EOI */
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

/* Every TICK_BRANCHES backward branches: interrupts arrive between
 * instructions, like on the hardware.  The lifted code keeps registers in
 * locals, so c->r[ESP] may be stale here; handlers run on their own stack. */
static void on_budget(Cpu *c, uint32_t at) {
    c->budget = TICK_BRANCHES;
    if (H.in_callback) return;
    uint32_t esp = c->r[ESP];
    c->r[ESP] = ISR_STACK;
    pump(c);
    c->r[ESP] = esp;
}

/* ---- indirect calls, traps ------------------------------------------------------ */
static void dispatch(Cpu *c, uint32_t target, uint32_t at) {
    if (target == BIOS_IRET) {                     /* chained-to original handler: iret */
        uint32_t esp = c->r[ESP];
        c->ret_to = rd32(c, esp);
        x86_unpack_flags(&c->f, rd32(c, esp + 8));
        c->r[ESP] = esp + 12;
        return;
    }
    unsigned lo = 0, hi = lifted_table_len;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (lifted_table[mid].addr < target) lo = mid + 1; else hi = mid;
    }
    if (lo < lifted_table_len && lifted_table[lo].addr == target) { lifted_table[lo].fn(c); return; }
    die(c, "call to %x (no lifted function) from %x", target, at);
}

static void on_trap(Cpu *c, uint32_t at, const char *what) {
    fprintf(stderr, "worms: untranslated instruction at %x: %s\n", at, what);
    (void)c;
}

/* ---- functions replaced by the runtime (lift.py HLE) ------------------------- */
static void on_hle(Cpu *c, uint32_t func) {
    switch (func) {
    case 0x47E02: {      /* int386x core: ESI = vector, EBX -> SREGS, EDI -> REGS in */
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
        return;
    }
}

static const Hooks HOOKS = { on_int, on_in, on_out, dispatch, on_trap, sel_base, on_hle, NULL, vga_mem_read, vga_mem_write, on_budget };

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
    fprintf(stderr, "worms: dumped entry state of %x to %s\n", addr, path);
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
    static const char env[] = "PATH=C:\\\0COMSPEC=C:\\COMMAND.COM\0BLASTER=\0\0\x01\0D:\\WRMS.EXE\0";
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
    H.cd_dir = argc > 2 ? argv[2] : "work/cd";
    const char *image = argc > 3 ? argv[3] : "build/image.bin";
    H.trace = getenv("WAR_TRACE") != NULL;
    if (getenv("WAR_SNAPSHOT")) H.snapshot_ms = (uint64_t)(atof(getenv("WAR_SNAPSHOT")) * 1000);
    parse_script(getenv("WAR_INPUT"));
    H.start_ns = now_ns();
    cd_load(getenv("WORMS_AUDIO") ? getenv("WORMS_AUDIO") : "work/audio.json");
    audio_open();
    if (getenv("WAR_WAV") && (wav_out = fopen(getenv("WAR_WAV"), "wb"))) {
        static const uint32_t room[11];
        fwrite(room, 4, 11, wav_out);                 /* header written by wav_close */
        atexit(wav_close);
    }
    H.mx_max = 639; H.my_max = 199;
    H.drive = 3;                                   /* WORMS.EXE starts WRMS.EXE from the CD */

    static Cpu c;
    memset(&c, 0, sizeof c);
    c.mem = calloc(1, MEM_SIZE);
    c.mem_size = MEM_SIZE;
    c.budget = TICK_BRANCHES;
    for (int v = 0; v < 256; v++) H.pm_vector[v] = BIOS_IRET;
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
    x86_fninit(&c);

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
        fprintf(stderr, "worms: entry point returned\n");
        return 0;
    }
    if (why == STOP_EXIT) return (int)c.fault_addr;
    const char *names[] = {"ok", "memory fault", "budget", "divide error", "bad return", "trap", "exit"};
    fprintf(stderr, "worms: stopped (%s) at %x\n  eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x\n",
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
