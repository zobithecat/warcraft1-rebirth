/* blitview: play WarCraft's intro frames through the game's own RLE blitter,
 * lifted from x86 to C and compiled natively for arm64.
 *
 * Each frame in the .wcf file (tools/pack_frames.py) is one call of the
 * blitter captured in DOSBox-X: its registers, RLE source, destination
 * buffer before the call, and the buffer DOSBox-X produced.  The viewer
 * rebuilds that guest memory, runs the lifted function natively, checks the
 * result against DOSBox-X and shows it.
 *
 *   blitview FRAMES.wcf              window: Space pause, Left/Right step, Esc quit
 *   blitview --check FRAMES.wcf      decode every frame, verify, print timings
 *   blitview --ppm N OUT.ppm FRAMES.wcf   write frame N as an image
 */
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "x86.h"

int lifted_run(uint32_t addr, uint32_t *regs, uint8_t *mem, uint32_t mem_size,
               uint32_t ro_lo, uint32_t ro_hi, int64_t budget, uint32_t *fault_addr);

#define GUEST_MEM   0x1000000u
#define BUDGET      100000000
#define SCALE       3
#define FRAME_MS    100
#define BENCH_RUNS  200

typedef struct {
    uint32_t regs_in[8], regs_out[8], ret;
    uint32_t src_addr, src_len, dst_addr, dst_len;
    const uint8_t *pal, *src, *before, *after;
} Frame;

typedef struct {
    uint32_t func, code_lo, code_hi, count;
    Frame *frames;
    uint8_t *blob;
} Movie;

typedef struct {
    int ok;              /* lifted_run returned STOP_OK */
    int matches;         /* buffer and registers equal DOSBox-X's */
    double usec;         /* one native call */
} Result;

static uint8_t *guest;

static uint32_t u32(const uint8_t **p) {
    uint32_t v;
    memcpy(&v, *p, 4);
    *p += 4;
    return v;
}

static int load_movie(const char *path, Movie *m) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    m->blob = malloc((size_t)size);
    if (!m->blob || fread(m->blob, 1, (size_t)size, f) != (size_t)size) { fclose(f); return -1; }
    fclose(f);

    const uint8_t *p = m->blob, *end = m->blob + size;
    if (u32(&p) != 0x31464357) { fprintf(stderr, "%s: not a WCF1 file\n", path); return -1; }
    m->count = u32(&p);
    m->func = u32(&p);
    m->code_lo = u32(&p);
    m->code_hi = u32(&p);
    m->frames = calloc(m->count, sizeof(Frame));
    for (uint32_t i = 0; i < m->count; i++) {
        Frame *fr = &m->frames[i];
        for (int r = 0; r < 8; r++) fr->regs_in[r] = u32(&p);
        for (int r = 0; r < 8; r++) fr->regs_out[r] = u32(&p);
        fr->ret = u32(&p);
        fr->src_addr = u32(&p); fr->src_len = u32(&p);
        fr->dst_addr = u32(&p); fr->dst_len = u32(&p);
        fr->pal = p;    p += 768;
        fr->src = p;    p += fr->src_len;
        fr->before = p; p += fr->dst_len;
        fr->after = p;  p += fr->dst_len;
        if (p > end) { fprintf(stderr, "%s: truncated at frame %u\n", path, i); return -1; }
    }
    return 0;
}

static double now_usec(void) {
    return (double)clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000.0;
}

/* Rebuild the guest memory the call needs and run the lifted blitter. */
static Result decode(const Movie *m, const Frame *fr) {
    memcpy(guest + fr->src_addr, fr->src, fr->src_len);
    memcpy(guest + fr->dst_addr, fr->before, fr->dst_len);
    memcpy(guest + fr->regs_in[ESP], &fr->ret, 4);      /* return address on the stack */
    uint32_t regs[8], fault = 0;
    memcpy(regs, fr->regs_in, sizeof regs);

    double t0 = now_usec();
    int why = lifted_run(m->func, regs, guest, GUEST_MEM, m->code_lo, m->code_hi, BUDGET, &fault);
    double t1 = now_usec();

    Result r = { why == STOP_OK, 0, t1 - t0 };
    r.matches = r.ok && memcmp(guest + fr->dst_addr, fr->after, fr->dst_len) == 0 &&
                memcmp(regs, fr->regs_out, sizeof regs) == 0;
    return r;
}

static uint32_t frame_width(const Frame *fr) { return fr->regs_in[ECX]; }   /* ecx = row width */

static void to_rgb(const Frame *fr, uint32_t *argb) {
    uint32_t lut[256];
    for (int i = 0; i < 256; i++) {
        const uint8_t *c = fr->pal + i * 3;
        lut[i] = 0xFF000000u | (uint32_t)(c[0] * 255 / 63) << 16 | (uint32_t)(c[1] * 255 / 63) << 8 |
                 (uint32_t)(c[2] * 255 / 63);
    }
    const uint8_t *px = guest + fr->dst_addr;
    for (uint32_t i = 0; i < fr->dst_len; i++) argb[i] = lut[px[i]];
}

static int check(const Movie *m) {
    int bad = 0;
    double total = 0;
    for (uint32_t i = 0; i < m->count; i++) {
        const Frame *fr = &m->frames[i];
        Result r = decode(m, fr);
        double best = r.usec;
        for (int k = 0; k < BENCH_RUNS; k++) {
            Result again = decode(m, fr);
            if (again.usec < best) best = again.usec;
        }
        total += best;
        bad += !r.matches;
        printf("frame %3u: %ux%u  %7.1f us  %s\n", i, frame_width(fr), fr->dst_len / frame_width(fr), best,
               r.matches ? "identical to DOSBox-X" : (r.ok ? "DIFFERS from DOSBox-X" : "stopped"));
    }
    printf("%u frames, %d mismatching, mean %.1f us per frame (native arm64)\n",
           m->count, bad, total / m->count);
    return bad ? 1 : 0;
}

static int write_ppm(const Movie *m, uint32_t n, const char *path) {
    if (n >= m->count) { fprintf(stderr, "frame %u out of range (%u frames)\n", n, m->count); return 1; }
    const Frame *fr = &m->frames[n];
    Result r = decode(m, fr);
    uint32_t w = frame_width(fr), h = fr->dst_len / w;
    uint32_t *argb = malloc(fr->dst_len * 4);
    to_rgb(fr, argb);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return 1; }
    fprintf(f, "P6\n%u %u\n255\n", w, h);
    for (uint32_t i = 0; i < w * h; i++) {
        uint8_t rgb[3] = { argb[i] >> 16, argb[i] >> 8, argb[i] };
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
    free(argb);
    printf("frame %u -> %s (%s DOSBox-X)\n", n, path, r.matches ? "identical to" : "DIFFERS from");
    return r.matches ? 0 : 1;
}

static int view(const Movie *m) {
    if (SDL_Init(SDL_INIT_VIDEO) != 0) { fprintf(stderr, "SDL_Init: %s\n", SDL_GetError()); return 1; }
    uint32_t max_len = 0;                      /* frames differ in size (320x144 cinematics, 320x200 screens) */
    for (uint32_t k = 0; k < m->count; k++)
        if (m->frames[k].dst_len > max_len) max_len = m->frames[k].dst_len;
    uint32_t *argb = malloc((size_t)max_len * 4);

    const Frame *f0 = &m->frames[0];
    int w = (int)frame_width(f0), h = (int)(f0->dst_len / frame_width(f0));
    SDL_Window *win = SDL_CreateWindow("blitview", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                       w * SCALE, h * SCALE, SDL_WINDOW_ALLOW_HIGHDPI);
    SDL_Renderer *ren = win ? SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC) : NULL;
    SDL_Texture *tex = NULL;
    int tex_w = 0, tex_h = 0;
    if (!win || !ren || !argb) { fprintf(stderr, "SDL: %s\n", SDL_GetError()); return 1; }

    uint32_t i = 0, shown = UINT32_MAX;
    int paused = 0, running = 1;
    Uint32 next = SDL_GetTicks();
    while (running) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) running = 0;
            if (e.type == SDL_KEYDOWN) {
                switch (e.key.keysym.sym) {
                case SDLK_ESCAPE: case SDLK_q: running = 0; break;
                case SDLK_SPACE: paused = !paused; break;
                case SDLK_RIGHT: i = (i + 1) % m->count; paused = 1; break;
                case SDLK_LEFT: i = (i + m->count - 1) % m->count; paused = 1; break;
                }
            }
        }
        if (!paused && SDL_GetTicks() >= next) {
            i = (shown == UINT32_MAX) ? 0 : (i + 1) % m->count;
            next = SDL_GetTicks() + FRAME_MS;
        }
        if (i != shown) {
            const Frame *fr = &m->frames[i];
            w = (int)frame_width(fr);
            h = (int)(fr->dst_len / frame_width(fr));
            if (w != tex_w || h != tex_h) {
                if (tex) SDL_DestroyTexture(tex);
                tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, w, h);
                if (!tex) { fprintf(stderr, "SDL: %s\n", SDL_GetError()); return 1; }
                SDL_SetWindowSize(win, w * SCALE, h * SCALE);
                tex_w = w;
                tex_h = h;
            }
            Result r = decode(m, fr);
            to_rgb(fr, argb);
            SDL_UpdateTexture(tex, NULL, argb, w * 4);
            char title[160];
            snprintf(title, sizeof title, "WarCraft intro via lifted arm64 blitter  |  frame %u/%u  |  %.1f us  |  %s%s",
                     i + 1, m->count, r.usec, r.matches ? "identical to DOSBox-X" : "DIFFERS from DOSBox-X",
                     paused ? "  |  paused" : "");
            SDL_SetWindowTitle(win, title);
            shown = i;
        }
        SDL_RenderClear(ren);
        SDL_RenderCopy(ren, tex, NULL, NULL);
        SDL_RenderPresent(ren);
        SDL_Delay(5);
    }
    free(argb);
    SDL_DestroyTexture(tex);
    SDL_DestroyRenderer(ren);
    SDL_DestroyWindow(win);
    SDL_Quit();
    return 0;
}

static int usage(void) {
    fprintf(stderr, "usage: blitview [--check | --ppm N OUT.ppm] FRAMES.wcf\n");
    return 2;
}

int main(int argc, char *argv[]) {
    if (argc < 2) return usage();
    const char *path = argv[argc - 1];
    Movie m = {0};
    guest = calloc(1, GUEST_MEM);
    if (!guest || load_movie(path, &m) != 0 || m.count == 0) return 1;
    if (argc == 3 && strcmp(argv[1], "--check") == 0) return check(&m);
    if (argc == 5 && strcmp(argv[1], "--ppm") == 0) return write_ppm(&m, (uint32_t)atoi(argv[2]), argv[3]);
    if (argc == 2) return view(&m);
    return usage();
}
