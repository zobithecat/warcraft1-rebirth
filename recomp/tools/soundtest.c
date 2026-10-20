/* Offline renders through runtime/sound.c, for checking it against DOSBox-X.
 * Build: make build/soundtest  (sound.c with -DSOUND_TRACE)
 *
 *   soundtest song GAME_DIR song.xmi out.wav SECONDS [regs.log]
 *       play an XMIDI file image with the AIL-style driver; optionally log
 *       every OPL register write ("ms reg value", notes as "# note ...")
 *   soundtest regs GAME_DIR regs.log out.wav SECONDS
 *       play a register log (tools/soundcmp.py dro2log) on the OPL model alone
 */
#include "sound.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern FILE *snd_trace;
void snd_opl_write(int reg, int v);
double snd_opl_sample(void);

static FILE *wav_open(const char *path, uint32_t rate, uint32_t chans, uint32_t frames) {
    FILE *o = fopen(path, "wb");
    if (!o) { perror(path); exit(1); }
    uint32_t hdr[11] = { 0x46464952, 36 + frames * chans * 2, 0x45564157, 0x20746D66, 16, 0x00010001 + (chans - 1) * 0x10000,
                         rate, rate * chans * 2, (chans * 2) | 16u << 16, 0x61746164, frames * chans * 2 };
    fwrite(hdr, 4, 11, o);
    return o;
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: soundtest song|regs GAME_DIR IN OUT.wav SECONDS [regs.log]\n"); return 2; }
    snd_init(48000, argv[2]);
    double secs = atof(argv[5]);
    if (!strcmp(argv[1], "song")) {
        static uint8_t buf[1 << 16];
        FILE *f = fopen(argv[3], "rb");
        if (!f) { perror(argv[3]); return 1; }
        size_t n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        if (argc > 6) snd_trace = fopen(argv[6], "w");
        snd_music_start(buf, (uint32_t)n, 0);
        uint32_t frames = (uint32_t)(secs * 48000);
        FILE *o = wav_open(argv[4], 48000, 2, frames);
        static int16_t pcm[2 * 4800];
        for (uint32_t i = 0; i < frames; i += 4800) {
            uint32_t k = frames - i < 4800 ? frames - i : 4800;
            snd_render(pcm, (int)k);
            fwrite(pcm, 4, k, o);
        }
        fclose(o);
    } else {
        FILE *in = fopen(argv[3], "r");
        if (!in) { perror(argv[3]); return 1; }
        uint32_t total = (uint32_t)(secs * 49716);
        FILE *o = wav_open(argv[4], 49716, 1, total);
        double t;
        int r, v;
        char line[128];
        int have = 0;
        for (uint32_t i = 0; i < total; i++) {
            double now = i * 1000.0 / 49716;
            for (;;) {
                if (!have) {
                    if (!fgets(line, sizeof line, in)) break;
                    if (line[0] == '#' || sscanf(line, "%lf %x %x", &t, &r, &v) != 3) continue;
                    have = 1;
                }
                if (t > now) break;
                if (r < 0x100) snd_opl_write(r, v);
                have = 0;
            }
            double s = snd_opl_sample() * 0.167 * 32767;       /* sound.c's MUSIC_GAIN */
            int16_t x = (int16_t)(s > 32767 ? 32767 : s < -32768 ? -32768 : s);
            fwrite(&x, 2, 1, o);
        }
        fclose(o);
    }
    return 0;
}
