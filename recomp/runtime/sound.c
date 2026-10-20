/* Sound for the recompiled game (see sound.h).
 *
 *   effects  WAV / Creative VOC file images (8-bit 11 kHz in WarCraft), four
 *            voices like the game's AIL setup, linear resampling
 *   music    XMIDI (120 Hz ticks, notes carry their duration, FOR/NEXT
 *            loops) -> what AIL's ADLIB.MDI does with it: timbres from the
 *            game's global timbre library DRIVERS/WARCRAFT.AD on nine OPL2
 *            voices, percussion (channel 10) from bank 127 keyed by note
 *   OPL2     a small YM3812 model written for this: two-operator FM, four
 *            waveforms, envelopes timed after the YM3812 manual's tables,
 *            KSL, tremolo, vibrato, feedback; run at the chip's 49716 Hz and
 *            resampled
 *
 * Everything runs on the game's thread: game.c calls snd_render() from its
 * frame pump with the number of frames that wall time asks for. */
#include "sound.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int out_rate = 48000;

/* ======================================================================= OPL2 */
#define OPL_RATE 49716.0

typedef struct {
    uint8_t r20, r40, r60, r80, rE0;
    double phase;           /* cycles */
    double env;             /* attenuation from the envelope, dB (0..96) */
    int stage;              /* EG_* */
    double out1, out2;      /* last two outputs, for feedback */
} OplOp;

enum { EG_OFF, EG_ATTACK, EG_DECAY, EG_SUSTAIN, EG_RELEASE };

typedef struct {
    uint16_t fnum;
    uint8_t block, key, rC0;
    OplOp op[2];            /* modulator, carrier */
} OplChan;

static struct {
    OplChan ch[9];
    uint8_t rBD;
    double lfo_am, lfo_vib; /* phases, cycles */
} opl;

static float sin_tab[1024];
static float db_tab[96 * 32 + 1];      /* attenuation in 1/32 dB -> amplitude */

/* Operator slots of each channel (register offsets 0x00-0x15). */
static const uint8_t slot_of[9][2] = {
    {0x00, 0x03}, {0x01, 0x04}, {0x02, 0x05}, {0x08, 0x0B}, {0x09, 0x0C},
    {0x0A, 0x0D}, {0x10, 0x13}, {0x11, 0x14}, {0x12, 0x15},
};

static OplOp *op_at(int slot) {
    for (int c = 0; c < 9; c++)
        for (int k = 0; k < 2; k++)
            if (slot_of[c][k] == slot) return &opl.ch[c].op[k];
    return NULL;
}

static void opl_reset(void) {
    memset(&opl, 0, sizeof opl);
    for (int c = 0; c < 9; c++)
        for (int k = 0; k < 2; k++) { opl.ch[c].op[k].env = 96; opl.ch[c].op[k].stage = EG_OFF; }
}

#ifdef SOUND_TRACE                      /* register log for comparing with a DOSBox-X .dro */
FILE *snd_trace;
double snd_trace_ms;
#endif

static void opl_write(int reg, uint8_t v) {
#ifdef SOUND_TRACE
    if (snd_trace) fprintf(snd_trace, "%.1f %02x %02x\n", snd_trace_ms, reg, v);
#endif
    int base = reg & 0xE0;
    if (reg == 0xBD) { opl.rBD = v; return; }
    if (base == 0x20 || base == 0x40 || base == 0x60 || base == 0x80 || base == 0xE0) {
        OplOp *o = op_at(reg & 0x1F);
        if (!o) return;
        if (base == 0x20) o->r20 = v;
        else if (base == 0x40) o->r40 = v;
        else if (base == 0x60) o->r60 = v;
        else if (base == 0x80) o->r80 = v;
        else o->rE0 = v;
        return;
    }
    int c = reg & 0x0F;
    if (c > 8) return;
    OplChan *ch = &opl.ch[c];
    if ((reg & 0xF0) == 0xA0) { ch->fnum = (uint16_t)((ch->fnum & 0x300) | v); return; }
    if ((reg & 0xF0) == 0xC0) { ch->rC0 = v; return; }
    if ((reg & 0xF0) == 0xB0) {
        int key = (v >> 5) & 1;
        ch->fnum = (uint16_t)((ch->fnum & 0xFF) | (v & 3) << 8);
        ch->block = (v >> 2) & 7;
        for (int k = 0; k < 2; k++) {
            OplOp *o = &ch->op[k];
            if (key && !ch->key) { o->stage = EG_ATTACK; o->phase = 0; }
            else if (!key && ch->key && o->stage != EG_OFF) o->stage = EG_RELEASE;
        }
        ch->key = (uint8_t)key;
    }
}

/* Effective envelope rate 0..63 for a 4-bit rate register. */
static int eg_rate(const OplChan *ch, const OplOp *o, int r) {
    if (!r) return 0;
    int kcode = ch->block << 1 | (ch->fnum >> 9 & 1);
    int rate = 4 * r + ((o->r20 & 0x10) ? kcode : kcode >> 2);
    return rate > 63 ? 63 : rate;
}

/* Relative speed of a rate; rate 4 (register 1, no key scaling) is 1.  The
 * YM3812 manual's times halve per register step, with quarter steps between. */
static double eg_speed(int rate) { return ldexp(1.0 + (rate & 3) / 4.0, (rate >> 2) - 1); }

#define ATTACK_96DB_S 2.82624     /* attack time, register 1 */
#define DECAY_96DB_S  39.28064    /* decay/release time over 96 dB, register 1 */

static void eg_step(const OplChan *ch, OplOp *o) {
    const double dt = 1.0 / OPL_RATE;
    switch (o->stage) {
    case EG_ATTACK: {
        int rate = eg_rate(ch, o, o->r60 >> 4);
        if (rate >= 60) o->env = 0;
        else if (rate) o->env *= exp(-log(512.0) * eg_speed(rate) / ATTACK_96DB_S * dt);
        if (o->env < 0.1875) { o->env = 0; o->stage = EG_DECAY; }
        break;
    }
    case EG_DECAY: {
        double sl = (o->r80 >> 4) == 15 ? 93.0 : (o->r80 >> 4) * 3.0;
        int rate = eg_rate(ch, o, o->r60 & 15);
        if (rate) o->env += 96.0 / DECAY_96DB_S * eg_speed(rate) * dt;
        if (o->env >= sl) { o->env = sl; o->stage = (o->r20 & 0x20) ? EG_SUSTAIN : EG_RELEASE; }
        break;
    }
    case EG_SUSTAIN:
        break;
    case EG_RELEASE: {
        int rate = eg_rate(ch, o, o->r80 & 15);
        if (rate) o->env += 96.0 / DECAY_96DB_S * eg_speed(rate) * dt;
        if (o->env >= 96) { o->env = 96; o->stage = EG_OFF; }
        break;
    }
    default:
        break;
    }
}

/* Key scale level: attenuation in dB at 6 dB/octave, before the KSL setting. */
static double ksl_db(const OplChan *ch) {
    static const double tab[16] = { 0, 18, 24, 27.75, 30, 32.25, 33.75, 35.25,
                                    36, 37.5, 38.25, 39, 39.75, 40.5, 41.25, 42 };
    double v = tab[ch->fnum >> 6] - 6.0 * (7 - ch->block);
    return v > 0 ? v : 0;
}

static double op_level(const OplChan *ch, const OplOp *o, double am) {
    static const double ksl_scale[4] = { 0, 0.5, 0.25, 1.0 };   /* 0, 3, 1.5, 6 dB/octave */
    double att = o->env + (o->r40 & 0x3F) * 0.75 + ksl_db(ch) * ksl_scale[o->r40 >> 6];
    if (o->r20 & 0x80) att += am;
    if (att >= 96) return 0;
    return db_tab[(int)(att * 32)];
}

static double wave(int w, double phase) {
    double f = phase - floor(phase);
    double s = sin_tab[(int)(f * 1024) & 1023];
    switch (w & 3) {
    case 1: return s > 0 ? s : 0;                     /* half sine */
    case 2: return fabs(s);                           /* absolute sine */
    case 3: return (f < 0.25 || (f >= 0.5 && f < 0.75)) ? fabs(s) : 0;   /* pulse sine */
    default: return s;
    }
}

static double opl_sample(void) {
    static const double mult[16] = { 0.5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 12, 12, 15, 15 };
    opl.lfo_am += 3.7 / OPL_RATE;
    opl.lfo_vib += 6.1 / OPL_RATE;
    double tri_am = 1.0 - fabs(2.0 * (opl.lfo_am - floor(opl.lfo_am)) - 1.0);   /* 0..1 */
    double am = tri_am * ((opl.rBD & 0x80) ? 4.8 : 1.0);
    double vib = sin(2 * M_PI * opl.lfo_vib) * ((opl.rBD & 0x40) ? 14.0 : 7.0);  /* cents */
    double sum = 0;
    for (int c = 0; c < 9; c++) {
        OplChan *ch = &opl.ch[c];
        OplOp *m = &ch->op[0], *k = &ch->op[1];
        if (m->stage == EG_OFF && k->stage == EG_OFF) continue;
        double f = ch->fnum * ldexp(OPL_RATE, ch->block - 20);
        for (int i = 0; i < 2; i++) {
            OplOp *o = &ch->op[i];
            double fo = f * mult[o->r20 & 15];
            if (o->r20 & 0x40) fo *= exp2(vib / 1200.0);
            o->phase += fo / OPL_RATE;
            if (o->phase > 1e6) o->phase -= floor(o->phase);
            eg_step(ch, o);
        }
        int fb = (ch->rC0 >> 1) & 7;
        double fbmod = fb ? (m->out1 + m->out2) * ldexp(1.0, fb - 7) : 0;
        double mo = wave(m->rE0, m->phase + fbmod) * op_level(ch, m, am);
        m->out2 = m->out1;
        m->out1 = mo;
        if (ch->rC0 & 1) sum += mo + wave(k->rE0, k->phase) * op_level(ch, k, am);
        else sum += wave(k->rE0, k->phase + 4.0 * mo) * op_level(ch, k, am);
    }
    return sum;
}

#ifdef SOUND_TRACE                      /* test access to the bare chip */
void snd_opl_write(int reg, int v) { opl_write(reg, (uint8_t)v); }
double snd_opl_sample(void) { return opl_sample(); }
#endif

/* ========================================================== AIL's AdLib driver */
typedef struct { const uint8_t *t; } Timbre;           /* 14-byte GTL record */
static uint8_t *gtl;                                   /* DRIVERS/WARCRAFT.AD */
static size_t gtl_len;

static const uint8_t *find_timbre(int patch, int bank) {
    if (!gtl) return NULL;
    for (size_t i = 0; i + 6 <= gtl_len; i += 6) {
        if (gtl[i] == 0xFF && gtl[i + 1] == 0xFF) break;
        if (gtl[i] == patch && gtl[i + 1] == bank) {
            uint32_t off = (uint32_t)gtl[i + 2] | gtl[i + 3] << 8 | gtl[i + 4] << 16 | (uint32_t)gtl[i + 5] << 24;
            if (off + 14 <= gtl_len) return gtl + off;
            return NULL;
        }
    }
    return NULL;
}

typedef struct {
    int program, bank, volume, expression, bend, sustain;
} MidiChan;

typedef struct {
    int on, chan, note, key, vel, sustained;
    uint32_t age;
    const uint8_t *timbre;
} Voice;

static MidiChan mch[16];
static Voice voice[9];
static uint32_t voice_clock;

static void midi_reset(void) {
    for (int i = 0; i < 16; i++) mch[i] = (MidiChan){ 0, 0, 127, 127, 8192, 0 };
    memset(voice, 0, sizeof voice);
    opl_reset();
    opl_write(0x01, 0x20);           /* waveform select enable */
    opl_write(0xBD, 0xC0);           /* deep tremolo and vibrato, as AIL's driver sets them */
}

/* Output level scaled like AdLib MIDI drivers do: (63 - TL) shrinks with level. */
static uint8_t scaled_tl(uint8_t r40, int level) {
    int tl = r40 & 0x3F;
    tl = 63 - (63 - tl) * level / 127;
    return (uint8_t)((r40 & 0xC0) | tl);
}

/* AIL's velocity sensitivity: velocity / 8 picks a level between 82 and 127. */
static const uint8_t vel_graph[16] = { 82, 85, 88, 91, 94, 97, 100, 103, 106, 109, 112, 115, 118, 121, 124, 127 };

static void voice_volume(int v) {
    Voice *vo = &voice[v];
    const MidiChan *m = &mch[vo->chan];
    int level = (vel_graph[vo->vel >> 3] * m->volume * m->expression + 127 * 127 / 2) / (127 * 127);   /* rounded, as AIL does */
    const uint8_t *t = vo->timbre;
    opl_write(0x40 + slot_of[v][1], scaled_tl(t[10], level));
    opl_write(0x40 + slot_of[v][0], (t[8] & 1) ? scaled_tl(t[4], level) : t[4]);
}

static void voice_pitch(int v, int keyon) {
    Voice *vo = &voice[v];
    double note = vo->key + (mch[vo->chan].bend - 8192) / 8192.0 * 2.0;   /* +-2 semitones */
    double f = 440.0 * exp2((note - 69) / 12.0);
    int block = 0;
    double fnum = f * ldexp(1.0, 20) / OPL_RATE;
    while (fnum >= 1024 && block < 7) { fnum /= 2; block++; }
    int fn = (int)(fnum + 0.5);
    if (fn > 1023) fn = 1023;
    opl_write(0xA0 + v, (uint8_t)fn);
    opl_write(0xB0 + v, (uint8_t)((keyon ? 0x20 : 0) | block << 2 | fn >> 8));
}

static void voice_off(int v) {
    voice[v].on = 0;
    voice[v].sustained = 0;
    opl_write(0xB0 + v, opl.ch[v].block << 2 | (opl.ch[v].fnum >> 8));
}

static void note_on(int ch, int note, int vel) {
    const uint8_t *t;
    int key;
    if (ch == 9) {                                  /* percussion: bank 127, patch = note */
        t = find_timbre(note, 127);
        if (!t) return;
        key = t[2];
    } else {
        t = find_timbre(mch[ch].program, mch[ch].bank);
        if (!t) t = find_timbre(mch[ch].program, 0);
        if (!t) return;
        key = note + (int8_t)t[2];
    }
    int v = -1;
    uint32_t best = UINT32_MAX;
    for (int i = 0; i < 9; i++)                     /* a free voice that has rung longest */
        if (!voice[i].on && voice[i].age < best) { best = voice[i].age; v = i; }
    if (v < 0) {                                    /* steal the oldest note */
        best = UINT32_MAX;
        for (int i = 0; i < 9; i++)
            if (voice[i].age < best) { best = voice[i].age; v = i; }
        voice_off(v);
    }
    voice[v] = (Voice){ 1, ch, note, key, vel, 0, ++voice_clock, t };
#ifdef SOUND_TRACE
    if (snd_trace) fprintf(snd_trace, "# note ch=%d note=%d vel=%d vol=%d expr=%d car=%02x mod=%02x con=%d\n",
                           ch, note, vel, mch[ch].volume, mch[ch].expression, t[10], t[4], t[8] & 1);
#endif
    int s0 = slot_of[v][0], s1 = slot_of[v][1];
    opl_write(0xB0 + v, 0);                         /* key off first so the envelope restarts */
    opl_write(0x20 + s0, t[3]); opl_write(0x60 + s0, t[5]); opl_write(0x80 + s0, t[6]); opl_write(0xE0 + s0, t[7]);
    opl_write(0x20 + s1, t[9]); opl_write(0x60 + s1, t[11]); opl_write(0x80 + s1, t[12]); opl_write(0xE0 + s1, t[13]);
    opl_write(0xC0 + v, t[8]);
    voice_volume(v);
    voice_pitch(v, 1);
}

static void note_off(int ch, int note) {
    for (int v = 0; v < 9; v++)
        if (voice[v].on && voice[v].chan == ch && voice[v].note == note) {
            if (mch[ch].sustain) voice[v].sustained = 1;
            else voice_off(v);
        }
}

static void all_notes_off(void) {
    for (int v = 0; v < 9; v++) if (voice[v].on) voice_off(v);
}

static void controller(int ch, int cc, int val) {
    MidiChan *m = &mch[ch];
    switch (cc) {
    case 7: case 11:
        if (cc == 7) m->volume = val; else m->expression = val;
        for (int v = 0; v < 9; v++) if (voice[v].on && voice[v].chan == ch) voice_volume(v);
        break;
    case 64:
        m->sustain = val >= 64;
        if (!m->sustain)
            for (int v = 0; v < 9; v++) if (voice[v].on && voice[v].chan == ch && voice[v].sustained) voice_off(v);
        break;
    case 114: m->bank = val; break;                 /* XMIDI patch bank select */
    case 121: m->volume = 127; m->expression = 127; m->bend = 8192; m->sustain = 0; break;
    case 123:
        for (int v = 0; v < 9; v++) if (voice[v].on && voice[v].chan == ch) voice_off(v);
        break;
    default: break;
    }
}

/* ============================================================== XMIDI player */
#define MAX_PENDING 256

static struct {
    uint8_t *data;          /* our copy of the file image */
    const uint8_t *ev;      /* EVNT chunk */
    uint32_t len, pos, wait;
    int playing;
    struct { uint32_t pos; int count; } loop[4];
    int loops;
    struct { uint8_t ch, note; uint32_t ticks; } off[MAX_PENDING];
    int noffs;
    double tick_frac;
} seq;

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }

static uint32_t vlq(void) {
    uint32_t v = 0;
    while (seq.pos < seq.len) {
        uint8_t b = seq.ev[seq.pos++];
        v = v << 7 | (b & 0x7F);
        if (!(b & 0x80)) break;
    }
    return v;
}

/* The `n`th FORM XMID's EVNT chunk in an IFF tree (FORM XDIR + CAT XMID, or a bare FORM XMID). */
static int find_evnt(const uint8_t *p, uint32_t len, int *n, const uint8_t **ev, uint32_t *evlen) {
    uint32_t i = 0;
    while (i + 8 <= len) {
        uint32_t sz = be32(p + i + 4);
        if (sz > len - i - 8) sz = len - i - 8;
        const uint8_t *body = p + i + 8;
        if ((!memcmp(p + i, "FORM", 4) || !memcmp(p + i, "CAT ", 4)) && sz >= 4) {
            if (!memcmp(p + i, "FORM", 4) && !memcmp(body, "XMID", 4)) {
                if ((*n)-- == 0) {
                    uint32_t j = 4;
                    while (j + 8 <= sz) {
                        uint32_t csz = be32(body + j + 4);
                        if (!memcmp(body + j, "EVNT", 4)) {
                            *ev = body + j + 8;
                            *evlen = csz < sz - j - 8 ? csz : sz - j - 8;
                            return 1;
                        }
                        j += 8 + csz + (csz & 1);
                    }
                    return 0;
                }
            } else if (find_evnt(body + 4, sz - 4, n, ev, evlen)) {
                return 1;
            }
        }
        i += 8 + sz + (sz & 1);
    }
    return 0;
}

static void seq_event(void) {
    uint8_t st = seq.ev[seq.pos++];
    int ch = st & 15;
    switch (st & 0xF0) {
    case 0x80: { int n = seq.ev[seq.pos]; seq.pos += 2; note_off(ch, n); break; }
    case 0x90: {
        int n = seq.ev[seq.pos], v = seq.ev[seq.pos + 1];
        seq.pos += 2;
        uint32_t dur = vlq();                        /* XMIDI: the note's length, not a later note-off */
        if (!v) { note_off(ch, n); break; }
        note_on(ch, n, v);
        if (seq.noffs < MAX_PENDING) {
            seq.off[seq.noffs].ch = (uint8_t)ch;
            seq.off[seq.noffs].note = (uint8_t)n;
            seq.off[seq.noffs].ticks = dur;
            seq.noffs++;
        }
        break;
    }
    case 0xA0: seq.pos += 2; break;
    case 0xB0: {
        int cc = seq.ev[seq.pos], val = seq.ev[seq.pos + 1];
        seq.pos += 2;
        if (cc == 116) {                             /* FOR: loop start, count (0 = forever) */
            if (seq.loops < 4) { seq.loop[seq.loops].pos = seq.pos; seq.loop[seq.loops].count = val; seq.loops++; }
        } else if (cc == 117) {                      /* NEXT (>= 64) / BREAK */
            if (seq.loops) {
                int top = seq.loops - 1;
                if (val >= 64 && (seq.loop[top].count == 0 || --seq.loop[top].count > 0)) seq.pos = seq.loop[top].pos;
                else seq.loops--;
            }
        } else {
            controller(ch, cc, val);
        }
        break;
    }
    case 0xC0: mch[ch].program = seq.ev[seq.pos++]; break;
    case 0xD0: seq.pos++; break;
    case 0xE0: {
        mch[ch].bend = seq.ev[seq.pos] | seq.ev[seq.pos + 1] << 7;
        seq.pos += 2;
        for (int v = 0; v < 9; v++) if (voice[v].on && voice[v].chan == ch) voice_pitch(v, 1);
        break;
    }
    default:
        if (st == 0xFF) {
            uint8_t type = seq.ev[seq.pos++];
            uint32_t l = vlq();
            if (type == 0x2F) { seq.playing = 0; all_notes_off(); return; }
            seq.pos += l;
        } else if (st == 0xF0 || st == 0xF7) {
            seq.pos += vlq();
        }
        break;
    }
}

/* One 120 Hz tick: end the notes whose time is up, then play what is due. */
static void seq_tick(void) {
    for (int i = 0; i < seq.noffs;) {
        if (seq.off[i].ticks-- <= 1) {
            note_off(seq.off[i].ch, seq.off[i].note);
            seq.off[i] = seq.off[--seq.noffs];
        } else {
            i++;
        }
    }
    if (!seq.playing) return;
    if (seq.wait) { seq.wait--; if (seq.wait) return; }
    while (seq.playing && seq.pos < seq.len) {
        uint8_t b = seq.ev[seq.pos];
        if (b < 0x80) {                              /* XMIDI delay: a run of bytes below 0x80, summed */
            while (seq.pos < seq.len && seq.ev[seq.pos] < 0x80) seq.wait += seq.ev[seq.pos++];
            if (seq.wait) return;
            continue;
        }
        seq_event();
    }
    if (seq.pos >= seq.len) { seq.playing = 0; all_notes_off(); }
}

/* ================================================================== effects */
typedef struct {
    int16_t *pcm;
    uint32_t frames;
    double pos, step;
    int loop, on;
    uint32_t key;
} Effect;

static Effect fx[4];
static int fx_rr_once, fx_rr_loop;

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

/* Append raw PCM to a growing mono int16 buffer. */
static int append_pcm(int16_t **buf, uint32_t *n, uint32_t *cap, const uint8_t *p, uint32_t bytes, int bits, int chans) {
    uint32_t frames = bytes / (uint32_t)(bits / 8 * chans);
    if (*n + frames > *cap) {
        uint32_t nc = (*n + frames) * 2;
        int16_t *nb = realloc(*buf, nc * sizeof **buf);
        if (!nb) return 0;
        *buf = nb;
        *cap = nc;
    }
    for (uint32_t i = 0; i < frames; i++) {
        int s = 0;
        for (int c = 0; c < chans; c++) {
            const uint8_t *q = p + (i * (uint32_t)chans + (uint32_t)c) * (uint32_t)(bits / 8);
            s += bits == 8 ? (q[0] - 128) << 8 : (int16_t)le16(q);
        }
        (*buf)[(*n)++] = (int16_t)(s / chans);
    }
    return 1;
}

/* Decode a WAV or VOC image into mono int16 at its own rate. */
static int16_t *decode(const uint8_t *f, uint32_t avail, uint32_t *frames, int *rate) {
    int16_t *buf = NULL;
    uint32_t n = 0, cap = 0;
    if (avail >= 12 && !memcmp(f, "RIFF", 4) && !memcmp(f + 8, "WAVE", 4)) {
        uint32_t end = 8 + le32(f + 4), i = 12;
        int bits = 8, chans = 1;
        if (end > avail) end = avail;
        *rate = 11025;
        while (i + 8 <= end) {
            uint32_t sz = le32(f + i + 4);
            if (sz > end - i - 8) sz = end - i - 8;
            if (!memcmp(f + i, "fmt ", 4) && sz >= 16) {
                chans = le16(f + i + 10);
                *rate = (int)le32(f + i + 12);
                bits = le16(f + i + 22);
            } else if (!memcmp(f + i, "data", 4) && (bits == 8 || bits == 16) && chans >= 1 && chans <= 2) {
                append_pcm(&buf, &n, &cap, f + i + 8, sz, bits, chans);
            }
            i += 8 + sz + (sz & 1);
        }
    } else if (avail >= 26 && !memcmp(f, "Creative Voice File\x1a", 20)) {
        uint32_t i = le16(f + 20);
        *rate = 11025;
        while (i + 4 <= avail && f[i]) {
            uint32_t sz = f[i + 1] | f[i + 2] << 8 | f[i + 3] << 16;
            const uint8_t *b = f + i + 4;
            if (sz > avail - i - 4) sz = avail - i - 4;
            if (f[i] == 1 && sz >= 2 && b[1] == 0) {         /* sound data, 8-bit unsigned */
                *rate = 1000000 / (256 - b[0]);
                append_pcm(&buf, &n, &cap, b + 2, sz - 2, 8, 1);
            } else if (f[i] == 2) {                          /* continuation */
                append_pcm(&buf, &n, &cap, b, sz, 8, 1);
            } else if (f[i] == 9 && sz >= 12) {              /* new format */
                int bits = b[4], chans = b[5], codec = le16(b + 6);
                *rate = (int)le32(b);
                if ((codec == 0 || codec == 4) && (bits == 8 || bits == 16) && chans >= 1 && chans <= 2)
                    append_pcm(&buf, &n, &cap, b + 12, sz - 12, bits, chans);
            }
            i += 4 + sz;
        }
    }
    if (!n) { free(buf); return NULL; }
    *frames = n;
    return buf;
}

/* ===================================================================== mixer */
static int vol_fx = 127, vol_music = 127;
static double fade_gain = 1, fade_step;     /* music fade-out in progress when fade_step > 0 */
static double opl_frac, opl_prev, opl_cur;   /* resampling the chip */
static double tick_acc;

void snd_init(int rate, const char *game_dir) {
    out_rate = rate;
    for (int i = 0; i < 1024; i++) sin_tab[i] = (float)sin(2 * M_PI * i / 1024);
    for (int i = 0; i <= 96 * 32; i++) db_tab[i] = (float)pow(10, -(i / 32.0) / 20);
    char path[1024];
    snprintf(path, sizeof path, "%s/DRIVERS/WARCRAFT.AD", game_dir);
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(path, sizeof path, "%s/drivers/warcraft.ad", game_dir);
        f = fopen(path, "rb");
    }
    if (f) {
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        rewind(f);
        gtl = malloc((size_t)n);
        if (gtl && fread(gtl, 1, (size_t)n, f) == (size_t)n) gtl_len = (size_t)n;
        fclose(f);
    }
    if (!gtl_len) fprintf(stderr, "war: no DRIVERS/WARCRAFT.AD timbre bank; music is off\n");
    midi_reset();
}

void snd_effect_play(const uint8_t *file, uint32_t avail, uint32_t key, int loop) {
    uint32_t frames;
    int rate;
    int16_t *pcm = decode(file, avail, &frames, &rate);
    if (!pcm || rate <= 0) return;
    int slot = -1;
    for (int i = 0; i < 4; i++) if (!fx[i].on) { slot = i; break; }
    if (slot < 0) {                                 /* all busy: take turns, like the game's wrapper */
        int *rr = loop ? &fx_rr_loop : &fx_rr_once;
        slot = *rr;
        *rr = (*rr + 1) & 3;
    }
    free(fx[slot].pcm);
    fx[slot] = (Effect){ pcm, frames, 0, (double)rate / out_rate, loop, 1, key };
}

void snd_effect_stop(uint32_t key) {
    for (int i = 0; i < 4; i++)
        if (fx[i].on && (!key || fx[i].key == key)) {
            fx[i].on = 0;
            if (key) break;
        }
}

int snd_effects_playing(void) {
    int n = 0;
    for (int i = 0; i < 4; i++) n += fx[i].on;
    return n;
}

void snd_effect_volume(int v) { vol_fx = v; }
void snd_music_volume(int v) { vol_music = v; }

void snd_music_start(const uint8_t *xmi, uint32_t len, int n) {
    snd_music_stop();
    if (!gtl_len) return;
    if (len > 1u << 16) len = 1u << 16;               /* the game's music buffer is 30000 bytes */
    if (len < 8) return;
    free(seq.data);
    seq.data = malloc(len);
    if (!seq.data) return;
    memcpy(seq.data, xmi, len);
    const uint8_t *ev;
    uint32_t evlen;
    int k = n;
    if (!find_evnt(seq.data, len, &k, &ev, &evlen)) { fprintf(stderr, "war: XMIDI sequence %d not found\n", n); return; }
    seq.ev = ev;
    seq.len = evlen;
    seq.pos = 0;
    seq.wait = 0;
    seq.loops = 0;
    seq.noffs = 0;
    seq.playing = 1;
    fade_gain = 1;
    fade_step = 0;
}

void snd_music_stop(void) {
    seq.playing = 0;
    seq.noffs = 0;
    midi_reset();
}

void snd_fade_out(int ms) {
    if (ms <= 0) { snd_music_stop(); snd_effect_stop(0); return; }
    fade_step = 1.0 / (ms / 1000.0 * out_rate);
}

#define FX_GAIN    0.85        /* 8-bit effect at full volume, relative to full scale */
#define MUSIC_GAIN 0.167       /* OPL output (sum of channels, each up to +-1) to full scale:
                                  the level DOSBox-X mixes AdLib music at */

void snd_render(int16_t *out, int frames) {
    for (int i = 0; i < frames; i++) {
        /* music: the chip and the 120 Hz sequencer run on their own clocks */
        opl_frac += OPL_RATE / out_rate;
        while (opl_frac >= 1) {
            opl_frac -= 1;
            tick_acc += 120.0 / OPL_RATE;
#ifdef SOUND_TRACE
            snd_trace_ms += 1000.0 / OPL_RATE;
#endif
            while (tick_acc >= 1) { tick_acc -= 1; seq_tick(); }
            opl_prev = opl_cur;
            opl_cur = opl_sample();
        }
        double music = (opl_prev + (opl_cur - opl_prev) * opl_frac) * MUSIC_GAIN * vol_music / 127.0 * fade_gain;
        if (fade_step > 0) {
            fade_gain -= fade_step;
            if (fade_gain <= 0) { fade_gain = 1; fade_step = 0; snd_music_stop(); snd_effect_stop(0); }
        }
        double mix = 0;
        for (int k = 0; k < 4; k++) {
            Effect *e = &fx[k];
            if (!e->on) continue;
            uint32_t p = (uint32_t)e->pos;
            double t = e->pos - p;
            int a = e->pcm[p], b = p + 1 < e->frames ? e->pcm[p + 1] : (e->loop ? e->pcm[0] : 0);
            mix += (a + (b - a) * t) / 32768.0;
            e->pos += e->step;
            if (e->pos >= e->frames) {
                if (e->loop) e->pos -= e->frames;
                else e->on = 0;
            }
        }
        double s = (music + mix * FX_GAIN * vol_fx / 127.0) * 32767.0;
        if (s > 32767) s = 32767;
        if (s < -32768) s = -32768;
        out[2 * i] = out[2 * i + 1] = (int16_t)s;
    }
}
