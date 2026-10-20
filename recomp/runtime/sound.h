/* Sound for the recompiled game, standing in for Blizzard's wrapper over
 * Miles AIL 3: digital effects from the game's VOC/WAV file images, and its
 * XMIDI music played on an emulated OPL2 with the game's own AIL timbre bank
 * (DRIVERS/WARCRAFT.AD), mixed to 16-bit stereo.  Nothing here touches the
 * guest: runtime/game.c passes host pointers and copies what it needs. */
#ifndef RECOMP_SOUND_H
#define RECOMP_SOUND_H

#include <stdint.h>

void snd_init(int rate, const char *game_dir);

/* Effects: `key` identifies the file image (its guest address) for snd_effect_stop. */
void snd_effect_play(const uint8_t *file, uint32_t avail, uint32_t key, int loop);
void snd_effect_stop(uint32_t key);            /* 0: all */
int snd_effects_playing(void);
void snd_effect_volume(int v);                 /* 0..127 */

/* Music: an XMIDI file image (copied), sequence `seq` within it. */
void snd_music_start(const uint8_t *xmi, uint32_t len, int seq);
void snd_music_stop(void);
void snd_music_volume(int v);                  /* 0..127 */
void snd_fade_out(int ms);                     /* fade the music, then stop everything */

/* Produce the next `frames` stereo frames (interleaved L, R). */
void snd_render(int16_t *out, int frames);

#endif
