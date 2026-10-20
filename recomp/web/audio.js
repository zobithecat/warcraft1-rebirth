// AudioWorklet: plays what the game's worker writes into the shared ring
// (runtime/game.c web_audio): float32 stereo frames, counters [written, read].
class WarAudio extends AudioWorkletProcessor {
  constructor(options) {
    super();
    this.buf = new Float32Array(options.processorOptions.buf);
    this.idx = new Int32Array(options.processorOptions.idx);
    this.cap = this.buf.length / 2;
    // Whatever was written before the page could play is stale: start near the writer.
    const wr = Atomics.load(this.idx, 0);
    Atomics.store(this.idx, 1, Math.max(Atomics.load(this.idx, 1), wr - 2048));
  }

  process(inputs, outputs) {
    const left = outputs[0][0], right = outputs[0][1] || left;
    const wr = Atomics.load(this.idx, 0);
    let rd = Atomics.load(this.idx, 1);
    for (let i = 0; i < left.length; i++) {
      if (rd < wr) {
        const j = (rd % this.cap) * 2;
        left[i] = this.buf[j];
        right[i] = this.buf[j + 1];
        rd++;
      } else {
        left[i] = right[i] = 0;      // the game fell behind: silence, not old sound
      }
    }
    Atomics.store(this.idx, 1, rd);
    return true;
  }
}
registerProcessor("war-audio", WarAudio);
