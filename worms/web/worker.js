// Runs the recompiled game in a worker, like ../recomp/web/worker.js: frames
// go out with postMessage (web_present in runtime/host.c) and input arrives
// through the SharedArrayBuffer ring the page writes (web_poll).
self.onmessage = (e) => {
  globalThis.warRing = new Int32Array(e.data.ring);
  globalThis.warEnv = e.data.env;
  globalThis.warAudio = { buf: new Float32Array(e.data.audioBuf), idx: new Int32Array(e.data.audioIdx) };
  const log = (s) => postMessage({ log: s });
  self.Module = {
    arguments: ["/game", "/cd", "/image.bin"],
    print: log,
    printErr: log,
    setStatus: (s) => postMessage({ status: s }),
    onExit: (code) => postMessage({ exit: code }),
    onAbort: (what) => postMessage({ exit: "abort: " + what }),
  };
  importScripts("worms.js");
};
