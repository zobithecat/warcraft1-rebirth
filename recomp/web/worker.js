// Runs the recompiled game.  Its main loop never returns to the event loop,
// so it lives in this worker: frames go out with postMessage (see
// web_present in runtime/game.c) and input arrives through the
// SharedArrayBuffer ring the page writes (web_poll).
self.onmessage = (e) => {
  globalThis.warRing = new Int32Array(e.data.ring);
  globalThis.warEnv = e.data.env;
  const log = (s) => postMessage({ log: s });
  self.Module = {
    arguments: ["/game", "/image.bin"],
    print: log,
    printErr: log,
    setStatus: (s) => postMessage({ status: s }),
    onExit: (code) => postMessage({ exit: code }),
    onAbort: (what) => postMessage({ exit: "abort: " + what }),
  };
  importScripts("war.js");
};
