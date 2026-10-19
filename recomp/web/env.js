// --pre-js for both wasm builds: WAR_* settings (WAR_INPUT, WAR_TRACE, ...)
// come from the shell under Node and from the page's URL in the browser.
Module.preRun = [].concat(Module.preRun || [], () => {
  const src = typeof process === "object" ? process.env : (globalThis.warEnv || {});
  for (const k in src) if (k.startsWith("WAR_")) ENV[k] = src[k];
});
