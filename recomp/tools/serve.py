#!/usr/bin/env python3
"""Serve build/web on localhost for the browser build.

SharedArrayBuffer (the input ring between the page and the game's worker)
needs a cross-origin isolated page, so every response carries COOP/COEP.

Usage: serve.py [DIR] [--port 8000]
"""
import argparse
import functools
import http.server


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map, ".wasm": "application/wasm"}

    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", nargs="?", default="build/web")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    handler = functools.partial(Handler, directory=args.dir)
    with http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler) as srv:
        print(f"WarCraft (wasm): http://localhost:{args.port}/")
        srv.serve_forever()


if __name__ == "__main__":
    main()
