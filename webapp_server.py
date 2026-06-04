"""
webapp_server.py  —  Serves the ZTA web UI on http://localhost:8080

Run this in a separate terminal alongside uvicorn.
It simply serves the /webapp folder as static HTML files.

Usage:
    python webapp_server.py
Then open: http://localhost:8080
"""
import http.server
import socketserver
import os

PORT    = 8080
WEBDIR  = os.path.join(os.path.dirname(__file__), "webapp")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEBDIR, **kwargs)

    def log_message(self, fmt, *args):
        print(f"  [webapp] {self.address_string()} — {fmt % args}")

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"\n  ZTA Web UI running at:  http://localhost:{PORT}")
        print(f"  Serving files from:     {WEBDIR}")
        print(f"  Make sure uvicorn is running on port 8000 too.\n")
        print(f"  Press Ctrl+C to stop.\n")
        httpd.serve_forever()
