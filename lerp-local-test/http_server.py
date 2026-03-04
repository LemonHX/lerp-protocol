"""
Simple HTTP server that listens on port 8000.
The lerp server daemon forwards incoming lerp connections to this server.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import json


class MyRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "message": "Hello from the lerp tunnel!",
            "path": self.path,
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"[http-server] {self.address_string()} - {format % args}")


def run_server(host="127.0.0.1", port=8000):
    server = HTTPServer((host, port), MyRequestHandler)
    print(f"[http-server] listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    print("[http-server] stopped.")


if __name__ == "__main__":
    run_server()
