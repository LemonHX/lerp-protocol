"""
HTTP client that sends requests through the lerp tunnel.

Traffic flow:
  this script  →  127.0.0.1:9000 (client daemon local port)
               →  relay (127.0.0.1:4433)
               →  server daemon
               →  127.0.0.1:8000 (http_server.py)

Usage:
  pip install requests
  python http_client.py
"""

import requests
import json
import time

BASE_URL = "http://127.0.0.1:9000"

PATHS = ["/", "/hello", "/status", "/foo/bar"]


def main():
    print(f"Sending requests to {BASE_URL} (via lerp tunnel)\n")
    print("=" * 60)

    for path in PATHS:
        url = f"{BASE_URL}{path}"
        try:
            t0 = time.perf_counter()
            resp = requests.get(url, timeout=10)
            elapsed_ms = (time.perf_counter() - t0) * 1000

            print(f"GET {path}")
            print(f"  Status : {resp.status_code}")
            print(f"  Latency: {elapsed_ms:.1f} ms")
            try:
                data = resp.json()
                print(f"  Body   : {json.dumps(data, indent=4)}")
            except Exception:
                print(f"  Body   : {resp.text[:200]}")
        except requests.exceptions.ConnectionError as e:
            print(f"GET {path}")
            print(f"  ERROR: cannot connect — is the client daemon running? ({e})")
        except requests.exceptions.Timeout:
            print(f"GET {path}")
            print(f"  ERROR: request timed out")
        print()

    print("=" * 60)
    print("Done.")


if __name__ == "__main__":
    main()
