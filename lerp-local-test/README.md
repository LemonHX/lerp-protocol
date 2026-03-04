# lerp local test

End-to-end smoke test: a Python HTTP server exposed through a localhost lerp
relay and accessed via a lerp tunnel.

```
[curl / http_client.py]
    │  TCP :9000
    ▼
[client daemon]  ─── WebTransport ───▶  [relay :4433]  ◀─── WebTransport ───  [server daemon]
                                                                                      │  TCP :8000
                                                                                      ▼
                                                                              [http_server.py]
```

---

## Prerequisites

| Tool | Install |
|------|---------|
| Rust / Cargo | <https://rustup.rs> |
| `lerp-daemon` binary | `cargo install --path crates/lerp-daemon` (from repo root) |
| OpenSSL CLI | bundled on macOS/Linux; [Win32 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) on Windows |
| Python 3 | <https://python.org> |
| `requests` | `pip install requests` |

---

## Quick start (automated)

Run the setup script **once** from the repo root:

```bash
# Linux / macOS
bash lerp-local-test/setup.sh

# Windows (PowerShell)
cd lerp-local-test && .\setup.ps1
```

The script:
1. Generates a self-signed TLS cert in `lerp-local-test/certs/`.
2. Creates a fresh endpoint identity and writes it into `server.config.toml`.
3. Generates a ticket and writes it into `client.config.toml`.

Then follow the four-terminal instructions printed at the end.

---

## Manual walkthrough

### Step 1 — Build everything

```bash
cargo build -p lerp-relay -p lerp-daemon
```

### Step 2 — Generate TLS cert for the relay

```bash
mkdir -p lerp-local-test/certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout lerp-local-test/certs/key.pem \
    -out    lerp-local-test/certs/cert.pem \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:*.localhost"
```

### Step 3 — Generate an endpoint identity

```bash
lerp-daemon new-endpoint
# → JFXGS3TBNVSXE2LBNRWCA3DPOBSSA43UOJUW4ZLTMVXGG33NEBTG
```

Edit `lerp-local-test/server.config.toml` and replace the placeholder `eid`
with the value you just got.

### Step 4 — Generate a ticket

```bash
lerp-daemon ticket \
  --eid       <YOUR_EID> \
  --relay     localhost \
  --relay-sec c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00 \
  --field     service=http
# → lerp1_AAAA…base64url…
```

Edit `lerp-local-test/client.config.toml` and replace the placeholder `ticket`
with the value you got.

### Step 5 — Terminal 1: start the relay

```bash
# From the repo root — the relay reads .env from the current directory.
cd lerp-local-test && cargo run -p lerp-relay
```

Expected output:
```
INFO lerp_relay: listening on 127.0.0.1:4433
```

### Step 6 — Terminal 2: start the server daemon

```bash
lerp-daemon --config lerp-local-test/server.config.toml serve
```

Expected output:
```
INFO serve: relay connected, waiting for peer to pair
```

### Step 7 — Terminal 3: start the client daemon

```bash
lerp-daemon --config lerp-local-test/client.config.toml connect
```

Expected output:
```
INFO connect: handshake complete, listening on 127.0.0.1:9000
```

### Step 8 — Terminal 4: start the Python HTTP server

```bash
python3 lerp-local-test/http_server.py
```

Expected output:
```
[http-server] listening on http://127.0.0.1:8000
```

### Step 9 — Make a request

**Option A — Python client:**
```bash
python3 lerp-local-test/http_client.py
```

**Option B — curl:**
```bash
curl -s http://127.0.0.1:9000/hello | python3 -m json.tool
```

**Option C — browser:**  
Open <http://127.0.0.1:9000/> in your browser.

Expected response:
```json
{
  "message": "Hello from the lerp tunnel!",
  "path": "/hello",
  "time": "2026-03-04T12:00:00Z"
}
```

---

## File reference

| File | Purpose |
|------|---------|
| `.env` | Relay config (secret, cert paths, bind address) |
| `server.config.toml` | Server daemon: expose local HTTP → relay |
| `client.config.toml` | Client daemon: relay → local port 9000 |
| `http_server.py` | Toy HTTP server on port 8000 |
| `http_client.py` | Test client sending requests via the tunnel |
| `setup.sh` | Automated setup (Linux / macOS) |
| `setup.ps1` | Automated setup (Windows PowerShell) |
| `certs/` | Auto-generated TLS cert (created by setup script) |

---

## Shared secret

The relay secret `c0ffee00…` is hard-coded for local testing and appears in
three places that must match:

| Location | Field |
|----------|-------|
| `.env` | `RELAY_SECRET` |
| `server.config.toml` | `relay_sec_hex` |
| `lerp-daemon ticket --relay-sec …` | CLI flag |

For a real deployment generate a fresh secret with `openssl rand -hex 32`.
