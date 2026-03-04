#!/usr/bin/env bash
# setup.sh — one-shot setup for the lerp local test
# Run from the lerp-local-test/ directory.
set -euo pipefail

RELAY_SEC="c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
RELAY_HOST="localhost"

cd "$(dirname "$0")"

echo "compile binaries with cargo"
cd ..
cargo build

echo "moving compiled binaries to ./"
cp ../target/debug/lerp-* ./

echo "=== 1. Generating TLS certificates ==="
# mkdir -p certs
# openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
#     -keyout certs/key.pem -out certs/cert.pem \
#     -days 365 -nodes \
#     -subj "/CN=localhost" \
#     -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:*.localhost"
# echo "    certs/cert.pem and certs/key.pem created."

echo "using pre-generated TLS certs in certs/ (edit certs/README.md to regenerate)"


echo ""
echo "=== 1.5 Setting up relay ==="
echo " you need to start the relay first before running this setup script"
echo " ./lerp-relay" # TODO: for ci/cd in background and kill at the end

echo ""
echo "=== 2. Generating endpoint identity ==="
echo "./lerp-daemon new-endpoint"
echo "but in this test case we are using a fixed EID for simplicity:"
EID="AAOAEMEBNJOFUJ7ZLIWLOE2GSJCRMG7LI54F6U5DBG2TUB7BAZ7A"
echo "    EID: $EID"

echo ""
echo "=== 3. Writing EID into server.config.toml ==="
ehco "write the server.config.toml"
echo "in this test, we have already set the EID in server.config.toml to $EID, but in a more general setup you would run:"
echo "    sed -i \"s|endpoint = \"REPLACE_WITH_EID\"|endpoint = \"$EID\"|\" server.config.toml"
echo "    Done."

echo ""
echo "=== 4. Generating ticket ==="
echo "for this test, we have already generated a ticket"
echo "ta7lCoWobGVycF92ZXKpMC4xLjAtZGV2qGxlcnBfZWlk2TRBQU9BRU1FQk5KT0ZVSjdaTElXTE9FMkdTSkNSTUc3TEk1NEY2VTVEQkcyVFVCN0JBWjdBqGxlcnBfcmx5qWxvY2FsaG9zdKhsZXJwX3NlY8QgwP_uAMD_7gDA_-4AwP_uAMD_7gDA_-4AwP_uAMD_7gCnc2VydmljZaRodHRw"
echo "but in a more general setup you would run: ./lerp-daemon ticket \
    --eid "$EID" \
    --relay "$RELAY_HOST" \
    --relay-sec "$RELAY_SEC" \
    --field service=http)"

echo "    Ticket: $TICKET" 
echo ""

echo "=== 5. Writing ticket into client.config.toml ==="

echo ""
echo "======================================================"
echo "Setup complete! Open 4 terminals and run:"
echo ""
echo "  Terminal 1 (relay):"
echo "    cd .. && cargo run -p lerp-relay"
echo ""
echo "  Terminal 2 (server daemon):"
echo "    ./lerp-daemon --config lerp-local-test/server.config.toml serve"
echo ""
echo "  Terminal 3 (client daemon):"
echo "    ./lerp-daemon --config lerp-local-test/client.config.toml connect"
echo ""
echo "  Terminal 4 (HTTP server):"
echo "    python3 lerp-local-test/http_server.py"
echo ""
echo "Then test with:"
echo "    python3 lerp-local-test/http_client.py"
echo "  or"
echo "    curl http://127.0.0.1:9000/hello"
echo "======================================================"
