## TLS-Encrypted Secure Socket Demo
A Python-based implementation of a secure client-server architecture using **Transport Layer Security (TLS)**.

### Features
* **End-to-End Encryption:** Uses Python’s `ssl` module for a local TLS server/client.
* **Framed Protocol (JSON over TLS):** Length-prefixed frames avoid partial-read issues and allow structured messages.
* **TLS Hardening:** Enforces TLS 1.2+ and restricts TLS 1.2 cipher suites when possible.
* **Optional mTLS:** Generate a local CA + client certs and require client certificates on the server.
* **Type Safety:** Python type hinting used throughout the codebase.

### Getting Started
1. **Setup:** Run `setup.bat` to install dependencies (`cryptography`).
2. **Generate Certs (self-signed server):** `python gen_certs.py --mode selfsigned`
3. **Run Server:** `python server.py`
4. **Run Client:** `python client.py`

### Usage
Client commands:
* `/ping` → server replies with `pong`
* `/info` → server replies with negotiated TLS info
* `/quit` → close session
* `/screenshot` → saves a **local** PNG screenshot to `./screenshots/` (requires Pillow)
* Any other text → echoed back as `{"type":"echo","text":"..."}`

### Optional: Mutual TLS (mTLS)
Generate a local CA, server cert, and client cert:
1. `python gen_certs.py --mode mtls`
2. Start server requiring a client cert:
   * `python server.py --require-client-cert --ca-file ca.crt`
3. Start client presenting its certificate:
   * `python client.py --ca-file ca.crt --use-client-cert --client-cert client.crt --client-key client.key`

### Remote Access via Portmap.io
You can expose the TLS server to the Internet without opening router ports by routing it through Portmap.io, which establishes an OpenVPN tunnel and forwards a public TCP port into your LAN before the TLS handshake even starts. citeturn0search0turn0search7

1. Sign up at Portmap.io, create a TCP service for your TLS port (e.g., 6767), download the OpenVPN profile, and run `openvpn --config <that-file>` or use the Portmap CLI to keep the tunnel running. citeturn0search0turn0search7
2. Run the server on `0.0.0.0` so it accepts the tunneled traffic: `python server.py --host 0.0.0.0 --port 6767`. The service on Portmap.io forwards its public port to that listener over the VPN. citeturn0search0
3. Regenerate certificates so the remote hostname is valid: `python gen_certs.py --mode selfsigned --server-cn yoursubdomain.portmap.io --server-alt yoursubdomain.portmap.io`. The `--server-alt` flag lets you add the Portmap.io hostname/IP to the SAN list.
4. Connect from another network using the assigned Portmap.io hostname/port: `python client.py --host yoursubdomain.portmap.io --port <public-port> --server-name yoursubdomain.portmap.io`.
5. Keep the Portmap.io tunnel up only while needed and close the server or firewall unused ports afterward to limit exposure.

---
