## TLS-Encrypted Secure Socket Demo
A Python-based implementation of a secure client-server architecture using **Transport Layer Security (TLS)**.

### Features
* **End-to-End Encryption:** Uses Python’s `ssl` module for a local TLS server/client.
* **Framed Protocol (JSON over TLS):** Length-prefixed frames avoid partial-read issues and allow structured messages.
* **TLS Hardening:** Enforces TLS 1.2+ and restricts TLS 1.2 cipher suites when possible.
* **Optional mTLS:** Generate a local CA + client certs and require client certificates on the server.
* **Type Safety:** Python type hinting used throughout the codebase.

### Getting Started
1. **Setup:** Run `setup.bat` to install dependencies (cryptography).
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

---
