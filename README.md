## TLS-Encrypted Secure Socket Demo
A Python-based implementation of a secure client-server architecture using **Transport Layer Security (TLS)**.

### Features
* **End-to-End Encryption:** Uses the `ssl` module with `PROTOCOL_TLS_SERVER`.
* **Dynamic Cert Generation:** Includes a script to generate self-signed RSA-2048 certificates with Subject Alternative Names (SAN).
* **Type Safety:** Python type hinting used throughout the codebase.

### Getting Started
1. **Setup:** Run `setup.bat` to install dependencies (cryptography).
2. **Generate Certs:** Run `python gen_certs.py` to create your local `server.key` and `server.crt`.
3. **Run Server:** `python server.py`
4. **Run Client:** `python client.py`

---