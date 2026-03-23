# TLS-Encrypted C2 Demo

A Python-based implementation of a secure client-server (C2) architecture using Transport Layer Security (TLS). Built as a TryHackMe challenge project.

> **For educational purposes only.** Use only on systems you own or have explicit permission to test.

---

## Features

- **End-to-end TLS 1.2+** encryption using Python's `ssl` module
- **Protobuf binary protocol** with zlib compression on the wire
- **Mutual TLS (mTLS)** support — optional client certificate auth
- **Auth token** validation on every connection
- **Async server** built on `asyncio` — handles many clients concurrently
- **Auto-heartbeat** — server pings clients every 30s, drops unresponsive ones
- **Exponential backoff reconnect** on the client side
- **File transfer** — upload and download files over the TLS tunnel
- **Screenshot capture** — grab the client screen as PNG
- **Remote shell** — run any command on the connected client
- **Client groups** — tag clients and send commands to a whole group
- **Message routing** — broadcast to all, or target a specific group
- **Web dashboard** — live client list at `http://localhost:8080`
- **Config files** — `config.yaml` for server, `client_config.yaml` for client
- **Portmap.io tunnel** — expose server globally without port forwarding
- **PyInstaller packaging** — build a standalone `tls_client.exe`
- **Docker deploy** — `docker-compose up` to run server in the cloud

---

## Project Structure

```
├── server.py             # Async TLS C2 server
├── client.py             # TLS agent / client
├── protocol.py           # Protobuf + zlib framing layer
├── tunnel.py             # Portmap.io SSH reverse tunnel
├── config_loader.py      # YAML config loader
├── config.yaml           # Server configuration
├── client_config.yaml    # Client configuration
├── gen_certs.py          # Generate CA + server + client certs
├── messages.proto        # Protobuf schema
├── messages_pb2.py       # Compiled protobuf (auto-generated)
├── build_client.spec     # PyInstaller spec for client exe
├── Dockerfile            # Docker image for server
├── docker-compose.yml    # Docker Compose for cloud deploy
├── setup.bat             # Windows quick-install script
└── requirements.txt      # Python dependencies
```

---

## Quick Start

### 1. Install dependencies

```bash
# Windows
setup.bat

# Linux / macOS
pip install -r requirements.txt
```

### 2. Compile protobuf schema

```bash
python -m grpc_tools.protoc -I. --python_out=. messages.proto
```

### 3. Generate TLS certificates

```bash
python gen_certs.py
```

This creates `ca.crt`, `server.crt/key`, `client.crt/key` in the current directory.
**Never commit `.key` or `.pem` files.**

### 4. Start the server

```bash
python server.py
```

### 5. Connect a client

```bash
python client.py
```

---

## Server Admin CLI

Once running, the server exposes an interactive CLI:

| Command | Description |
|---------|-------------|
| `clients` | List all connected clients |
| `groups` | List clients grouped by tag |
| `use <id>` | Select a client by ID or UUID prefix |
| `ping` | Ping the selected client |
| `info` | Get OS, TLS version, cipher, PID |
| `exec <cmd>` | Run a shell command on the client |
| `file_get <remote> [local]` | Download a file from the client |
| `file_put <local> <remote>` | Upload a file to the client |
| `screenshot [out.png]` | Capture a screenshot |
| `echo <text>` | Echo text back |
| `queue` | Show pending command queue |
| `broadcast <msg>` | Send to all connected clients |
| `groupsend <group> <msg>` | Send to a specific group |
| `drop` | Disconnect the selected client |
| `exit` | Shut down the server |

---

## Web Dashboard

Visit `http://127.0.0.1:8080` while the server is running.
Auto-refreshes every 5 seconds showing all connected clients, their groups, hostnames, and TLS info.

---

## Configuration

### Server — `config.yaml`

Key settings:

```yaml
server:
  host: "127.0.0.1"
  port: 6767

auth:
  token: "changeme-token-1234"   # clients must match this

heartbeat:
  interval: 30     # seconds between pings
  timeout: 10      # drop client if no pong within this

tunnel:
  enabled: false   # set true to expose via Portmap.io
```

### Client — `client_config.yaml`

```yaml
server:
  host: "127.0.0.1"
  port: 6767

client:
  group: "default"   # tag this client for group commands
```

---

## Mutual TLS (mTLS)

```bash
# Server
python server.py --require-client-cert

# Client
python client.py --use-client-cert
```

---

## Global Access via Portmap.io

Expose the server to the internet without touching your router:

1. Sign up at [portmap.io](https://portmap.io) → create a configuration → Type: **SSH**
2. Download the `.pem` key file → save to `~/.ssh/`
3. On Linux/macOS: `chmod 600 ~/.ssh/<n>.first`
4. Update `config.yaml`:

```yaml
tunnel:
  enabled: true
  key_file: "~/.ssh/<n>.first"
  username: "<n>.first"
  remote_host: "<n>-<port>.portmap.host"
  remote_port: <assigned-port>
  local_port: 6767
```

5. Update `client_config.yaml` on the remote machine:

```yaml
server:
  host: "<n>-<port>.portmap.host"
  port: <assigned-port>
  server_name: "localhost"
```

---

## Package Client as EXE

```bash
pip install pyinstaller
pyinstaller build_client.spec
# Output: dist/tls_client.exe
```

The exe is fully standalone — no Python needed on the target machine.

---

## Deploy Server on Cloud

```bash
# Docker
docker build -t tls-server .
docker run -p 6767:6767 -p 8080:8080 tls-server

# Docker Compose
AUTH_TOKEN=mysecrettoken docker-compose up -d
```

---

## Security Notes

- Certificates are self-signed and intended for lab/demo use
- Change `auth.token` in both config files before any real use
- Never commit `.key`, `.pem`, or `.crt` files — `.gitignore` already handles this

---

## License

MIT
