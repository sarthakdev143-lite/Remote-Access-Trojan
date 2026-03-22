import argparse
import json
import socket
import ssl
import struct
import threading
from collections.abc import Mapping

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6767
DEFAULT_CERT_FILE = "server.crt"
DEFAULT_KEY_FILE = "server.key"
DEFAULT_CA_FILE = "ca.crt"

MAX_FRAME_BYTES = 1024 * 1024  # 1 MiB


def recv_exact(conn: ssl.SSLSocket, nbytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = nbytes
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(conn: ssl.SSLSocket) -> bytes:
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    if length == 0:
        return b""
    if length > MAX_FRAME_BYTES:
        raise ValueError(f"frame too large: {length} bytes")
    return recv_exact(conn, length)


def send_frame(conn: ssl.SSLSocket, payload: bytes) -> None:
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def send_json(conn: ssl.SSLSocket, message: Mapping[str, object]) -> None:
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    send_frame(conn, payload)


def recv_json(conn: ssl.SSLSocket) -> dict[str, object]:
    payload = recv_frame(conn)
    if not payload:
        return {}
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("expected JSON object")
    return decoded


def tls_server_context(
    *,
    cert_file: str,
    key_file: str,
    ca_file: str | None,
    require_client_cert: bool,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    # TLS 1.3 ciphers are configured by OpenSSL; for TLS 1.2 we can restrict.
    try:
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    except ssl.SSLError:
        pass

    if require_client_cert:
        if not ca_file:
            raise ValueError("--require-client-cert needs --ca-file")
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=ca_file)
    else:
        context.verify_mode = ssl.CERT_NONE

    return context


def _client_label(addr: tuple[str, int]) -> str:
    return f"{addr[0]}:{addr[1]}"


def handle_client(conn: ssl.SSLSocket, addr: tuple[str, int], *, idle_timeout_s: float) -> None:
    conn.settimeout(idle_timeout_s)
    label = _client_label(addr)

    cipher = conn.cipher()
    cipher_name = cipher[0] if cipher else "unknown-cipher"
    peer_cert = conn.getpeercert()
    peer_subject = None
    if peer_cert and isinstance(peer_cert, dict):
        peer_subject = peer_cert.get("subject")

    print(f"[*] Client connected: {label} {conn.version()} ({cipher_name})")
    if peer_subject:
        print(f"[*] Client cert subject: {peer_subject}")

    while True:
        try:
            msg = recv_json(conn)
        except TimeoutError:
            print(f"[*] Idle timeout, closing: {label}")
            return
        except ConnectionError:
            print(f"[*] Client disconnected: {label}")
            return
        except (ValueError, json.JSONDecodeError) as exc:
            send_json(conn, {"type": "error", "error": f"bad message: {exc}"})
            continue

        if not msg:
            continue

        msg_type = msg.get("type")
        if msg_type == "quit":
            send_json(conn, {"type": "bye"})
            print(f"[*] Closing session: {label}")
            return

        if msg_type == "ping":
            send_json(conn, {"type": "pong"})
            continue

        if msg_type == "info":
            send_json(
                conn,
                {
                    "type": "info",
                    "tls_version": conn.version(),
                    "cipher": cipher_name,
                    "peer": label,
                },
            )
            continue

        if msg_type == "echo":
            text = msg.get("text")
            if not isinstance(text, str):
                send_json(conn, {"type": "error", "error": "echo.text must be a string"})
                continue
            send_json(conn, {"type": "echo", "text": text})
            continue

        send_json(conn, {"type": "error", "error": f"unknown type: {msg_type!r}"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TLS framed echo server (safe demo)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--cert-file", default=DEFAULT_CERT_FILE)
    parser.add_argument("--key-file", default=DEFAULT_KEY_FILE)
    parser.add_argument("--ca-file", default=DEFAULT_CA_FILE)
    parser.add_argument("--require-client-cert", action="store_true")
    parser.add_argument("--idle-timeout", type=float, default=120.0)
    parser.add_argument("--backlog", type=int, default=64)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    context = tls_server_context(
        cert_file=args.cert_file,
        key_file=args.key_file,
        ca_file=args.ca_file if args.require_client_cert else None,
        require_client_cert=args.require_client_cert,
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((args.host, args.port))
        server_sock.listen(args.backlog)
        print(f"[*] TLS server listening on {args.host}:{args.port}")
        print(f"[*] Cert: {args.cert_file}  Key: {args.key_file}")
        if args.require_client_cert:
            print(f"[*] mTLS enabled (CA: {args.ca_file})")

        while True:
            raw_conn, addr = server_sock.accept()
            try:
                conn = context.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as exc:
                raw_conn.close()
                print(f"[!] TLS handshake failed from {_client_label(addr)}: {exc}")
                continue

            def run_client() -> None:
                with conn:
                    handle_client(conn, addr, idle_timeout_s=args.idle_timeout)

            thread = threading.Thread(target=run_client, daemon=True)
            thread.start()


if __name__ == "__main__":
    main()
