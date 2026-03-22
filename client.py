import argparse
import json
import socket
import ssl
import struct
from datetime import datetime
from pathlib import Path
from collections.abc import Mapping

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6767
DEFAULT_SERVER_NAME = "localhost"
DEFAULT_CA_FILE = "server.crt"
DEFAULT_CLIENT_CERT = "client.crt"
DEFAULT_CLIENT_KEY = "client.key"
DEFAULT_SCREENSHOT_DIR = "screenshots"

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TLS framed echo client (safe demo)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--server-name", default=DEFAULT_SERVER_NAME)
    parser.add_argument("--ca-file", default=DEFAULT_CA_FILE)
    parser.add_argument("--client-cert", default=DEFAULT_CLIENT_CERT)
    parser.add_argument("--client-key", default=DEFAULT_CLIENT_KEY)
    parser.add_argument("--use-client-cert", action="store_true")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--screenshot-dir", default=DEFAULT_SCREENSHOT_DIR)
    return parser.parse_args()


def save_local_screenshot(*, out_dir: str) -> Path:
    """
    Captures the *local* screen and saves it to disk.

    For safety, this project intentionally does NOT send screenshots over the network.
    """
    try:
        from PIL import ImageGrab  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "Screenshot support requires Pillow. Install it with: pip install pillow"
        ) from exc

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = directory / f"screenshot-{timestamp}.png"

    image = ImageGrab.grab()
    image.save(path, format="PNG")
    return path


def main() -> None:
    args = parse_args()

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    if args.use_client_cert:
        context.load_cert_chain(certfile=args.client_cert, keyfile=args.client_key)

    with socket.create_connection((args.host, args.port)) as sock:
        with context.wrap_socket(sock, server_hostname=args.server_name) as tls_sock:
            tls_sock.settimeout(args.timeout)
            cipher = tls_sock.cipher()
            cipher_name = cipher[0] if cipher else "unknown-cipher"
            print(
                f"[*] Connected to {args.host}:{args.port} "
                f"with {tls_sock.version()} ({cipher_name})"
            )
            print("[*] Commands: /ping  /info  /quit  /screenshot")

            while True:
                try:
                    line = input("Message> ").strip()
                except KeyboardInterrupt:
                    print("\n[*] Closing connection.")
                    return

                if not line:
                    continue

                if line == "/quit":
                    send_json(tls_sock, {"type": "quit"})
                    try:
                        reply = recv_json(tls_sock)
                        if reply.get("type") == "bye":
                            print("[*] Server replied: bye")
                    except Exception:
                        pass
                    return

                if line == "/screenshot":
                    try:
                        path = save_local_screenshot(out_dir=args.screenshot_dir)
                    except RuntimeError as exc:
                        print(f"[!] {exc}")
                        continue
                    print(f"[*] Saved local screenshot: {path}")
                    continue

                if line == "/ping":
                    send_json(tls_sock, {"type": "ping"})
                elif line == "/info":
                    send_json(tls_sock, {"type": "info"})
                else:
                    send_json(tls_sock, {"type": "echo", "text": line})

                try:
                    reply = recv_json(tls_sock)
                except TimeoutError:
                    print("[!] Timed out waiting for server.")
                    continue
                except ConnectionError:
                    print("[!] Server closed the connection.")
                    return

                print(f"Server replied: {reply}")


if __name__ == "__main__":
    main()
