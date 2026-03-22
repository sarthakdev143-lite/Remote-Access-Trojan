import socket
import ssl

HOST = "127.0.0.1"
PORT = 6767
CERT_FILE = "server.crt"
KEY_FILE = "server.key"


def handle_client(conn: ssl.SSLSocket, addr: tuple[str, int]) -> None:
    cipher = conn.cipher()
    cipher_name = cipher[0] if cipher else "unknown-cipher"
    print(
        f"[*] Client connected from {addr} "
        f"using {conn.version()} ({cipher_name})"
    )

    while True:
        data = conn.recv(4096)
        if not data:
            print("[*] Client disconnected.")
            break

        message = data.decode("utf-8").strip()
        print(f"Received: {message}")

        if message.lower() == "quit":
            conn.sendall(b"bye")
            print("[*] Closing session.")
            break

        conn.sendall(f"echo: {message}".encode("utf-8"))


def main() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        print(f"[*] TLS echo server listening on {HOST}:{PORT}")

        with context.wrap_socket(server_sock, server_side=True) as tls_server:
            while True:
                conn, addr = tls_server.accept()
                with conn:
                    handle_client(conn, addr)


if __name__ == "__main__":
    main()
