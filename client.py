import socket
import ssl

HOST = "127.0.0.1"
PORT = 6767
SERVER_NAME = "localhost"
CA_FILE = "server.crt"


def main() -> None:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_NAME) as tls_sock:
            cipher = tls_sock.cipher()
            cipher_name = cipher[0] if cipher else "unknown-cipher"
            print(
                f"[*] Connected to {HOST}:{PORT} "
                f"with {tls_sock.version()} ({cipher_name})"
            )

            while True:
                try:
                    message = input("Message> ").strip()
                except KeyboardInterrupt:
                    print("\n[*] Closing connection.")
                    break

                if not message:
                    continue

                tls_sock.sendall(message.encode("utf-8"))
                if message.lower() == "quit":
                    print("[*] Closing connection.")
                    break

                response = tls_sock.recv(4096)
                if not response:
                    print("[!] Server closed the connection.")
                    break

                print(f"Server replied: {response.decode('utf-8')}")


if __name__ == "__main__":
    main()
