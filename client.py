"""Send one sample authentication attempt to the local demo service."""

import argparse
import socket


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12348)
    args = parser.parse_args()
    with socket.create_connection((args.host, args.port), timeout=5) as client:
        client.settimeout(5)
        print(client.recv(1024).decode("utf-8", errors="replace"), end="")
        client.sendall(b"admin\n")
        print(client.recv(1024).decode("utf-8", errors="replace"), end="")
        client.sendall(b"example-password\n")
        print(client.recv(1024).decode("utf-8", errors="replace"), end="")


if __name__ == "__main__":
    main()
