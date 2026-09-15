"""Cliente CLI (Alice ou Bob). Faz o handshake inicial em X25519 e troca mensagens
via Double Ratchet + AES-256-GCM através do servidor relay.

Uso:
    python client.py alice
    python client.py bob
"""

import json
import socket
import sys
import threading
from collections.abc import Iterator

from crypto_primitives import dh, generate_x25519_keypair, hkdf
from double_ratchet import DoubleRatchet, Header

HOST = "127.0.0.1"
PORT = 5050


def send_line(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode())


def recv_lines(sock: socket.socket) -> Iterator[dict]:
    buffer = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if line:
                yield json.loads(line)


def derive_shared_secret(my_private, peer_public_bytes: bytes) -> bytes:
    return hkdf(dh(my_private, peer_public_bytes), salt=b"", info=b"InitialHandshake-v1", length=32)


def handshake_bob(sock: socket.socket, lines: Iterator[dict]) -> DoubleRatchet:
    bob_private, bob_public = generate_x25519_keypair()
    send_line(sock, {"type": "prekey", "pub": bob_public.hex()})
    print("[bob] prekey enviada, aguardando Alice...")

    msg = next(lines)
    assert msg["type"] == "identity"
    alice_public = bytes.fromhex(msg["pub"])

    shared_secret = derive_shared_secret(bob_private, alice_public)
    ratchet = DoubleRatchet.init_bob(shared_secret, keypair=(bob_private, bob_public))
    print("[bob] handshake concluído, ratchet inicializado.\n")
    return ratchet


def handshake_alice(sock: socket.socket, lines: Iterator[dict]) -> DoubleRatchet:
    alice_private, alice_public = generate_x25519_keypair()

    msg = next(lines)
    assert msg["type"] == "prekey"
    bob_public = bytes.fromhex(msg["pub"])

    shared_secret = derive_shared_secret(alice_private, bob_public)
    ratchet = DoubleRatchet.init_alice(shared_secret, bob_public)

    send_line(sock, {"type": "identity", "pub": alice_public.hex()})
    print("[alice] handshake concluído, ratchet inicializado.\n")
    return ratchet


def receiver_loop(ratchet: DoubleRatchet, lines: Iterator[dict], name: str) -> None:
    for msg in lines:
        if msg.get("type") != "chat":
            continue
        header = Header.from_wire(msg["header"])
        ciphertext = bytes.fromhex(msg["ciphertext"])
        try:
            plaintext = ratchet.decrypt(header, ciphertext)
            print(f"\n[peer]: {plaintext.decode()}\n{name}> ", end="", flush=True)
        except Exception as exc:
            print(f"\n[!] falha ao decifrar mensagem recebida: {exc}\n{name}> ", end="", flush=True)


def sender_loop(sock: socket.socket, ratchet: DoubleRatchet, name: str) -> None:
    while True:
        try:
            text = input(f"{name}> ")
        except EOFError:
            return
        if not text:
            continue
        if ratchet.chain_key_send is None:
            print("[!] ainda não é possível enviar: aguardando a primeira mensagem do outro lado "
                  "(no Double Ratchet, quem responde só pode enviar depois de receber a 1ª mensagem)")
            continue
        header, ciphertext = ratchet.encrypt(text.encode())
        send_line(sock, {"type": "chat", "header": header.to_wire(), "ciphertext": ciphertext.hex()})


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("alice", "bob"):
        print("uso: python client.py [alice|bob]")
        sys.exit(1)
    name = sys.argv[1]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    lines = recv_lines(sock)

    ratchet = handshake_bob(sock, lines) if name == "bob" else handshake_alice(sock, lines)

    receiver = threading.Thread(target=receiver_loop, args=(ratchet, lines, name), daemon=True)
    receiver.start()
    sender_loop(sock, ratchet, name)


if __name__ == "__main__":
    main()
