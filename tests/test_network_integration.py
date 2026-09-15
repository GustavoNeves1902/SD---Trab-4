import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import server as server_module  # noqa: E402
from client import handshake_alice, handshake_bob, recv_lines, send_line  # noqa: E402
from double_ratchet import Header  # noqa: E402


def start_server_in_background() -> None:
    threading.Thread(target=server_module.main, daemon=True).start()
    time.sleep(0.3)


def test_end_to_end_handshake_and_messages_over_socket():
    start_server_in_background()
    results: dict[str, bytes] = {}
    errors: list[Exception] = []

    def bob_thread() -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_module.HOST, server_module.PORT))
            lines = recv_lines(sock)
            ratchet = handshake_bob(sock, lines)

            msg = next(lines)
            header = Header.from_wire(msg["header"])
            ciphertext = bytes.fromhex(msg["ciphertext"])
            results["bob_received"] = ratchet.decrypt(header, ciphertext)

            header, ct = ratchet.encrypt(b"oi alice, aqui e o bob")
            send_line(sock, {"type": "chat", "header": header.to_wire(), "ciphertext": ct.hex()})
            sock.close()
        except Exception as exc:  # pragma: no cover - só para diagnóstico em falha
            errors.append(exc)

    def alice_thread() -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_module.HOST, server_module.PORT))
            lines = recv_lines(sock)
            ratchet = handshake_alice(sock, lines)

            header, ct = ratchet.encrypt(b"oi bob, aqui e a alice")
            send_line(sock, {"type": "chat", "header": header.to_wire(), "ciphertext": ct.hex()})

            msg = next(lines)
            header = Header.from_wire(msg["header"])
            ciphertext = bytes.fromhex(msg["ciphertext"])
            results["alice_received"] = ratchet.decrypt(header, ciphertext)
            sock.close()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    tb = threading.Thread(target=bob_thread)
    ta = threading.Thread(target=alice_thread)
    tb.start()
    ta.start()
    tb.join(timeout=5)
    ta.join(timeout=5)

    assert not errors, errors
    assert results.get("bob_received") == b"oi bob, aqui e a alice"
    assert results.get("alice_received") == b"oi alice, aqui e o bob"
