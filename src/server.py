"""Servidor relay: encaminha mensagens entre Alice e Bob sem nunca decifrá-las.

O servidor enxerga apenas o envelope JSON (tipo da mensagem, remetente, tamanho);
o campo "ciphertext" é opaco para ele, pois não possui nenhuma chave privada.
Isso demonstra na prática o modelo "zero-trust" em relação ao transporte/servidor.
"""

import socket
import threading

HOST = "127.0.0.1"
PORT = 5050


def relay(source: socket.socket, destination: socket.socket, label: str) -> None:
    with source:
        buffer = b""
        try:
            while True:
                chunk = source.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line:
                        continue
                    print(f"[server] repassando {len(line)} bytes de {label} (conteúdo ilegível para o servidor)")
                    destination.sendall(line + b"\n")
        except OSError:
            pass
    print(f"[server] conexão de {label} encerrada")


def main() -> None:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(2)
    print(f"[server] aguardando Alice e Bob em {HOST}:{PORT}...")

    conn_a, addr_a = server_socket.accept()
    print(f"[server] primeiro cliente conectado: {addr_a}")
    conn_b, addr_b = server_socket.accept()
    print(f"[server] segundo cliente conectado: {addr_b}")

    t1 = threading.Thread(target=relay, args=(conn_a, conn_b, "cliente-1"), daemon=True)
    t2 = threading.Thread(target=relay, args=(conn_b, conn_a, "cliente-2"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    server_socket.close()
    print("[server] encerrado")


if __name__ == "__main__":
    main()
