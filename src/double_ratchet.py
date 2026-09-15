"""Double Ratchet (Signal): combina o DH ratchet (X25519) com ratchets simétricos
(HKDF/HMAC-SHA256) para derivar uma chave AES-256-GCM nova a cada mensagem.

Segue o pseudocódigo de referência em https://signal.org/docs/specifications/doubleratchet/,
com uma simplificação: a chave X25519 inicial de Bob é gerada localmente em `init_bob`
em vez de vir de um signed prekey publicado antecipadamente (X3DH completo).
"""

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto_primitives import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    dh,
    generate_x25519_keypair,
    hkdf,
)

MAX_SKIP = 100


@dataclass
class Header:
    dh_public: bytes
    pn: int
    n: int

    def to_wire(self) -> dict:
        return {"dh_public": self.dh_public.hex(), "pn": self.pn, "n": self.n}

    @classmethod
    def from_wire(cls, data: dict) -> "Header":
        return cls(dh_public=bytes.fromhex(data["dh_public"]), pn=data["pn"], n=data["n"])


def kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    output = hkdf(dh_output, salt=root_key, info=b"DoubleRatchetRootKey", length=64)
    return output[:32], output[32:]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    return next_chain_key, message_key


def _header_aad(associated_data: bytes, header: Header) -> bytes:
    return associated_data + header.dh_public + header.pn.to_bytes(4, "big") + header.n.to_bytes(4, "big")


@dataclass
class DoubleRatchet:
    dhs_private: X25519PrivateKey
    dhs_public: bytes
    dhr_public: bytes | None
    root_key: bytes
    chain_key_send: bytes | None = None
    chain_key_recv: bytes | None = None
    n_send: int = 0
    n_recv: int = 0
    pn: int = 0
    skipped_keys: dict = field(default_factory=dict)

    @classmethod
    def init_alice(cls, shared_secret: bytes, bob_dh_public: bytes) -> "DoubleRatchet":
        dhs_private, dhs_public = generate_x25519_keypair()
        root_key, chain_key_send = kdf_rk(shared_secret, dh(dhs_private, bob_dh_public))
        return cls(
            dhs_private=dhs_private,
            dhs_public=dhs_public,
            dhr_public=bob_dh_public,
            root_key=root_key,
            chain_key_send=chain_key_send,
        )

    @classmethod
    def init_bob(
        cls,
        shared_secret: bytes,
        keypair: tuple[X25519PrivateKey, bytes] | None = None,
    ) -> "DoubleRatchet":
        dhs_private, dhs_public = keypair if keypair is not None else generate_x25519_keypair()
        return cls(
            dhs_private=dhs_private,
            dhs_public=dhs_public,
            dhr_public=None,
            root_key=shared_secret,
        )

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> tuple[Header, bytes]:
        self.chain_key_send, message_key = kdf_ck(self.chain_key_send)
        header = Header(dh_public=self.dhs_public, pn=self.pn, n=self.n_send)
        self.n_send += 1
        ciphertext = aes_gcm_encrypt(message_key, plaintext, _header_aad(associated_data, header))
        return header, ciphertext

    def decrypt(self, header: Header, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        plaintext = self._try_skipped(header, ciphertext, associated_data)
        if plaintext is not None:
            return plaintext

        if header.dh_public != self.dhr_public:
            self._skip_message_keys(header.pn)
            self._dh_ratchet(header.dh_public)

        self._skip_message_keys(header.n)
        self.chain_key_recv, message_key = kdf_ck(self.chain_key_recv)
        self.n_recv += 1
        return aes_gcm_decrypt(message_key, ciphertext, _header_aad(associated_data, header))

    def _try_skipped(self, header: Header, ciphertext: bytes, associated_data: bytes) -> bytes | None:
        message_key = self.skipped_keys.pop((header.dh_public, header.n), None)
        if message_key is None:
            return None
        return aes_gcm_decrypt(message_key, ciphertext, _header_aad(associated_data, header))

    def _skip_message_keys(self, until: int) -> None:
        if self.chain_key_recv is None:
            return
        if until - self.n_recv > MAX_SKIP:
            raise RuntimeError("Número de mensagens puladas excede o limite permitido")
        while self.n_recv < until:
            self.chain_key_recv, message_key = kdf_ck(self.chain_key_recv)
            self.skipped_keys[(self.dhr_public, self.n_recv)] = message_key
            self.n_recv += 1

    def _dh_ratchet(self, new_dhr_public: bytes) -> None:
        self.pn = self.n_send
        self.n_send = 0
        self.n_recv = 0
        self.dhr_public = new_dhr_public
        self.root_key, self.chain_key_recv = kdf_rk(self.root_key, dh(self.dhs_private, self.dhr_public))
        self.dhs_private, self.dhs_public = generate_x25519_keypair()
        self.root_key, self.chain_key_send = kdf_rk(self.root_key, dh(self.dhs_private, self.dhr_public))
