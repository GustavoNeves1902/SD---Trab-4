"""Primitivas criptográficas base: X25519 (ECDH), HKDF-SHA256 e AES-256-GCM."""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_KEY_LEN = 32
GCM_NONCE_LEN = 12


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_bytes


def dh(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public_key)


def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(input_key_material)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    nonce = os.urandom(GCM_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, payload: bytes, associated_data: bytes = b"") -> bytes:
    nonce, ciphertext = payload[:GCM_NONCE_LEN], payload[GCM_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
