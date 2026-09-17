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
    private_bytes = private_key.private_bytes_raw()
    public_bytes = private_key.public_key().public_bytes_raw()
    print(f"chave privada: {private_bytes.hex()} - chave pública: {public_bytes.hex()}")
    return private_key, public_bytes


def dh(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    secret = private_key.exchange(peer_public_key)
    print(f"chave publica do peer: {peer_public_key.public_bytes_raw().hex()} - secret obtido: {secret.hex()}")
    return secret


def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    hkdf_key = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(input_key_material)
    print(f"chave base: {input_key_material.hex()}, salt: {salt.hex()}, info: {info.hex()} - chave após hkdf: {hkdf_key.hex()}")
    return hkdf_key


def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    nonce = os.urandom(GCM_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    print(f"[encrypt] mensagem original: {plaintext} - chave: {key.hex()} - texto cifrado: {ciphertext.hex()}")
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, payload: bytes, associated_data: bytes = b"") -> bytes:
    nonce, ciphertext = payload[:GCM_NONCE_LEN], payload[GCM_NONCE_LEN:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    print(f"[decrypt] mensagem original: {plaintext} - chave: {key.hex()} - texto cifrado: {ciphertext.hex()}")
    return plaintext
