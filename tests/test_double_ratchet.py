import os
import sys

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from double_ratchet import DoubleRatchet  # noqa: E402


def make_pair() -> tuple[DoubleRatchet, DoubleRatchet]:
    shared_secret = os.urandom(32)
    bob = DoubleRatchet.init_bob(shared_secret)
    alice = DoubleRatchet.init_alice(shared_secret, bob.dhs_public)
    return alice, bob


def test_single_message_alice_to_bob():
    alice, bob = make_pair()
    header, ciphertext = alice.encrypt(b"ola bob")
    plaintext = bob.decrypt(header, ciphertext)
    assert plaintext == b"ola bob"


def test_ping_pong_triggers_dh_ratchet():
    alice, bob = make_pair()
    alice_dh_before = alice.dhs_public

    header, ct = alice.encrypt(b"msg 1 de alice")
    assert bob.decrypt(header, ct) == b"msg 1 de alice"

    header, ct = bob.encrypt(b"msg 1 de bob")
    assert alice.decrypt(header, ct) == b"msg 1 de bob"

    # ao receber a primeira mensagem de Bob, Alice deve ter girado seu DH ratchet
    assert alice.dhs_public != alice_dh_before

    header, ct = alice.encrypt(b"msg 2 de alice")
    assert bob.decrypt(header, ct) == b"msg 2 de alice"


def test_forward_secrecy_keys_change_each_message():
    alice, bob = make_pair()
    _, ct1 = alice.encrypt(b"primeira")
    ck_after_first = alice.chain_key_send
    _, ct2 = alice.encrypt(b"segunda")
    ck_after_second = alice.chain_key_send
    assert ck_after_first != ck_after_second
    assert ct1 != ct2


def test_out_of_order_delivery():
    alice, bob = make_pair()
    h1, ct1 = alice.encrypt(b"mensagem 1")
    h2, ct2 = alice.encrypt(b"mensagem 2")
    h3, ct3 = alice.encrypt(b"mensagem 3")

    assert bob.decrypt(h3, ct3) == b"mensagem 3"
    assert bob.decrypt(h1, ct1) == b"mensagem 1"
    assert bob.decrypt(h2, ct2) == b"mensagem 2"


def test_tampered_ciphertext_is_rejected():
    alice, bob = make_pair()
    header, ciphertext = alice.encrypt(b"mensagem confidencial")
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        bob.decrypt(header, bytes(tampered))


def test_long_conversation_both_directions():
    alice, bob = make_pair()
    for i in range(10):
        h, ct = alice.encrypt(f"alice->bob {i}".encode())
        assert bob.decrypt(h, ct) == f"alice->bob {i}".encode()
        h, ct = bob.encrypt(f"bob->alice {i}".encode())
        assert alice.decrypt(h, ct) == f"bob->alice {i}".encode()
