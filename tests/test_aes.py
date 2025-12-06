import os
import sys
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.aes_module import AESCipher


def test_key_generation():
    key = AESCipher.generate_key()
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_encrypt_decrypt():
    key = AESCipher.generate_key()
    payload = AESCipher.encrypt(b"hello world", key)
    decrypted = AESCipher.decrypt(payload, key)
    assert decrypted == b"hello world"


def test_encryption_randomness():
    key = AESCipher.generate_key()
    p1 = AESCipher.encrypt(b"same plaintext", key)
    p2 = AESCipher.encrypt(b"same plaintext", key)
    assert p1["nonce"] != p2["nonce"]
    assert p1["ciphertext"] != p2["ciphertext"]


def test_invalid_key():
    key_good = AESCipher.generate_key()
    payload = AESCipher.encrypt(b"secret", key_good)
    key_bad = AESCipher.generate_key()
    with pytest.raises(ValueError):
        AESCipher.decrypt(payload, key_bad)
