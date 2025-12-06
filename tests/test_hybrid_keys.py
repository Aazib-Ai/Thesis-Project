import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.hybrid_encryption import KeyManager
from src.crypto.ckks_module import CKKSContext


def test_keymanager_encrypt_decrypt_aes_key_with_ckks():
    km = KeyManager()
    ck = CKKSContext()
    ck.create_context()
    aes = km.generate_aes_key()
    enc = km.encrypt_aes_key_with_ckks(aes, ck)
    dec = km.decrypt_aes_key_with_ckks(enc, ck)
    assert dec == aes

