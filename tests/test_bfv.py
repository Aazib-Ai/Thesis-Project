import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext


def test_bfv_encrypt_decrypt_simple():
    ctx = CKKSContext()
    ctx.create_bfv_context()
    enc = ctx.bfv_encrypt([3])
    dec = ctx.bfv_decrypt(enc)
    assert dec == [3]


def test_bfv_sum_integers():
    ctx = CKKSContext()
    ctx.create_bfv_context()
    a = ctx.bfv_encrypt([5])
    b = ctx.bfv_encrypt([7])
    s = a + b
    dec = ctx.bfv_decrypt(s)
    val = dec[0]
    if val < 0:
        val += ctx.bfv_plain_modulus
    assert val == 12

