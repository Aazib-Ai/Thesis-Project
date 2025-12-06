import os
import sys
import numpy as np
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext


def test_context_creation():
    mgr = CKKSContext()
    ctx = mgr.create_context()
    assert ctx is not None


def test_encrypt_decrypt_accuracy():
    mgr = CKKSContext()
    mgr.create_context()
    vec = [120.5, 80.3, 72.1, 98.6]
    enc = mgr.encrypt_vector(vec)
    dec = mgr.decrypt_vector(enc)
    assert np.allclose(np.array(dec), np.array(vec), atol=1e-2)


def test_homomorphic_addition():
    mgr = CKKSContext()
    mgr.create_context()
    a = mgr.encrypt_vector([5.0])
    b = mgr.encrypt_vector([3.0])
    c = mgr.add_encrypted(a, b)
    dec = mgr.decrypt_vector(c)
    assert np.allclose(dec, [8.0], atol=1e-2)


def test_homomorphic_multiplication():
    mgr = CKKSContext()
    mgr.create_context()
    a = mgr.encrypt_vector([2.0])
    b = mgr.encrypt_vector([4.0])
    c = mgr.multiply_encrypted(a, b)
    dec = mgr.decrypt_vector(c)
    assert np.allclose(dec, [8.0], atol=1e-2)

