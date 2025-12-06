import os
import sys
import numpy as np
import pandas as pd
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext
from src.analytics.statistics import homomorphic_mean, homomorphic_variance


def test_homomorphic_mean_simple():
    mgr = CKKSContext()
    mgr.create_context()
    vals = [10.0, 20.0, 30.0]
    enc = [mgr.encrypt_vector([v]) for v in vals]
    mean_enc = homomorphic_mean(enc)
    dec = mgr.decrypt_vector(mean_enc)
    assert np.allclose(dec, [20.0], atol=1e-2)


def test_statistics_on_real_data():
    mgr = CKKSContext()
    mgr.create_context()
    path = os.path.join("data", "synthetic", "patients_1k.csv")
    df = pd.read_csv(path)
    hr = df["heart_rate"].astype(float).tolist()
    enc_vals = [mgr.encrypt_vector([v]) for v in hr]

    mean_enc = homomorphic_mean(enc_vals)
    var_enc = homomorphic_variance(enc_vals)

    mean_dec = mgr.decrypt_vector(mean_enc)[0]
    var_dec = mgr.decrypt_vector(var_enc)[0]

    mean_plain = float(np.mean(hr))
    var_plain = float(np.var(hr))

    assert abs(mean_dec - mean_plain) / mean_plain < 0.01
    assert abs(var_dec - var_plain) / (var_plain if var_plain != 0 else 1.0) < 0.01

