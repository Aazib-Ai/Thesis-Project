import os
import sys
import numpy as np
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext
from src.crypto.hybrid_encryption import KeyManager, HybridEncryptor
from src.analytics.statistics import homomorphic_mean


def test_hybrid_end_to_end_mean():
    km = KeyManager()
    ck = CKKSContext()
    ck.create_context()

    he = HybridEncryptor(ck, km)
    aes_key = km.generate_aes_key()

    df = pd.read_csv(os.path.join("data", "synthetic", "patients_1k.csv"))
    sub = df.head(10)
    hr_plain = sub["heart_rate"].astype(float).tolist()

    enc_records = [
        he.encrypt_patient_record(row.to_dict(), aes_key) for _, row in sub.iterrows()
    ]

    hr_enc = [rec["heart_rate_enc"] for rec in enc_records]
    mean_enc = homomorphic_mean(hr_enc)
    mean_dec = ck.decrypt_vector(mean_enc)[0]

    mean_plain = float(np.mean(hr_plain))
    assert abs(mean_dec - mean_plain) / mean_plain < 0.01

