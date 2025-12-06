import os
from typing import Dict, Any, List

from src.crypto.aes_module import AESCipher
from src.crypto.ckks_module import CKKSContext


class KeyManager:
    def __init__(self, keys_dir: str = os.path.join("data", "keys")):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)

    def generate_aes_key(self) -> bytes:
        return AESCipher.generate_key()

    def store_key(self, key_id: str, key: bytes) -> str:
        path = os.path.join(self.keys_dir, f"{key_id}.bin")
        with open(path, "wb") as f:
            f.write(key)
        return path

    def encrypt_aes_key_with_ckks(self, aes_key: bytes, ckks: CKKSContext):
        ints = [float(b) for b in aes_key]
        return ckks.encrypt_vector(ints)

    def decrypt_aes_key_with_ckks(self, enc_key, ckks: CKKSContext) -> bytes:
        vals = ckks.decrypt_vector(enc_key)
        ints = [int(round(v)) % 256 for v in vals]
        return bytes(ints)


class HybridEncryptor:
    def __init__(self, ckks: CKKSContext, key_manager: KeyManager):
        self.ckks = ckks
        self.key_manager = key_manager

    def encrypt_patient_record(self, record: Dict[str, Any], aes_key: bytes) -> Dict[str, Any]:
        pii_fields = ["patient_id", "name", "address", "phone", "email"]
        vitals_fields = [
            "heart_rate",
            "blood_pressure_sys",
            "blood_pressure_dia",
            "temperature",
            "glucose",
        ]

        out: Dict[str, Any] = {}
        for f in pii_fields:
            if f in record:
                val = str(record[f]).encode("utf-8")
                out[f] = AESCipher.encrypt(val, aes_key)

        for f in vitals_fields:
            if f in record:
                v = float(record[f])
                out[f + "_enc"] = self.ckks.encrypt_vector([v])

        return out

    def decrypt_patient_record(self, enc_record: Dict[str, Any], aes_key: bytes) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in enc_record.items():
            if isinstance(v, dict) and {"nonce", "ciphertext", "tag"} <= set(v.keys()):
                pt = AESCipher.decrypt(v, aes_key)
                out[k] = pt.decode("utf-8")
            elif k.endswith("_enc"):
                dec = self.ckks.decrypt_vector(v)
                base = k[:-4]
                out[base] = float(dec[0])
        return out

