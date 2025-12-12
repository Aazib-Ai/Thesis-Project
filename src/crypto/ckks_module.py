import tenseal as ts
from typing import List


class CKKSContext:
    def __init__(self):
        self.context = None

    def create_context(self, poly_degree: int = 8192):
        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly_degree,
            coeff_mod_bit_sizes=[60, 40, 40, 60],
        )
        self.context.global_scale = 2 ** 40
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()
        return self.context

    def generate_keys(self):
        if self.context is None:
            raise RuntimeError("Context not created")
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()
        return True

    def create_optimized_context(self):
        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=16384,
            coeff_mod_bit_sizes=[60, 40, 40, 40, 40, 60],
        )
        self.context.global_scale = 2 ** 40
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()
        return self.context

    def serialize_context(self, save_secret_key: bool = True) -> bytes:
        if self.context is None:
            raise RuntimeError("Context not created")
        return self.context.serialize(save_secret_key=save_secret_key)

    @staticmethod
    def deserialize_context(blob: bytes):
        ctx = ts.context_from(blob)
        return ctx

    def encrypt_vector(self, plaintext_vector: List[float]):
        if self.context is None:
            raise RuntimeError("Context not created")
        return ts.ckks_vector(self.context, plaintext_vector)

    def batch_encrypt(self, list_of_vectors: List[List[float]]):
        if self.context is None:
            raise RuntimeError("Context not created")
        flat = []
        for v in list_of_vectors:
            flat.extend(v)
        return ts.ckks_vector(self.context, flat)

    @staticmethod
    def decrypt_vector(ciphertext):
        return ciphertext.decrypt()

    @staticmethod
    def batch_decrypt(ciphertext, record_len: int):
        dec = ciphertext.decrypt()
        out = []
        for i in range(0, len(dec), record_len):
            out.append(dec[i : i + record_len])
        return out

    @staticmethod
    def add_encrypted(enc_a, enc_b):
        res = enc_a + enc_b
        return res

    @staticmethod
    def multiply_encrypted(enc_a, enc_b):
        res = enc_a * enc_b
        return res

    @staticmethod
    def add_plain(enc_a, plaintext: float):
        res = enc_a + plaintext
        return res

    def create_bfv_context(self, poly_degree: int = 8192, plain_modulus: int = 1032193):
        self.context = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree=poly_degree,
            plain_modulus=plain_modulus,
        )
        self.bfv_plain_modulus = plain_modulus
        return self.context

    def bfv_encrypt(self, ints: List[int]):
        if self.context is None:
            raise RuntimeError("Context not created")
        return ts.bfv_vector(self.context, ints)

    @staticmethod
    def bfv_decrypt(ciphertext):
        return ciphertext.decrypt()
