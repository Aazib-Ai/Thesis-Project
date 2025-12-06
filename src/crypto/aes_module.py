from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


class AESCipher:
    """AES-256-GCM encryption helper."""

    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 256-bit (32-byte) AES key."""
        return get_random_bytes(32)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> dict:
        """Encrypt plaintext bytes with AES-256-GCM.

        Returns a dict with base64-encoded fields: nonce, ciphertext, tag.
        """
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }

    @staticmethod
    def decrypt(payload: dict, key: bytes) -> bytes:
        """Decrypt payload produced by encrypt() using AES-256-GCM.

        Payload must include base64-encoded 'nonce', 'ciphertext', and 'tag'.
        Returns plaintext bytes.
        """
        nonce = base64.b64decode(payload["nonce"])  # type: ignore[index]
        ciphertext = base64.b64decode(payload["ciphertext"])  # type: ignore[index]
        tag = base64.b64decode(payload["tag"])  # type: ignore[index]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
