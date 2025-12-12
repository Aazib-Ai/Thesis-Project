"""
AES-256-GCM Encryption Module for PII Protection

This module implements AES-256-GCM (Advanced Encryption Standard with 
Galois/Counter Mode) for encrypting Personally Identifiable Information (PII)
in the hybrid encryption system.

Standards Compliance:
- Algorithm: AES-256 (NIST FIPS 197)
- Mode: GCM (Galois/Counter Mode) - NIST SP 800-38D
- Key Size: 256 bits (32 bytes)
- Nonce Size: 96 bits (12 bytes)
- Authentication Tag: 128 bits (16 bytes)

Security Properties:
- Confidentiality: 256-bit security level
- Authenticity: GCM provides authenticated encryption
- Integrity: Authentication tag prevents tampering
- Semantic Security: Probabilistic encryption (unique nonce per operation)

Implementation:
- Library: PyCryptodome 3.19.0
- Post-Quantum Consideration: AES-256 provides 128-bit quantum security (Grover's algorithm)

Security Rationale for PII:
PII fields (patient_id, name, address, phone, email, dob) require:
- Fast encryption/decryption (< 1ms per record)
- Deterministic access patterns (quick lookups)
- Compact ciphertext (minimal storage overhead ~1.1x)
- Strong authentication (prevent unauthorized modifications)

AES-256-GCM satisfies all requirements while maintaining NIST compliance.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


class AESCipher:
    """
    AES-256-GCM encryption helper for PII protection (NIST FIPS 197).
    
    Implements authenticated encryption with associated data (AEAD) to ensure
    both confidentiality and integrity of encrypted PII fields.
    """

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a random 256-bit (32-byte) AES key.
        
        Uses cryptographically secure random number generation (CSPRNG)
        from the operating system's entropy source.
        
        Returns:
            32-byte AES-256 key
            
        Security:
            - 256-bit keyspace (2^256 possible keys)
            - Post-quantum security: 128-bit against Grover's algorithm
            - NIST recommended key strength for TOP SECRET data
        """
        return get_random_bytes(32)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> dict:
        """
        Encrypt plaintext bytes with AES-256-GCM.
        
        Provides authenticated encryption with:
        - Confidentiality: AES-256 encryption
        - Authenticity: GCM authentication tag
        - Integrity: Tag verification on decryption
        
        Args:
            plaintext: Raw bytes to encrypt (typically UTF-8 encoded strings)
            key: 32-byte AES-256 key
            
        Returns:
            Dictionary with base64-encoded fields:
            - nonce: 12-byte initialization vector (unique per encryption)
            - ciphertext: Encrypted data
            - tag: 16-byte authentication tag (MAC)
            
        Security Notes:
            - Nonce MUST be unique per encryption (guaranteed by CSPRNG)
            - Tag provides integrity: any tampering will fail decryption
            - GCM mode prevents chosen-ciphertext attacks
            
        Example:
            >>> key = AESCipher.generate_key()
            >>> plaintext = b"John Doe"
            >>> ciphertext_dict = AESCipher.encrypt(plaintext, key)
            >>> ciphertext_dict.keys()
            dict_keys(['nonce', 'ciphertext', 'tag'])
        """
        # Generate unique 12-byte nonce (NIST SP 800-38D recommendation)
        nonce = get_random_bytes(12)
        
        # Create AES-256-GCM cipher instance
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt and compute authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Return base64-encoded components for JSON serialization
        return {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }

    @staticmethod
    def decrypt(payload: dict, key: bytes) -> bytes:
        """
        Decrypt payload produced by encrypt() using AES-256-GCM.
        
        Verifies authentication tag before returning plaintext, ensuring:
        - Data was encrypted with the correct key
        - Data has not been modified (integrity check)
        - Data is authentic (not forged)
        
        Args:
            payload: Dictionary with base64-encoded 'nonce', 'ciphertext', and 'tag'
            key: 32-byte AES-256 key (must match encryption key)
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            ValueError: If authentication tag verification fails (tampering detected)
            KeyError: If payload is missing required fields
            
        Security Notes:
            - Tag verification is MANDATORY (enforced by GCM mode)
            - Any bit flip in ciphertext or tag will cause decryption failure
            - Prevents padding oracle attacks (GCM is not vulnerable)
            
        Example:
            >>> decrypted = AESCipher.decrypt(ciphertext_dict, key)
            >>> decrypted.decode("utf-8")
            'John Doe'
        """
        # Decode base64-encoded components
        nonce = base64.b64decode(payload["nonce"])  # type: ignore[index]
        ciphertext = base64.b64decode(payload["ciphertext"])  # type: ignore[index]
        tag = base64.b64decode(payload["tag"])  # type: ignore[index]
        
        # Create AES-256-GCM cipher with same nonce
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt and verify authentication tag (atomically)
        # Raises ValueError if tag verification fails
        return cipher.decrypt_and_verify(ciphertext, tag)
