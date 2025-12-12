import os
import logging
from typing import Dict, Any, List

from src.crypto.aes_module import AESCipher
from src.crypto.ckks_module import CKKSContext
from src.crypto.data_classifier import DataClassifier

# Configure logging for encryption operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
    """
    Hybrid encryption system using AES-256-GCM for PII and CKKS for vitals.
    
    This class implements the core hybrid encryption architecture to prove H1
    (Security Efficacy) by routing different data types to appropriate
    encryption schemes based on their security and computational requirements.
    
    SIMD Optimization: Vitals are batched into CKKS vector slots for
    parallel processing, matching the optimized benchmark methodology.
    """
    
    def __init__(self, ckks: CKKSContext, key_manager: KeyManager):
        self.ckks = ckks
        self.key_manager = key_manager
        self.classification_metadata: Dict[str, Any] = {}

    def encrypt_patient_record(self, record: Dict[str, Any], aes_key: bytes) -> Dict[str, Any]:
        """
        Encrypt a patient record using hybrid encryption with SIMD batching.
        
        Uses DataClassifier to segment data:
        - PII fields → AES-256-GCM (fast, deterministic encryption)
        - Vitals fields → CKKS with SIMD batching (supports homomorphic computation)
        
        Args:
            record: Patient record dictionary
            aes_key: AES-256 key for PII encryption
            
        Returns:
            Encrypted record with classification metadata
        """
        # Segment record into PII and vitals using explicit classifier
        pii_dict, vitals_dict = DataClassifier.segment_record(record)
        
        # Log classification for thesis proof
        pii_count = len(pii_dict)
        vitals_count = len(vitals_dict)
        logger.info(f"Classified {pii_count} PII fields for AES, {vitals_count} vitals for CKKS (SIMD)")
        
        # Store classification metadata
        self.classification_metadata = {
            'pii_fields': list(pii_dict.keys()),
            'vitals_fields': list(vitals_dict.keys()),
            'pii_count': pii_count,
            'vitals_count': vitals_count,
            'simd_optimized': True  # Mark as SIMD optimized
        }
        
        out: Dict[str, Any] = {}
        
        # Encrypt PII fields with AES-256-GCM
        for field_name, value in pii_dict.items():
            val = value.encode("utf-8")
            out[field_name] = AESCipher.encrypt(val, aes_key)
            logger.debug(f"Encrypted PII field '{field_name}' with AES-256-GCM")
        
        # Encrypt vitals fields with CKKS using SIMD batching
        # Pack all vitals into a single vector for parallel processing
        if vitals_dict:
            vitals_names = list(vitals_dict.keys())
            vitals_values = [float(vitals_dict[name]) for name in vitals_names]
            
            # Encrypt all vitals in a single SIMD vector
            encrypted_vitals = self.ckks.encrypt_vector(vitals_values)
            
            # Store the encrypted vector with metadata for decryption
            out['_vitals_encrypted'] = encrypted_vitals
            out['_vitals_field_order'] = vitals_names
            logger.debug(f"Encrypted {len(vitals_names)} vitals with CKKS SIMD batching")
        
        # Add classification metadata to output
        out['_classification_metadata'] = self.classification_metadata
        
        return out

    def decrypt_patient_record(self, enc_record: Dict[str, Any], aes_key: bytes) -> Dict[str, Any]:
        """
        Decrypt a patient record encrypted with SIMD batching.
        
        Handles both legacy format (individual _enc fields) and new SIMD format
        (_vitals_encrypted with _vitals_field_order).
        """
        out: Dict[str, Any] = {}
        
        # Handle SIMD-batched vitals (new format)
        if '_vitals_encrypted' in enc_record and '_vitals_field_order' in enc_record:
            field_order = enc_record['_vitals_field_order']
            dec_values = self.ckks.decrypt_vector(enc_record['_vitals_encrypted'])
            for i, field_name in enumerate(field_order):
                if i < len(dec_values):
                    out[field_name] = float(dec_values[i])
        
        # Handle other fields
        for k, v in enc_record.items():
            if k in ('_vitals_encrypted', '_vitals_field_order', '_classification_metadata'):
                continue  # Skip metadata fields
            if isinstance(v, dict) and {"nonce", "ciphertext", "tag"} <= set(v.keys()):
                # AES encrypted field
                pt = AESCipher.decrypt(v, aes_key)
                out[k] = pt.decode("utf-8")
            elif k.endswith("_enc"):
                # Legacy format: individual CKKS encrypted field
                dec = self.ckks.decrypt_vector(v)
                base = k[:-4]
                out[base] = float(dec[0])
        
        return out

