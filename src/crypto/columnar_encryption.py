"""
Columnar Encryption Module for SIMD-Optimized CKKS Encryption

This module implements columnar (column-wise) encryption to enable true
homomorphic computation on encrypted data. Unlike row-wise encryption,
columnar encryption allows efficient operations across all values of a
single field without decryption.

Architecture:
- Row-wise (OLD): Each record encrypted separately → Cannot sum across records
- Columnar (NEW): All values of a field encrypted together → True homomorphic operations

Example:
    Row-wise: [{"hr": 70}, {"hr": 80}] → 2 ciphertexts (cannot sum)
    Columnar: {"hr": [70, 80]} → 1 ciphertext (can sum homomorphically)
"""

import os
import base64
import logging
from typing import Dict, List, Any, Tuple
import tenseal as ts

from src.crypto.data_classifier import DataClassifier
from src.crypto.ckks_module import CKKSContext

logger = logging.getLogger(__name__)


class ColumnarEncryptor:
    """
    Encrypts healthcare data in columnar format for SIMD-optimized homomorphic operations.
    
    This class transforms row-wise patient records into column-wise encrypted vectors,
    enabling efficient operations like sum, mean, and variance on encrypted data.
    """
    
    def __init__(self, ckks_context: CKKSContext, simd_slot_count: int = None):
        """
        Initialize the columnar encryptor.
        
        Args:
            ckks_context: CKKS context for encryption
            simd_slot_count: Maximum number of values per ciphertext (default: poly_degree / 2)
        """
        self.ckks = ckks_context
        
        # Determine SIMD slot count from context
        if simd_slot_count is None:
            # For poly_degree=16384, we get 8192 slots
            # This is a safe default for TenSEAL CKKS
            self.simd_slot_count = 8192
        else:
            self.simd_slot_count = simd_slot_count
            
        logger.info(f"ColumnarEncryptor initialized with SIMD slot count: {self.simd_slot_count}")
    
    def pivot_to_columns(self, records: List[Dict[str, Any]]) -> Tuple[Dict[str, List[str]], Dict[str, List[float]]]:
        """
        Transform row-wise records into column-wise format.
        
        Separates PII (for AES encryption) and vitals (for CKKS encryption) and
        pivots each category into columnar format.
        
        Args:
            records: List of patient record dictionaries
            
        Returns:
            Tuple of (pii_columns, vitals_columns)
            - pii_columns: Dict mapping PII field names to lists of string values
            - vitals_columns: Dict mapping vitals field names to lists of float values
            
        Example:
            >>> records = [
            ...     {"patient_id": "P001", "heart_rate": 70, "temperature": 98.6},
            ...     {"patient_id": "P002", "heart_rate": 80, "temperature": 99.1}
            ... ]
            >>> pii, vitals = encryptor.pivot_to_columns(records)
            >>> pii
            {'patient_id': ['P001', 'P002']}
            >>> vitals
            {'heart_rate': [70.0, 80.0], 'temperature': [98.6, 99.1]}
        """
        pii_columns: Dict[str, List[str]] = {}
        vitals_columns: Dict[str, List[float]] = {}
        
        for record in records:
            # Segment each record into PII and vitals
            pii_dict, vitals_dict = DataClassifier.segment_record(record)
            
            # Accumulate PII fields into columns
            for field_name, value in pii_dict.items():
                if field_name not in pii_columns:
                    pii_columns[field_name] = []
                pii_columns[field_name].append(value)
            
            # Accumulate vitals fields into columns
            for field_name, value in vitals_dict.items():
                if field_name not in vitals_columns:
                    vitals_columns[field_name] = []
                vitals_columns[field_name].append(value)
        
        logger.info(f"Pivoted {len(records)} records into {len(pii_columns)} PII columns and {len(vitals_columns)} vitals columns")
        
        return pii_columns, vitals_columns
    
    def encrypt_columns(self, columns: Dict[str, List[float]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Encrypt each column of vitals data with CKKS.
        
        Handles columns larger than SIMD slot count by splitting into multiple ciphertexts.
        Each column is encrypted independently to allow field-specific operations.
        
        Args:
            columns: Dictionary mapping field names to lists of float values
            
        Returns:
            Tuple of (encrypted_columns, metadata)
            - encrypted_columns: Dict mapping field names to encrypted data
            - metadata: Dict with encryption metadata (actual_count, column_names, etc.)
            
        Example:
            >>> columns = {"heart_rate": [70.0, 80.0, 90.0]}
            >>> enc_cols, metadata = encryptor.encrypt_columns(columns)
            >>> metadata['actual_count']
            {'heart_rate': 3}
        """
        encrypted_columns = {}
        actual_counts = {}
        
        for field_name, values in columns.items():
            actual_count = len(values)
            actual_counts[field_name] = actual_count
            
            # Handle large datasets that exceed SIMD slot count
            if actual_count <= self.simd_slot_count:
                # Single ciphertext can hold all values
                # Pad to SIMD slot count for consistent processing
                padded_values = values + [0.0] * (self.simd_slot_count - actual_count)
                encrypted_vector = self.ckks.encrypt_vector(padded_values)
                
                encrypted_columns[field_name] = {
                    'ciphertext': encrypted_vector,
                    'chunk_count': 1,
                    'actual_count': actual_count
                }
                
                logger.debug(f"Encrypted column '{field_name}' with {actual_count} values (single ciphertext)")
            else:
                # Need multiple ciphertexts
                chunks = []
                num_chunks = (actual_count + self.simd_slot_count - 1) // self.simd_slot_count
                
                for i in range(num_chunks):
                    start_idx = i * self.simd_slot_count
                    end_idx = min(start_idx + self.simd_slot_count, actual_count)
                    chunk_values = values[start_idx:end_idx]
                    
                    # Pad the last chunk if needed
                    if len(chunk_values) < self.simd_slot_count:
                        chunk_values = chunk_values + [0.0] * (self.simd_slot_count - len(chunk_values))
                    
                    encrypted_chunk = self.ckks.encrypt_vector(chunk_values)
                    chunks.append(encrypted_chunk)
                
                encrypted_columns[field_name] = {
                    'ciphertexts': chunks,
                    'chunk_count': num_chunks,
                    'actual_count': actual_count
                }
                
                logger.debug(f"Encrypted column '{field_name}' with {actual_count} values ({num_chunks} ciphertexts)")
        
        metadata = {
            'column_names': list(columns.keys()),
            'actual_counts': actual_counts,
            'simd_slot_count': self.simd_slot_count,
            'total_records': max(actual_counts.values()) if actual_counts else 0
        }
        
        logger.info(f"Encrypted {len(columns)} columns with total {metadata['total_records']} records")
        
        return encrypted_columns, metadata
    
    def save_encrypted_columns(self, encrypted_columns: Dict[str, Any], output_dir: str) -> None:
        """
        Save encrypted columns to disk as individual binary files.
        
        Creates a 'columns/' subdirectory and saves each column as a .bin file.
        
        Args:
            encrypted_columns: Dictionary of encrypted column data
            output_dir: Base directory for the encrypted dataset
        """
        columns_dir = os.path.join(output_dir, "columns")
        os.makedirs(columns_dir, exist_ok=True)
        
        for field_name, enc_data in encrypted_columns.items():
            field_path = os.path.join(columns_dir, f"{field_name}.bin")
            
            if enc_data['chunk_count'] == 1:
                # Single ciphertext - save directly
                ciphertext_bytes = enc_data['ciphertext'].serialize()
                with open(field_path, 'wb') as f:
                    f.write(ciphertext_bytes)
                logger.debug(f"Saved single ciphertext for '{field_name}' to {field_path}")
            else:
                # Multiple ciphertexts - concatenate with length prefixes
                with open(field_path, 'wb') as f:
                    # Write number of chunks as first 4 bytes
                    f.write(enc_data['chunk_count'].to_bytes(4, byteorder='little'))
                    
                    for chunk in enc_data['ciphertexts']:
                        chunk_bytes = chunk.serialize()
                        # Write chunk length as 4 bytes, then chunk data
                        f.write(len(chunk_bytes).to_bytes(4, byteorder='little'))
                        f.write(chunk_bytes)
                
                logger.debug(f"Saved {enc_data['chunk_count']} ciphertexts for '{field_name}' to {field_path}")
        
        logger.info(f"Saved {len(encrypted_columns)} encrypted columns to {columns_dir}")
    
    def load_encrypted_column(self, field_name: str, columns_dir: str, context: ts.Context) -> Dict[str, Any]:
        """
        Load an encrypted column from disk.
        
        Args:
            field_name: Name of the field to load
            columns_dir: Path to the columns directory
            context: TenSEAL context for deserialization
            
        Returns:
            Dictionary with ciphertext(s) and metadata
        """
        field_path = os.path.join(columns_dir, f"{field_name}.bin")
        
        if not os.path.exists(field_path):
            raise FileNotFoundError(f"Encrypted column file not found: {field_path}")
        
        with open(field_path, 'rb') as f:
            data = f.read()
        
        # Check if this is a multi-chunk file (first 4 bytes indicate chunk count)
        if len(data) >= 4:
            chunk_count = int.from_bytes(data[:4], byteorder='little')
            
            # If chunk_count is 1 and file is small, it's likely a single ciphertext
            # stored without the chunk count prefix (backward compatibility)
            if chunk_count > 1 and chunk_count < 1000:  # Sanity check
                # Multi-chunk file
                chunks = []
                offset = 4
                
                for _ in range(chunk_count):
                    chunk_len = int.from_bytes(data[offset:offset+4], byteorder='little')
                    offset += 4
                    chunk_bytes = data[offset:offset+chunk_len]
                    offset += chunk_len
                    
                    chunk = ts.ckks_vector_from(context, chunk_bytes)
                    chunks.append(chunk)
                
                return {
                    'ciphertexts': chunks,
                    'chunk_count': chunk_count
                }
        
        # Single ciphertext (entire file is one ciphertext)
        ciphertext = ts.ckks_vector_from(context, data)
        return {
            'ciphertext': ciphertext,
            'chunk_count': 1
        }
