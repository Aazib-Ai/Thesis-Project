"""
Columnar Statistics Module for True Homomorphic Computation

This module provides homomorphic statistical operations on columnar encrypted data.
Unlike row-wise encryption, columnar operations work on entire columns at once,
enabling efficient computation without server-side decryption.

Key Features:
- True homomorphic sum, mean, and variance
- Support for multi-ciphertext columns (>8192 records)
- No server-side decryption - results stay encrypted
- Accurate handling of padding via actual_count metadata

Architecture:
- Each column stored as encrypted vector(s)
- Operations use TenSEAL's native CKKS operations
- Results returned as encrypted ciphertexts for client-side decryption
"""

import logging
from typing import Dict, List, Any, Union
import tenseal as ts

logger = logging.getLogger(__name__)


class ColumnarStatistics:
    """
    Provides homomorphic statistical operations on columnar encrypted data.
    
    All operations maintain encryption throughout computation and return
    encrypted results. This ensures data-in-use security.
    """
    
    @staticmethod
    def homomorphic_sum_slots(encrypted_vector: ts.CKKSVector) -> ts.CKKSVector:
        """
        Sum all slots in an encrypted CKKS vector homomorphically.
        
        Uses TenSEAL's native .sum() operation which performs slot-wise
        summation without decryption.
        
        Args:
            encrypted_vector: Encrypted CKKS vector containing data slots
            
        Returns:
            Encrypted CKKS vector containing the sum in slot 0
            
        Example:
            >>> ctx = create_context()
            >>> enc = ctx.encrypt([10.0, 20.0, 30.0])
            >>> result_enc = ColumnarStatistics.homomorphic_sum_slots(enc)
            >>> result_enc.decrypt()[0]  # 60.0
            60.0
            
        Note:
            Result is still encrypted. Must decrypt client-side to see value.
        """
        try:
            # TenSEAL's sum() performs homomorphic summation of all slots
            result = encrypted_vector.sum()
            logger.debug(f"Computed homomorphic sum (result encrypted)")
            return result
        except Exception as e:
            logger.error(f"Error in homomorphic_sum_slots: {e}")
            raise
    
    @staticmethod
    def homomorphic_mean_columnar(encrypted_vector: ts.CKKSVector, actual_count: int) -> ts.CKKSVector:
        """
        Compute mean of encrypted column homomorphically.
        
        Formula: Mean = Sum(all values) / actual_count
        
        Handles padding correctly by using actual_count from metadata rather
        than total slot count. For example, with 100 records in 8192 slots,
        actual_count=100 ensures correct mean.
        
        Args:
            encrypted_vector: Encrypted CKKS vector containing column data
            actual_count: Number of actual data points (excluding padding)
            
        Returns:
            Encrypted CKKS vector containing the mean in slot 0
            
        Example:
            >>> values = [70.0, 80.0, 90.0]  # Mean = 80.0
            >>> ctx = create_context()
            >>> enc = ctx.encrypt(values)
            >>> result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc, 3)
            >>> result_enc.decrypt()[0]
            80.0
        """
        try:
            if actual_count <= 0:
                raise ValueError(f"actual_count must be positive, got {actual_count}")
            
            # Sum all slots homomorphically
            total = encrypted_vector.sum()
            
            # Multiply by 1/n to get mean (scalar multiplication is homomorphic)
            mean = total * (1.0 / actual_count)
            
            logger.debug(f"Computed homomorphic mean for {actual_count} records (result encrypted)")
            return mean
        except Exception as e:
            logger.error(f"Error in homomorphic_mean_columnar: {e}")
            raise
    
    @staticmethod
    def homomorphic_variance_columnar(encrypted_vector: ts.CKKSVector, actual_count: int) -> ts.CKKSVector:
        """
        Compute variance of encrypted column homomorphically.
        
        Formula: Var(X) = E[X²] - E[X]²
        Where:
        - E[X²] = mean of squared values
        - E[X]² = square of mean
        
        This approach avoids decryption by using only homomorphic operations:
        - Square each slot: enc_vector.square()
        - Sum and average: .sum() and scalar multiplication
        - Subtract: homomorphic subtraction
        
        Args:
            encrypted_vector: Encrypted CKKS vector containing column data
            actual_count: Number of actual data points (excluding padding)
            
        Returns:
            Encrypted CKKS vector containing the variance in slot 0
            
        Example:
            >>> values = [10.0, 20.0, 30.0]  # Variance = 66.67
            >>> ctx = create_context()
            >>> enc = ctx.encrypt(values)
            >>> result_enc = ColumnarStatistics.homomorphic_variance_columnar(enc, 3)
            >>> abs(result_enc.decrypt()[0] - 66.67) < 0.1
            True
        """
        try:
            if actual_count <= 0:
                raise ValueError(f"actual_count must be positive, got {actual_count}")
            
            # E[X] = mean
            mean_enc = ColumnarStatistics.homomorphic_mean_columnar(encrypted_vector, actual_count)
            
            # X²
            squared_vector = encrypted_vector.square()
            
            # E[X²] = mean of squared values
            mean_of_squares_enc = ColumnarStatistics.homomorphic_mean_columnar(squared_vector, actual_count)
            
            # E[X]²
            square_of_mean_enc = mean_enc.square()
            
            # Var(X) = E[X²] - E[X]²
            variance_enc = mean_of_squares_enc - square_of_mean_enc
            
            logger.debug(f"Computed homomorphic variance for {actual_count} records (result encrypted)")
            return variance_enc
        except Exception as e:
            logger.error(f"Error in homomorphic_variance_columnar: {e}")
            raise
    
    @staticmethod
    def handle_multi_ciphertext_sum(ciphertexts: List[ts.CKKSVector], actual_counts: List[int]) -> ts.CKKSVector:
        """
        Sum across multiple ciphertext chunks for large datasets (>8192 records).
        
        When a column has more records than fit in one ciphertext, it's split
        into multiple chunks. This function aggregates across all chunks.
        
        Args:
            ciphertexts: List of encrypted CKKS vectors (chunks)
            actual_counts: Number of actual values in each chunk
            
        Returns:
            Encrypted CKKS vector containing the total sum
            
        Example:
            >>> # Dataset with 10,000 records split into 2 chunks
            >>> chunk1 = ctx.encrypt([...8192 values...])
            >>> chunk2 = ctx.encrypt([...1808 values...])
            >>> result_enc = ColumnarStatistics.handle_multi_ciphertext_sum(
            ...     [chunk1, chunk2], [8192, 1808]
            ... )
        """
        try:
            if not ciphertexts:
                raise ValueError("ciphertexts list cannot be empty")
            
            # Sum each chunk
            chunk_sums = [chunk.sum() for chunk in ciphertexts]
            
            # Add all chunk sums together
            total_sum = chunk_sums[0]
            for chunk_sum in chunk_sums[1:]:
                total_sum = total_sum + chunk_sum
            
            logger.debug(f"Computed multi-ciphertext sum across {len(ciphertexts)} chunks")
            return total_sum
        except Exception as e:
            logger.error(f"Error in handle_multi_ciphertext_sum: {e}")
            raise
    
    @staticmethod
    def handle_multi_ciphertext_mean(ciphertexts: List[ts.CKKSVector], actual_counts: List[int]) -> ts.CKKSVector:
        """
        Compute mean across multiple ciphertext chunks.
        
        Args:
            ciphertexts: List of encrypted CKKS vectors (chunks)
            actual_counts: Number of actual values in each chunk
            
        Returns:
            Encrypted CKKS vector containing the mean
        """
        try:
            total_sum = ColumnarStatistics.handle_multi_ciphertext_sum(ciphertexts, actual_counts)
            total_count = sum(actual_counts)
            mean = total_sum * (1.0 / total_count)
            
            logger.debug(f"Computed multi-ciphertext mean for {total_count} total records")
            return mean
        except Exception as e:
            logger.error(f"Error in handle_multi_ciphertext_mean: {e}")
            raise
    
    @staticmethod
    def handle_multi_ciphertext_variance(ciphertexts: List[ts.CKKSVector], actual_counts: List[int]) -> ts.CKKSVector:
        """
        Compute variance across multiple ciphertext chunks.
        
        Uses the same formula as single ciphertext: Var(X) = E[X²] - E[X]²
        but aggregates across chunks.
        
        Args:
            ciphertexts: List of encrypted CKKS vectors (chunks)
            actual_counts: Number of actual values in each chunk
            
        Returns:
            Encrypted CKKS vector containing the variance
        """
        try:
            # Compute global mean across all chunks
            mean_enc = ColumnarStatistics.handle_multi_ciphertext_mean(ciphertexts, actual_counts)
            
            # Square each chunk and compute mean of squares
            squared_chunks = [chunk.square() for chunk in ciphertexts]
            mean_of_squares_enc = ColumnarStatistics.handle_multi_ciphertext_mean(squared_chunks, actual_counts)
            
            # Variance = E[X²] - E[X]²
            square_of_mean_enc = mean_enc.square()
            variance_enc = mean_of_squares_enc - square_of_mean_enc
            
            total_count = sum(actual_counts)
            logger.debug(f"Computed multi-ciphertext variance for {total_count} total records")
            return variance_enc
        except Exception as e:
            logger.error(f"Error in handle_multi_ciphertext_variance: {e}")
            raise
    
    @staticmethod
    def compute_operation(enc_col: Dict[str, Any], operation: str) -> ts.CKKSVector:
        """
        Unified interface for computing operations on encrypted columns.
        
        Automatically handles both single and multi-ciphertext columns.
        
        Args:
            enc_col: Encrypted column data (from ColumnarEncryptor.load_encrypted_column)
            operation: One of 'sum', 'mean', 'variance'
            
        Returns:
            Encrypted result
            
        Raises:
            ValueError: If operation is unknown
        """
        chunk_count = enc_col.get('chunk_count', 1)
        
        if chunk_count == 1:
            # Single ciphertext
            enc_vector = enc_col['ciphertext']
            actual_count = enc_col.get('actual_count', 1)
            
            if operation == 'sum':
                return ColumnarStatistics.homomorphic_sum_slots(enc_vector)
            elif operation == 'mean':
                return ColumnarStatistics.homomorphic_mean_columnar(enc_vector, actual_count)
            elif operation == 'variance':
                return ColumnarStatistics.homomorphic_variance_columnar(enc_vector, actual_count)
            else:
                raise ValueError(f"Unknown operation: {operation}")
        else:
            # Multi-ciphertext
            ciphertexts = enc_col['ciphertexts']
            
            # For multi-ciphertext, we need actual_counts per chunk
            # This should be in metadata, but if not, estimate from total
            total_actual = enc_col.get('actual_count', len(ciphertexts) * 8192)
            chunk_size = 8192
            actual_counts = []
            for i in range(len(ciphertexts)):
                if i < len(ciphertexts) - 1:
                    actual_counts.append(chunk_size)
                else:
                    # Last chunk may be partial
                    actual_counts.append(total_actual - (chunk_size * i))
            
            if operation == 'sum':
                return ColumnarStatistics.handle_multi_ciphertext_sum(ciphertexts, actual_counts)
            elif operation == 'mean':
                return ColumnarStatistics.handle_multi_ciphertext_mean(ciphertexts, actual_counts)
            elif operation == 'variance':
                return ColumnarStatistics.handle_multi_ciphertext_variance(ciphertexts, actual_counts)
            else:
                raise ValueError(f"Unknown operation: {operation}")
