"""
Comprehensive accuracy tests for CKKS encryption system.

This module tests the accuracy metrics calculation and validates that CKKS
homomorphic encryption maintains the required accuracy levels:
- Mean accuracy: 99.99%+
- Variance accuracy: 99.9%+
- Sum accuracy: high precision

Tests cover:
1. Accuracy calculation correctness (MSE, RMSE, accuracy percentage)
2. CKKS accuracy on all operations (mean, variance, sum)
3. Accuracy degradation across dataset sizes
4. Edge cases (zero values, large values, negative values)
"""

import os
import sys
import numpy as np
import pytest
from typing import List

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext
from src.analytics.accuracy_metrics import (
    calculate_mse,
    calculate_rmse,
    calculate_accuracy_percentage,
    calculate_relative_error_percentage,
    generate_accuracy_report
)


class TestAccuracyCalculations:
    """Test the correctness of accuracy metric calculations."""
    
    def test_mse_with_known_values(self):
        """Test MSE calculation with known inputs and expected outputs."""
        # Perfect match should give MSE = 0
        plaintext = [1.0, 2.0, 3.0, 4.0]
        decrypted = [1.0, 2.0, 3.0, 4.0]
        mse = calculate_mse(plaintext, decrypted)
        assert mse == 0.0, "MSE should be 0 for perfect match"
        
        # Known MSE value
        plaintext = [1.0, 2.0, 3.0]
        decrypted = [1.1, 2.1, 3.1]
        # Error = [0.1, 0.1, 0.1], MSE = mean([0.01, 0.01, 0.01]) = 0.01
        mse = calculate_mse(plaintext, decrypted)
        assert np.isclose(mse, 0.01, atol=1e-6), f"Expected MSE=0.01, got {mse}"
        
        # Larger error
        plaintext = [10.0, 20.0, 30.0]
        decrypted = [11.0, 22.0, 33.0]
        # Error = [1, 2, 3], MSE = mean([1, 4, 9]) = 14/3
        expected_mse = (1 + 4 + 9) / 3
        mse = calculate_mse(plaintext, decrypted)
        assert np.isclose(mse, expected_mse, atol=1e-6), f"Expected MSE={expected_mse}, got {mse}"
    
    def test_rmse_calculation(self):
        """Test RMSE calculation (should be sqrt of MSE)."""
        plaintext = [1.0, 2.0, 3.0]
        decrypted = [1.1, 2.1, 3.1]
        
        mse = calculate_mse(plaintext, decrypted)
        rmse = calculate_rmse(plaintext, decrypted)
        
        assert np.isclose(rmse, np.sqrt(mse), atol=1e-6), "RMSE should equal sqrt(MSE)"
        assert np.isclose(rmse, 0.1, atol=1e-6), "RMSE should be 0.1 for uniform 0.1 error"
    
    def test_accuracy_percentage_calculation(self):
        """Test accuracy percentage calculation with various tolerances."""
        plaintext = [1.0, 2.0, 3.0, 4.0, 5.0]
        
        # All values within tolerance
        decrypted = [1.005, 2.005, 3.005, 4.005, 5.005]
        accuracy = calculate_accuracy_percentage(plaintext, decrypted, tolerance=0.01)
        assert accuracy == 100.0, "All values within tolerance should give 100% accuracy"
        
        # Half within tolerance
        decrypted = [1.005, 2.005, 3.05, 4.05, 5.05]  # Last 3 exceed 0.01 tolerance
        accuracy = calculate_accuracy_percentage(plaintext, decrypted, tolerance=0.01)
        assert accuracy == 40.0, "2/5 within tolerance should give 40% accuracy"
        
        # None within tolerance
        decrypted = [10.0, 20.0, 30.0, 40.0, 50.0]
        accuracy = calculate_accuracy_percentage(plaintext, decrypted, tolerance=0.01)
        assert accuracy == 0.0, "No values within tolerance should give 0% accuracy"
    
    def test_relative_error_percentage(self):
        """Test relative error percentage calculation."""
        # 10% relative error
        rel_error = calculate_relative_error_percentage(100.0, 110.0)
        assert np.isclose(rel_error, 10.0, atol=1e-6), "Should be 10% relative error"
        
        # 5% relative error
        rel_error = calculate_relative_error_percentage(200.0, 210.0)
        assert np.isclose(rel_error, 5.0, atol=1e-6), "Should be 5% relative error"
        
        # Zero plaintext value (edge case)
        rel_error = calculate_relative_error_percentage(0.0, 0.5)
        assert rel_error >= 0, "Should handle zero plaintext gracefully"
    
    def test_mse_length_mismatch(self):
        """Test that MSE raises error on length mismatch."""
        plaintext = [1.0, 2.0, 3.0]
        decrypted = [1.0, 2.0]
        
        with pytest.raises(ValueError, match="Length mismatch"):
            calculate_mse(plaintext, decrypted)
    
    def test_accuracy_percentage_length_mismatch(self):
        """Test that accuracy percentage raises error on length mismatch."""
        plaintext = [1.0, 2.0, 3.0]
        decrypted = [1.0, 2.0]
        
        with pytest.raises(ValueError, match="Length mismatch"):
            calculate_accuracy_percentage(plaintext, decrypted)


class TestEdgeCases:
    """Test edge cases for accuracy metrics."""
    
    def test_zero_values(self):
        """Test accuracy metrics with zero values."""
        plaintext = [0.0, 0.0, 0.0]
        decrypted = [0.0, 0.0, 0.0]
        
        mse = calculate_mse(plaintext, decrypted)
        rmse = calculate_rmse(plaintext, decrypted)
        accuracy = calculate_accuracy_percentage(plaintext, decrypted)
        
        assert mse == 0.0, "MSE should be 0 for matching zeros"
        assert rmse == 0.0, "RMSE should be 0 for matching zeros"
        assert accuracy == 100.0, "Accuracy should be 100% for matching zeros"
    
    def test_large_values(self):
        """Test accuracy metrics with large values."""
        plaintext = [1e6, 2e6, 3e6]
        decrypted = [1e6 + 1, 2e6 + 1, 3e6 + 1]
        
        mse = calculate_mse(plaintext, decrypted)
        rmse = calculate_rmse(plaintext, decrypted)
        
        # Error is 1 for each value, so MSE = 1
        assert np.isclose(mse, 1.0, atol=1e-6), "MSE should be 1"
        assert np.isclose(rmse, 1.0, atol=1e-6), "RMSE should be 1"
    
    def test_negative_values(self):
        """Test accuracy metrics with negative values."""
        plaintext = [-100.0, -200.0, -300.0]
        decrypted = [-100.1, -200.1, -300.1]
        
        mse = calculate_mse(plaintext, decrypted)
        accuracy = calculate_accuracy_percentage(plaintext, decrypted, tolerance=0.2)
        
        assert mse > 0, "MSE should be positive for mismatched values"
        assert accuracy == 100.0, "All values within tolerance=0.2"
    
    def test_mixed_values(self):
        """Test accuracy metrics with mixed positive and negative values."""
        plaintext = [-10.0, 0.0, 10.0, 100.0]
        decrypted = [-10.01, 0.01, 10.01, 100.01]
        
        mse = calculate_mse(plaintext, decrypted)
        accuracy = calculate_accuracy_percentage(plaintext, decrypted, tolerance=0.02)
        
        assert mse > 0, "MSE should be positive"
        assert accuracy == 100.0, "All values within tolerance"
    
    def test_empty_arrays(self):
        """Test accuracy metrics with empty arrays."""
        plaintext = []
        decrypted = []
        
        # MSE should handle empty arrays
        mse = calculate_mse(plaintext, decrypted)
        # NumPy mean of empty array returns nan
        assert np.isnan(mse) or mse == 0, "MSE of empty arrays should be nan or 0"
        
        # Accuracy percentage should return 0 for empty arrays
        accuracy = calculate_accuracy_percentage(plaintext, decrypted)
        assert accuracy == 0.0, "Accuracy of empty arrays should be 0"


class TestCKKSAccuracy:
    """Test CKKS encryption accuracy on various operations."""
    
    @pytest.fixture
    def ckks_context(self):
        """Create a CKKS context for testing."""
        context = CKKSContext()
        context.create_context()
        return context
    
    def test_mean_accuracy(self, ckks_context):
        """Test that CKKS mean computation achieves 99.99%+ accuracy."""
        # Test data
        data = [120.5, 80.3, 72.1, 98.6, 110.2, 95.7, 88.4, 102.3]
        plaintext_mean = np.mean(data)
        
        # Encrypt data
        encrypted_values = [ckks_context.encrypt_vector([val]) for val in data]
        
        # Compute encrypted sum then divide by count
        encrypted_sum = encrypted_values[0]
        for enc in encrypted_values[1:]:
            encrypted_sum = ckks_context.add_encrypted(encrypted_sum, enc)
        
        # Decrypt and compute mean
        decrypted_sum = ckks_context.decrypt_vector(encrypted_sum)[0]
        decrypted_mean = decrypted_sum / len(data)
        
        # Calculate accuracy
        relative_error = abs(plaintext_mean - decrypted_mean) / abs(plaintext_mean) * 100
        accuracy = 100 - relative_error
        
        assert accuracy >= 99.99, f"Mean accuracy should be >= 99.99%, got {accuracy}%"
    
    def test_variance_accuracy(self, ckks_context):
        """Test that CKKS variance computation achieves 99.9%+ accuracy."""
        # Test data
        data = [120.5, 80.3, 72.1, 98.6, 110.2, 95.7, 88.4, 102.3]
        plaintext_mean = np.mean(data)
        plaintext_variance = np.var(data, ddof=0)  # Population variance
        
        # Encrypt data
        encrypted_values = [ckks_context.encrypt_vector([val]) for val in data]
        
        # Compute encrypted mean
        encrypted_sum = encrypted_values[0]
        for enc in encrypted_values[1:]:
            encrypted_sum = ckks_context.add_encrypted(encrypted_sum, enc)
        decrypted_mean = ckks_context.decrypt_vector(encrypted_sum)[0] / len(data)
        
        # Compute variance: E[(X - mean)^2]
        # For simplicity, use E[X^2] - (E[X])^2
        encrypted_squared_sum = None
        for val in data:
            enc_val = ckks_context.encrypt_vector([val])
            enc_squared = ckks_context.multiply_encrypted(enc_val, enc_val)
            if encrypted_squared_sum is None:
                encrypted_squared_sum = enc_squared
            else:
                encrypted_squared_sum = ckks_context.add_encrypted(encrypted_squared_sum, enc_squared)
        
        decrypted_squared_mean = ckks_context.decrypt_vector(encrypted_squared_sum)[0] / len(data)
        decrypted_variance = decrypted_squared_mean - (decrypted_mean ** 2)
        
        # Calculate accuracy
        relative_error = abs(plaintext_variance - decrypted_variance) / abs(plaintext_variance) * 100
        accuracy = 100 - relative_error
        
        assert accuracy >= 99.9, f"Variance accuracy should be >= 99.9%, got {accuracy}%"
    
    def test_sum_accuracy(self, ckks_context):
        """Test that CKKS sum computation maintains high accuracy."""
        # Test data
        data = [120.5, 80.3, 72.1, 98.6, 110.2]
        plaintext_sum = sum(data)
        
        # Encrypt and sum
        encrypted_values = [ckks_context.encrypt_vector([val]) for val in data]
        encrypted_sum = encrypted_values[0]
        for enc in encrypted_values[1:]:
            encrypted_sum = ckks_context.add_encrypted(encrypted_sum, enc)
        
        decrypted_sum = ckks_context.decrypt_vector(encrypted_sum)[0]
        
        # Calculate accuracy
        relative_error = abs(plaintext_sum - decrypted_sum) / abs(plaintext_sum) * 100
        accuracy = 100 - relative_error
        
        assert accuracy >= 99.99, f"Sum accuracy should be >= 99.99%, got {accuracy}%"
        assert np.isclose(plaintext_sum, decrypted_sum, rtol=1e-4), "Sum should be very close"
    
    def test_encrypt_decrypt_roundtrip(self, ckks_context):
        """Test basic encryption/decryption roundtrip accuracy."""
        data = [42.5, 37.8, 91.2, 65.4]
        
        encrypted = [ckks_context.encrypt_vector([val]) for val in data]
        decrypted = [ckks_context.decrypt_vector(enc)[0] for enc in encrypted]
        
        mse = calculate_mse(data, decrypted)
        rmse = calculate_rmse(data, decrypted)
        accuracy = calculate_accuracy_percentage(data, decrypted, tolerance=0.01)
        
        assert mse < 1e-4, f"MSE should be very small, got {mse}"
        assert rmse < 0.01, f"RMSE should be < 0.01, got {rmse}"
        assert accuracy >= 99.0, f"Accuracy should be >= 99%, got {accuracy}%"


class TestAccuracyAcrossDatasetSizes:
    """Test accuracy degradation across different dataset sizes."""
    
    @pytest.fixture
    def ckks_context(self):
        """Create a CKKS context for testing."""
        context = CKKSContext()
        context.create_context()
        return context
    
    def test_accuracy_1k_dataset(self, ckks_context):
        """Test accuracy on 1K dataset."""
        np.random.seed(42)
        data = np.random.uniform(50, 150, 1000).tolist()
        
        # Sample a subset for testing (to keep test time reasonable)
        sample = data[:100]
        
        encrypted = [ckks_context.encrypt_vector([val]) for val in sample]
        decrypted = [ckks_context.decrypt_vector(enc)[0] for enc in encrypted]
        
        accuracy = calculate_accuracy_percentage(sample, decrypted, tolerance=0.1)
        
        assert accuracy >= 99.0, f"1K dataset accuracy should be >= 99%, got {accuracy}%"
    
    def test_accuracy_10k_dataset(self, ckks_context):
        """Test accuracy on 10K dataset (sampled)."""
        np.random.seed(43)
        data = np.random.uniform(50, 150, 10000).tolist()
        
        # Sample for testing
        sample = data[:100]
        
        encrypted = [ckks_context.encrypt_vector([val]) for val in sample]
        decrypted = [ckks_context.decrypt_vector(enc)[0] for enc in encrypted]
        
        accuracy = calculate_accuracy_percentage(sample, decrypted, tolerance=0.1)
        
        assert accuracy >= 99.0, f"10K dataset accuracy should be >= 99%, got {accuracy}%"
    
    def test_no_significant_degradation(self, ckks_context):
        """Test that accuracy doesn't degrade significantly with dataset size."""
        np.random.seed(44)
        
        accuracies = []
        
        for size in [10, 50, 100]:
            data = np.random.uniform(50, 150, size).tolist()
            encrypted = [ckks_context.encrypt_vector([val]) for val in data]
            decrypted = [ckks_context.decrypt_vector(enc)[0] for enc in encrypted]
            
            accuracy = calculate_accuracy_percentage(data, decrypted, tolerance=0.1)
            accuracies.append(accuracy)
        
        # All accuracies should be similar (within 1%)
        max_degradation = max(accuracies) - min(accuracies)
        assert max_degradation < 1.0, f"Accuracy degradation should be < 1%, got {max_degradation}%"


class TestGenerateAccuracyReport:
    """Test the generate_accuracy_report function."""
    
    @pytest.fixture
    def ckks_context(self):
        """Create a CKKS context for testing."""
        context = CKKSContext()
        context.create_context()
        return context
    
    def test_accuracy_report_generation(self, ckks_context):
        """Test that accuracy report generation works correctly."""
        plaintext = [100.0, 200.0, 300.0]
        encrypted = [ckks_context.encrypt_vector([val]) for val in plaintext]
        
        report = generate_accuracy_report(plaintext, encrypted, ckks_context)
        
        # Check report structure
        assert "mse" in report, "Report should contain MSE"
        assert "rmse" in report, "Report should contain RMSE"
        assert "accuracy_pct" in report, "Report should contain accuracy percentage"
        assert "decrypted_values" in report, "Report should contain decrypted values"
        
        # Check report values
        assert isinstance(report["mse"], (float, np.floating)), "MSE should be a float"
        assert isinstance(report["rmse"], (float, np.floating)), "RMSE should be a float"
        assert isinstance(report["accuracy_pct"], (float, np.floating)), "Accuracy should be a float"
        assert isinstance(report["decrypted_values"], list), "Decrypted values should be a list"
        assert len(report["decrypted_values"]) == len(plaintext), "Should have same number of decrypted values"
        
        # Check accuracy is high
        assert report["accuracy_pct"] >= 99.0, f"Accuracy should be >= 99%, got {report['accuracy_pct']}%"
        assert report["mse"] < 1.0, f"MSE should be very small, got {report['mse']}"


class TestMultiplicativeDepth:
    """Test accuracy with operations requiring different multiplicative depths."""
    
    @pytest.fixture
    def ckks_context(self):
        """Create a CKKS context for testing."""
        context = CKKSContext()
        context.create_context()
        return context
    
    def test_single_multiplication(self, ckks_context):
        """Test accuracy after single multiplication (depth 1)."""
        a = ckks_context.encrypt_vector([10.0])
        b = ckks_context.encrypt_vector([5.0])
        
        c = ckks_context.multiply_encrypted(a, b)
        result = ckks_context.decrypt_vector(c)[0]
        
        expected = 50.0
        relative_error = abs(expected - result) / expected * 100
        
        assert relative_error < 0.1, f"Single multiplication should have < 0.1% error, got {relative_error}%"
    
    def test_nested_multiplications(self, ckks_context):
        """Test accuracy after nested multiplications (higher depth)."""
        # ((2 * 3) * 4) = 24
        a = ckks_context.encrypt_vector([2.0])
        b = ckks_context.encrypt_vector([3.0])
        c = ckks_context.encrypt_vector([4.0])
        
        temp = ckks_context.multiply_encrypted(a, b)
        result_enc = ckks_context.multiply_encrypted(temp, c)
        result = ckks_context.decrypt_vector(result_enc)[0]
        
        expected = 24.0
        relative_error = abs(expected - result) / expected * 100
        
        # Allow slightly higher error for nested operations
        assert relative_error < 1.0, f"Nested multiplications should have < 1% error, got {relative_error}%"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
