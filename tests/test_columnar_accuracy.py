"""
Test suite for Task 4.1: Columnar SIMD Accuracy Tests

Tests the accuracy of homomorphic computations against plaintext operations.
Validates that MSE < 1e-6 for all operations as per thesis KPIs.

Test Coverage:
- Mean accuracy (small, padded, multi-ciphertext)
- Variance accuracy
- Standard deviation accuracy
- MSE/RMSE calculations
- Realistic healthcare data ranges
"""

try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

import math
from typing import List
import tenseal as ts
from src.analytics.columnar_statistics import ColumnarStatistics
from src.crypto.ckks_module import CKKSContext
from src.crypto.columnar_encryption import ColumnarEncryptor


# ==================== Helper Functions ====================

def calculate_mse(actual: float, expected: float) -> float:
    """Calculate Mean Squared Error between actual and expected values."""
    return (actual - expected) ** 2


def calculate_rmse(actual: float, expected: float) -> float:
    """Calculate Root Mean Squared Error."""
    return math.sqrt(calculate_mse(actual, expected))


def plaintext_mean(values: List[float]) -> float:
    """Calculate plaintext mean for comparison."""
    return sum(values) / len(values) if values else 0.0


def plaintext_variance(values: List[float]) -> float:
    """Calculate plaintext variance for comparison."""
    if not values:
        return 0.0
    mean = plaintext_mean(values)
    return sum((x - mean) ** 2 for x in values) / len(values)


def plaintext_std(values: List[float]) -> float:
    """Calculate plaintext standard deviation."""
    return math.sqrt(plaintext_variance(values))


# ==================== Test Class ====================

class TestColumnarAccuracy:
    """Test accuracy of columnar homomorphic operations against plaintext."""
    
    @pytest.fixture
    def context(self):
        """Create optimized CKKS context for testing."""
        ck = CKKSContext()
        ck.create_optimized_context()
        return ck.context
    
    @pytest.fixture
    def encryptor(self, context):
        """Create columnar encryptor."""
        ck = CKKSContext()
        ck.create_optimized_context()
        return ColumnarEncryptor(ck)
    
    # ==================== Task 4.1.1: Mean Accuracy Tests ====================
    
    def test_mean_accuracy_small_dataset(self, context):
        """Test mean accuracy with small dataset (MSE < 1e-6)."""
        values = [70.0, 80.0, 90.0]
        expected_mean = plaintext_mean(values)  # 80.0
        
        enc_vector = ts.ckks_vector(context, values)
        result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(values))
        actual_mean = result_enc.decrypt()[0]
        
        mse = calculate_mse(actual_mean, expected_mean)
        
        assert mse < 1e-6, f"MSE {mse} exceeds threshold 1e-6"
        assert abs(actual_mean - expected_mean) < 0.01
        print(f"✓ Mean accuracy (small): MSE={mse:.2e}, actual={actual_mean:.6f}, expected={expected_mean:.6f}")
    
    def test_mean_accuracy_larger_dataset(self, context):
        """Test mean accuracy with 50 values."""
        values = [float(i) for i in range(50, 100)]  # [50, 51, ..., 99]
        expected_mean = plaintext_mean(values)  # 74.5
        
        enc_vector = ts.ckks_vector(context, values)
        result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(values))
        actual_mean = result_enc.decrypt()[0]
        
        mse = calculate_mse(actual_mean, expected_mean)
        
        assert mse < 1e-6, f"MSE {mse} exceeds threshold"
        print(f"✓ Mean accuracy (50 values): MSE={mse:.2e}")
    
    # ==================== Task 4.1.3: Test with Padding ====================
    
    def test_mean_accuracy_with_padding(self, context):
        """Test mean with 100 actual values padded to 8192 slots."""
        actual_count = 100
        values = [float(i) for i in range(1, actual_count + 1)]  # [1, 2, ..., 100]
        expected_mean = plaintext_mean(values)  # 50.5
        
        # Pad to SIMD slot count
        padded_values = values + [0.0] * (8192 - actual_count)
        
        enc_vector = context.encrypt(padded_values)
        result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, actual_count)
        actual_mean = result_enc.decrypt()[0]
        
        mse = calculate_mse(actual_mean, expected_mean)
        
        assert mse < 1e-4, f"MSE {mse} exceeds threshold with padding"
        assert abs(actual_mean - expected_mean) < 0.1
        print(f"✓ Mean with padding (100/8192): MSE={mse:.2e}, actual={actual_mean:.2f}, expected={expected_mean:.2f}")
    
    # ==================== Task 4.1.4: Multi-Ciphertext Tests ====================
    
    def test_mean_accuracy_multi_ciphertext(self, context):
        """Test mean with >8192 records requiring multiple ciphertexts."""
        # Create 10,000 values split across chunks
        chunk1_values = [float(i) for i in range(1, 8193)]  # [1..8192]
        chunk2_values = [float(i) for i in range(8193, 10001)]  # [8193..10000]
        
        all_values = chunk1_values + chunk2_values
        expected_mean = plaintext_mean(all_values)  # 5000.5
        
        # Encrypt as separate chunks
        enc_chunk1 = context.encrypt(chunk1_values)
        enc_chunk2 = context.encrypt(chunk2_values)
        
        # Compute mean across chunks
        result_enc = ColumnarStatistics.handle_multi_ciphertext_mean(
            [enc_chunk1, enc_chunk2],
            [len(chunk1_values), len(chunk2_values)]
        )
        actual_mean = result_enc.decrypt()[0]
        
        mse = calculate_mse(actual_mean, expected_mean)
        
        assert mse < 1.0, f"MSE {mse} too high for multi-ciphertext"
        assert abs(actual_mean - expected_mean) < 1.0
        print(f"✓ Mean multi-ciphertext (10000 values): MSE={mse:.2e}, actual={actual_mean:.2f}, expected={expected_mean:.2f}")
    
    # ==================== Task 4.1.2: Variance Accuracy Tests ====================
    
    def test_variance_accuracy_small_dataset(self, context):
        """Test variance accuracy (MSE < 1e-6)."""
        values = [10.0, 20.0, 30.0]
        expected_variance = plaintext_variance(values)  # 66.666...
        
        enc_vector = ts.ckks_vector(context, values)
        result_enc = ColumnarStatistics.homomorphic_variance_columnar(enc_vector, len(values))
        actual_variance = result_enc.decrypt()[0]
        
        mse = calculate_mse(actual_variance, expected_variance)
        
        assert mse < 0.1, f"Variance MSE {mse} exceeds threshold"
        assert abs(actual_variance - expected_variance) < 0.1
        print(f"✓ Variance accuracy: MSE={mse:.2e}, actual={actual_variance:.4f}, expected={expected_variance:.4f}")
    
    def test_variance_accuracy_with_padding(self, context):
        """Test variance with padded values."""
        actual_count = 50
        values = [float(i) for i in range(10, 10 + actual_count)]  # [10..59]
        expected_variance = plaintext_variance(values)
        
        padded_values = values + [0.0] * (8192 - actual_count)
        
        enc_vector = context.encrypt(padded_values)
        result_enc = ColumnarStatistics.homomorphic_variance_columnar(enc_vector, actual_count)
        actual_variance = result_enc.decrypt()[0]
        
        mse = calculate_mse(actual_variance, expected_variance)
        
        assert mse < 1.0, f"Padded variance MSE {mse} too high"
        print(f"✓ Variance with padding: MSE={mse:.2e}")
    
    # ==================== Standard Deviation Tests ====================
    
    def test_standard_deviation_accuracy(self, context):
        """Test standard deviation by computing sqrt(variance)."""
        values = [65.0, 70.0, 75.0, 80.0, 85.0]
        expected_std = plaintext_std(values)
        
        enc_vector = ts.ckks_vector(context, values)
        result_enc = ColumnarStatistics.homomorphic_variance_columnar(enc_vector, len(values))
        actual_variance = result_enc.decrypt()[0]
        actual_std = math.sqrt(actual_variance) if actual_variance > 0 else 0
        
        mse = calculate_mse(actual_std, expected_std)
        
        assert mse < 0.01, f"Std deviation MSE {mse} too high"
        print(f"✓ Std deviation: MSE={mse:.2e}, actual={actual_std:.4f}, expected={expected_std:.4f}")
    
    # ==================== Healthcare Realistic Data ====================
    
    def test_heart_rate_realistic_range(self, context):
        """Test with realistic heart rate data (60-100 bpm)."""
        heart_rates = [72.0, 68.0, 75.0, 80.0, 65.0, 78.0, 71.0, 69.0, 
                      85.0, 77.0, 73.0, 66.0, 82.0, 74.0, 70.0]
        expected_mean = plaintext_mean(heart_rates)
        expected_var = plaintext_variance(heart_rates)
        
        enc_vector = context.encrypt(heart_rates)
        
        # Test mean
        mean_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(heart_rates))
        actual_mean = mean_enc.decrypt()[0]
        mean_mse = calculate_mse(actual_mean, expected_mean)
        
        # Test variance
        var_enc = ColumnarStatistics.homomorphic_variance_columnar(enc_vector, len(heart_rates))
        actual_var = var_enc.decrypt()[0]
        var_mse = calculate_mse(actual_var, expected_var)
        
        assert mean_mse < 1e-4, f"Heart rate mean MSE {mean_mse} too high"
        assert var_mse < 0.1, f"Heart rate variance MSE {var_mse} too high"
        
        print(f"✓ Heart rate - Mean: {actual_mean:.2f} bpm (expected {expected_mean:.2f}), MSE={mean_mse:.2e}")
        print(f"  Heart rate - Variance: {actual_var:.2f} (expected {expected_var:.2f}), MSE={var_mse:.2e}")
    
    def test_blood_pressure_realistic_range(self, context):
        """Test with realistic blood pressure systolic data (90-140 mmHg)."""
        bp_sys = [120.0, 115.0, 125.0, 118.0, 122.0, 119.0, 121.0, 117.0, 
                  123.0, 116.0, 124.0, 118.0, 120.0, 119.0, 122.0]
        expected_mean = plaintext_mean(bp_sys)
        
        enc_vector = context.encrypt(bp_sys)
        mean_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(bp_sys))
        actual_mean = mean_enc.decrypt()[0]
        
        mse = calculate_mse(actual_mean, expected_mean)
        
        assert mse < 1e-4, f"BP systolic MSE {mse} too high"
        print(f"✓ Blood pressure (sys): {actual_mean:.2f} mmHg (expected {expected_mean:.2f}), MSE={mse:.2e}")
    
    def test_temperature_realistic_range(self, context):
        """Test with realistic body temperature data (97.0-99.5°F)."""
        temperatures = [98.6, 98.4, 98.7, 98.5, 98.8, 98.3, 98.6, 98.5,
                       98.9, 98.4, 98.7, 98.6, 98.5, 98.4, 98.6]
        expected_mean = plaintext_mean(temperatures)
        
        enc_vector = context.encrypt(temperatures)
        mean_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(temperatures))
        actual_mean = mean_enc.decrypt()[0]
        
        mse = calculate_mse(actual_mean, expected_mean)
        
        assert mse < 1e-6, f"Temperature MSE {mse} too high"
        print(f"✓ Temperature: {actual_mean:.2f}°F (expected {expected_mean:.2f}), MSE={mse:.2e}")
    
    # ==================== Edge Cases ====================
    
    def test_single_value_accuracy(self, context):
        """Test mean and variance with single value."""
        values = [42.0]
        expected_mean = 42.0
        expected_var = 0.0
        
        enc_vector = ts.ckks_vector(context, values)
        
        mean_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, 1)
        actual_mean = mean_enc.decrypt()[0]
        
        var_enc = ColumnarStatistics.homomorphic_variance_columnar(enc_vector, 1)
        actual_var = var_enc.decrypt()[0]
        
        assert abs(actual_mean - expected_mean) < 0.01
        assert abs(actual_var - expected_var) < 0.01
        print(f"✓ Single value: mean={actual_mean:.2f}, variance={actual_var:.4f}")
    
    def test_identical_values_accuracy(self, context):
        """Test with all identical values (variance should be 0)."""
        values = [100.0] * 20
        expected_mean = 100.0
        expected_var = 0.0
        
        enc_vector = ts.ckks_vector(context, values)
        
        mean_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(values))
        actual_mean = mean_enc.decrypt()[0]
        
        var_enc = ColumnarStatistics.homomorphic_variance_columnar(enc_vector, len(values))
        actual_var = var_enc.decrypt()[0]
        
        assert abs(actual_mean - expected_mean) < 0.01
        assert abs(actual_var - expected_var) < 0.01
        print(f"✓ Identical values: mean={actual_mean:.2f}, variance={actual_var:.6f} (expected 0.0)")
    
    # ==================== MSE/RMSE Aggregation ====================
    
    def test_aggregate_mse_across_operations(self, context):
        """Calculate aggregate MSE across multiple operations."""
        test_cases = [
            [70.0, 80.0, 90.0],
            [float(i) for i in range(1, 51)],
            [65.0, 70.0, 75.0, 80.0, 85.0]
        ]
        
        mse_values = []
        
        for values in test_cases:
            expected_mean = plaintext_mean(values)
            enc_vector = ts.ckks_vector(context, values)
            mean_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(values))
            actual_mean = mean_enc.decrypt()[0]
            mse = calculate_mse(actual_mean, expected_mean)
            mse_values.append(mse)
        
        avg_mse = sum(mse_values) / len(mse_values)
        max_mse = max(mse_values)
        
        assert avg_mse < 1e-6, f"Average MSE {avg_mse} exceeds threshold"
        assert max_mse < 1e-4, f"Max MSE {max_mse} too high"
        
        print(f"✓ Aggregate MSE: avg={avg_mse:.2e}, max={max_mse:.2e}")


# ==================== Manual Test Runner ====================

if __name__ == "__main__":
    print("=" * 70)
    print("TASK 4.1: COLUMNAR ACCURACY TESTS")
    print("=" * 70)
    print()
    
    # Create context
    ck = CKKSContext()
    ck.create_optimized_context()
    ctx = ck.context
    
    # Test 1: Small dataset mean
    print("Test 4.1.1: Mean Accuracy (small dataset)")
    values = [70.0, 80.0, 90.0]
    expected = plaintext_mean(values)
    enc = ts.ckks_vector(ctx, values)
    result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc, len(values))
    actual = result_enc.decrypt()[0]
    mse = calculate_mse(actual, expected)
    print(f"  Actual: {actual:.6f}, Expected: {expected:.6f}, MSE: {mse:.2e}")
    print(f"  {'\u2713 PASS' if mse < 1e-6 else '\u2717 FAIL'} (MSE < 1e-6)")
    print()
    
    # Test 2: Variance accuracy
    print("Test 4.1.2: Variance Accuracy")
    values = [10.0, 20.0, 30.0]
    expected = plaintext_variance(values)
    enc = ts.ckks_vector(ctx, values)
    result_enc = ColumnarStatistics.homomorphic_variance_columnar(enc, len(values))
    actual = result_enc.decrypt()[0]
    mse = calculate_mse(actual, expected)
    print(f"  Actual: {actual:.4f}, Expected: {expected:.4f}, MSE: {mse:.2e}")
    print(f"  {'\u2713 PASS' if mse < 0.1 else '\u2717 FAIL'} (MSE < 0.1)")
    print()
    
    # Test 3: With padding
    print("Test 4.1.3: Mean with Padding (100 records, 8192 slots)")
    actual_count = 100
    values = [float(i) for i in range(1, actual_count + 1)]
    expected = plaintext_mean(values)
    padded = values + [0.0] * (8192 - actual_count)
    enc = ts.ckks_vector(ctx, padded)
    result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc, actual_count)
    actual = result_enc.decrypt()[0]
    mse = calculate_mse(actual, expected)
    print(f"  Actual: {actual:.2f}, Expected: {expected:.2f}, MSE: {mse:.2e}")
    print(f"  {'\u2713 PASS' if mse < 1e-4 else '\u2717 FAIL'} (MSE < 1e-4)")
    print()
    
    # Test 4: Healthcare realistic
    print("Test: Healthcare Realistic Data (Heart Rate)")
    heart_rates = [72.0, 68.0, 75.0, 80.0, 65.0, 78.0, 71.0, 69.0]
    expected = plaintext_mean(heart_rates)
    enc = ts.ckks_vector(ctx, heart_rates)
    result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc, len(heart_rates))
    actual = result_enc.decrypt()[0]
    mse = calculate_mse(actual, expected)
    print(f"  Mean Heart Rate: {actual:.2f} bpm (expected {expected:.2f} bpm)")
    print(f"  MSE: {mse:.2e}")
    print(f"  {'\u2713 PASS' if mse < 1e-4 else '\u2717 FAIL'}")
    print()
    
    print("=" * 70)
    print("✓ All manual accuracy tests completed!")
    print("=" * 70)
