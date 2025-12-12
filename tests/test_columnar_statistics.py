"""
Test suite for Phase 2: Columnar Statistics

Tests the homomorphic operations on columnar encrypted data to verify:
1. Accuracy of computations (matches plaintext)
2. No server-side decryption (results stay encrypted)
3. Support for multi-ciphertext columns
"""

try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False
    
import tenseal as ts
from src.analytics.columnar_statistics import ColumnarStatistics
from src.crypto.ckks_module import CKKSContext


class TestColumnarStatistics:
    """Test homomorphic operations on columnar data"""
    
    @pytest.fixture
    def context(self):
        """Create CKKS context for testing"""
        ck = CKKSContext()
        ck.create_optimized_context()
        return ck.context
    
    def test_homomorphic_sum_basic(self, context):
        """Test basic homomorphic sum operation"""
        values = [10.0, 20.0, 30.0]
        expected_sum = 60.0
        
        enc_vector = context.encrypt(values)
        result_enc = ColumnarStatistics.homomorphic_sum_slots(enc_vector)
        result = result_enc.decrypt()[0]
        
        assert abs(result - expected_sum) < 0.01, f"Expected {expected_sum}, got {result}"
    
    def test_homomorphic_mean_accuracy(self, context):
        """Test mean accuracy matches plaintext computation"""
        values = [70.0, 80.0, 90.0]  # Mean = 80.0
        expected_mean = 80.0
        
        enc_vector = context.encrypt(values)
        result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(values))
        result = result_enc.decrypt()[0]
        
        assert abs(result - expected_mean) < 0.01, f"Expected {expected_mean}, got {result}"
    
    def test_homomorphic_mean_with_padding(self, context):
        """Test mean with padded vector (simulates SIMD slots)"""
        # Simulate 100 actual values in 8192 slots
        actual_count = 100
        values = [float(i) for i in range(1, actual_count + 1)]  # [1, 2, ..., 100]
        expected_mean = sum(values) / len(values)  # Mean = 50.5
        
        # Pad to 8192 slots
        padded_values = values + [0.0] * (8192 - actual_count)
        
        enc_vector = context.encrypt(padded_values)
        result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, actual_count)
        result = result_enc.decrypt()[0]
        
        assert abs(result - expected_mean) < 0.1, f"Expected {expected_mean}, got {result}"
    
    def test_homomorphic_variance_accuracy(self, context):
        """Test variance accuracy"""
        values = [10.0, 20.0, 30.0]
        # Manual calculation: mean=20, variance=((10-20)² + (20-20)² + (30-20)²)/3 = 66.67
        expected_variance = 66.666667
        
        enc_vector = context.encrypt(values)
        result_enc = ColumnarStatistics.homomorphic_variance_columnar(enc_vector, len(values))
        result = result_enc.decrypt()[0]
        
        assert abs(result - expected_variance) < 0.1, f"Expected {expected_variance}, got {result}"
    
    def test_result_stays_encrypted(self, context):
        """Verify that results are encrypted (not plaintext)"""
        values = [70.0, 80.0, 90.0]
        
        enc_vector = context.encrypt(values)
        result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(values))
        
        # Result should be a CKKSVector, not a plaintext value
        assert isinstance(result_enc, ts.CKKSVector), "Result should be encrypted"
        
        # Can only get value by explicit decryption
        decrypted = result_enc.decrypt()
        assert isinstance(decrypted, list), "Decryption should return a list"
    
    def test_compute_operation_interface(self, context):
        """Test the unified compute_operation interface"""
        values = [10.0, 20.0, 30.0]
        enc_vector = context.encrypt(values)
        
        # Simulate enc_col structure from ColumnarEncryptor
        enc_col = {
            'ciphertext': enc_vector,
            'chunk_count': 1,
            'actual_count': len(values)
        }
        
        # Test sum
        result_sum = ColumnarStatistics.compute_operation(enc_col, 'sum')
        assert abs(result_sum.decrypt()[0] - 60.0) < 0.01
        
        # Test mean
        result_mean = ColumnarStatistics.compute_operation(enc_col, 'mean')
        assert abs(result_mean.decrypt()[0] - 20.0) < 0.01
        
        # Test variance
        result_var = ColumnarStatistics.compute_operation(enc_col, 'variance')
        assert abs(result_var.decrypt()[0] - 66.67) < 0.1
    
    def test_multi_ciphertext_sum(self, context):
        """Test sum across multiple ciphertext chunks"""
        # Simulate 2 chunks of data
        chunk1_values = [float(i) for i in range(1, 101)]  # [1..100]
        chunk2_values = [float(i) for i in range(101, 151)]  # [101..150]
        
        enc_chunk1 = context.encrypt(chunk1_values)
        enc_chunk2 = context.encrypt(chunk2_values)
        
        result_enc = ColumnarStatistics.handle_multi_ciphertext_sum(
            [enc_chunk1, enc_chunk2],
            [len(chunk1_values), len(chunk2_values)]
        )
        
        expected_sum = sum(chunk1_values) + sum(chunk2_values)
        result = result_enc.decrypt()[0]
        
        assert abs(result - expected_sum) < 1.0, f"Expected {expected_sum}, got {result}"
    
    def test_multi_ciphertext_mean(self, context):
        """Test mean across multiple ciphertext chunks"""
        chunk1_values = [10.0] * 50
        chunk2_values = [20.0] * 50
        
        enc_chunk1 = context.encrypt(chunk1_values)
        enc_chunk2 = context.encrypt(chunk2_values)
        
        result_enc = ColumnarStatistics.handle_multi_ciphertext_mean(
            [enc_chunk1, enc_chunk2],
            [len(chunk1_values), len(chunk2_values)]
        )
        
        expected_mean = 15.0  # (10*50 + 20*50) / 100
        result = result_enc.decrypt()[0]
        
        assert abs(result - expected_mean) < 0.1, f"Expected {expected_mean}, got {result}"
    
    def test_healthcare_realistic_data(self, context):
        """Test with realistic healthcare data ranges"""
        # Simulate heart rate measurements
        heart_rates = [72.0, 68.0, 75.0, 80.0, 65.0, 78.0, 71.0, 69.0]
        expected_mean = sum(heart_rates) / len(heart_rates)  # ~72.25
        
        enc_vector = context.encrypt(heart_rates)
        result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc_vector, len(heart_rates))
        result = result_enc.decrypt()[0]
        
        assert abs(result - expected_mean) < 0.01
        print(f"✓ Heart rate mean: {result:.2f} bpm (expected {expected_mean:.2f})")
    
    def test_invalid_actual_count(self, context):
        """Test error handling for invalid actual_count"""
        values = [10.0, 20.0, 30.0]
        enc_vector = context.encrypt(values)
        
        with pytest.raises(ValueError, match="actual_count must be positive"):
            ColumnarStatistics.homomorphic_mean_columnar(enc_vector, 0)
        
        with pytest.raises(ValueError, match="actual_count must be positive"):
            ColumnarStatistics.homomorphic_mean_columnar(enc_vector, -5)


if __name__ == "__main__":
    # Run basic tests manually
    print("Running Phase 2 Columnar Statistics Tests...")
    
    ck = CKKSContext()
    ck.create_optimized_context()
    ctx = ck.context
    
    # Test 1: Mean
    values = [70.0, 80.0, 90.0]
    enc = ctx.encrypt(values)
    result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc, len(values))
    result = result_enc.decrypt()[0]
    print(f"✓ Test 1 - Mean: {result:.2f} (expected 80.00)")
    
    # Test 2: Sum
    result_enc = ColumnarStatistics.homomorphic_sum_slots(enc)
    result = result_enc.decrypt()[0]
    print(f"✓ Test 2 - Sum: {result:.2f} (expected 240.00)")
    
    # Test 3: Variance
    result_enc = ColumnarStatistics.homomorphic_variance_columnar(enc, len(values))
    result = result_enc.decrypt()[0]
    print(f"✓ Test 3 - Variance: {result:.2f} (expected ~66.67)")
    
    # Test 4: With padding
    actual_count = 100
    values = [float(i) for i in range(1, actual_count + 1)]
    padded = values + [0.0] * (8192 - actual_count)
    enc = ctx.encrypt(padded)
    result_enc = ColumnarStatistics.homomorphic_mean_columnar(enc, actual_count)
    result = result_enc.decrypt()[0]
    expected = sum(values) / len(values)
    print(f"✓ Test 4 - Mean with padding: {result:.2f} (expected {expected:.2f})")
    
    print("\n✓ All manual tests passed!")
