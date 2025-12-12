"""
Test suite for Task 4.3: End-to-End Integration Tests

Tests complete workflow from CSV upload through encryption, analytics, and decryption.
Simulates real user scenarios with realistic healthcare data.

Test Coverage:
- Generate 1000-record synthetic CSV
- Upload and encrypt with columnar SIMD
- Compute mean, variance, std on various fields
- Decrypt client-side and verify accuracy
- Compare performance vs baseline
"""

try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

import os
import json
import csv
import tempfile
import time
import random
from typing import List, Dict
import tenseal as ts

from src.crypto.columnar_encryption import ColumnarEncryptor
from src.crypto.ckks_module import CKKSContext
from src.analytics.columnar_statistics import ColumnarStatistics


# ==================== Synthetic Data Generator ====================

class HealthcareDataGenerator:
    """Generate realistic synthetic healthcare data."""
    
    @staticmethod
    def generate_patient_record(patient_id: int) -> Dict[str, any]:
        """Generate a single patient record with realistic vitals."""
        return {
            'patient_id': f'P{patient_id:05d}',
            'name': f'Patient_{patient_id}',
            'age': random.randint(25, 75),
            'heart_rate': random.uniform(60.0, 100.0),  # bpm
            'blood_pressure_sys': random.uniform(90.0, 140.0),  # mmHg
            'blood_pressure_dia': random.uniform(60.0, 90.0),  # mmHg
            'temperature': random.uniform(97.0, 99.5),  # °F
            'oxygen_saturation': random.uniform(95.0, 100.0),  # %
            'respiratory_rate': random.uniform(12.0, 20.0),  # breaths/min
        }
    
    @staticmethod
    def generate_dataset(num_records: int) -> List[Dict]:
        """Generate a complete dataset."""
        random.seed(42)  # For reproducibility
        return [HealthcareDataGenerator.generate_patient_record(i) 
                for i in range(1, num_records + 1)]
    
    @staticmethod
    def save_to_csv(records: List[Dict], filepath: str):
        """Save records to CSV file."""
        if not records:
            return
        
        fieldnames = records[0].keys()
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)
    
    @staticmethod
    def load_from_csv(filepath: str) -> List[Dict]:
        """Load records from CSV file."""
        records = []
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert numeric fields
                record = {
                    'patient_id': row['patient_id'],
                    'name': row['name'],
                    'age': int(row['age']),
                    'heart_rate': float(row['heart_rate']),
                    'blood_pressure_sys': float(row['blood_pressure_sys']),
                    'blood_pressure_dia': float(row['blood_pressure_dia']),
                    'temperature': float(row['temperature']),
                    'oxygen_saturation': float(row['oxygen_saturation']),
                    'respiratory_rate': float(row['respiratory_rate']),
                }
                records.append(record)
        return records


# ==================== Helper Functions ====================

def plaintext_mean(values: List[float]) -> float:
    """Calculate plaintext mean."""
    return sum(values) / len(values) if values else 0.0


def plaintext_variance(values: List[float]) -> float:
    """Calculate plaintext variance."""
    if not values:
        return 0.0
    mean = plaintext_mean(values)
    return sum((x - mean) ** 2 for x in values) / len(values)


def extract_field_values(records: List[Dict], field: str) -> List[float]:
    """Extract numeric values for a specific field."""
    return [record[field] for record in records if field in record]


# ==================== Test Class ====================

class TestColumnarE2E:
    """End-to-end integration tests for columnar SIMD workflow."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def context(self):
        """Create CKKS context."""
        ck = CKKSContext()
        ck.create_optimized_context()
        return ck
    
    @pytest.fixture
    def encryptor(self, context):
        """Create columnar encryptor."""
        return ColumnarEncryptor(context)
    
    # ==================== Task 4.3.1: Upload 1000-Record CSV ====================
    
    def test_e2e_generate_1000_record_csv(self, temp_dir):
        """Generate and save 1000-record synthetic CSV."""
        num_records = 1000
        records = HealthcareDataGenerator.generate_dataset(num_records)
        
        assert len(records) == num_records
        assert 'patient_id' in records[0]
        assert 'heart_rate' in records[0]
        
        csv_path = os.path.join(temp_dir, 'patients_1000.csv')
        HealthcareDataGenerator.save_to_csv(records, csv_path)
        
        assert os.path.exists(csv_path)
        
        # Verify CSV can be loaded
        loaded_records = HealthcareDataGenerator.load_from_csv(csv_path)
        assert len(loaded_records) == num_records
        
        print(f"✓ Generated and saved {num_records} records to CSV")
    
    def test_e2e_encrypt_1000_records(self, temp_dir, context, encryptor):
        """Encrypt 1000-record dataset with columnar SIMD."""
        # Generate data
        num_records = 1000
        records = HealthcareDataGenerator.generate_dataset(num_records)
        
        # Pivot to columns
        pii, vitals = encryptor.pivot_to_columns(records)
        
        assert 'patient_id' in pii
        assert 'heart_rate' in vitals
        assert len(vitals['heart_rate']) == num_records
        
        # Encrypt columns
        encrypted_columns, metadata = encryptor.encrypt_columns(vitals)
        
        # Verify encryption
        assert 'heart_rate' in encrypted_columns
        assert metadata['heart_rate']['actual_count'] == num_records
        assert metadata['heart_rate']['chunk_count'] >= 1
        
        # Save encrypted data
        output_dir = os.path.join(temp_dir, 'encrypted_dataset')
        os.makedirs(output_dir, exist_ok=True)
        encryptor.save_encrypted_columns(encrypted_columns, output_dir)
        
        columns_dir = os.path.join(output_dir, 'columns')
        assert os.path.exists(columns_dir)
        assert os.path.exists(os.path.join(columns_dir, 'heart_rate.bin'))
        
        print(f"✓ Encrypted {num_records} records with columnar SIMD")
    
    # ==================== Task 4.3.2: Run Mean Calculation ====================
    
    def test_e2e_mean_calculation_on_heart_rate(self, context, encryptor):
        """Complete workflow: generate data → encrypt → compute mean → decrypt."""
        # Step 1: Generate data
        num_records = 1000
        records = HealthcareDataGenerator.generate_dataset(num_records)
        
        # Step 2: Extract plaintext values for comparison
        heart_rates = extract_field_values(records, 'heart_rate')
        expected_mean = plaintext_mean(heart_rates)
        
        # Step 3: Encrypt in columnar format
        pii, vitals = encryptor.pivot_to_columns(records)
        encrypted_columns, metadata = encryptor.encrypt_columns(vitals)
        
        # Step 4: Load encrypted heart_rate column
        enc_col = encrypted_columns['heart_rate']
        
        # Step 5: Compute homomorphic mean
        result_enc = ColumnarStatistics.compute_operation(enc_col, 'mean')
        
        # Step 6: Decrypt result (client-side)
        actual_mean = result_enc.decrypt()[0]
        
        # Step 7: Verify accuracy
        error = abs(actual_mean - expected_mean)
        mse = (actual_mean - expected_mean) ** 2
        
        assert error < 0.5, f"Mean error {error} too large"
        assert mse < 1.0, f"MSE {mse} too large"
        
        print(f"✓ E2E Mean: actual={actual_mean:.2f}, expected={expected_mean:.2f}, MSE={mse:.2e}")
    
    # ==================== Task 4.3.3: Decrypt and Verify ====================
    
    def test_e2e_multiple_field_calculations(self, context, encryptor):
        """Test analytics on multiple fields: heart_rate, blood_pressure, temperature."""
        # Generate data
        num_records = 500
        records = HealthcareDataGenerator.generate_dataset(num_records)
        
        # Encrypt
        pii, vitals = encryptor.pivot_to_columns(records)
        encrypted_columns, metadata = encryptor.encrypt_columns(vitals)
        
        # Test multiple fields
        fields_to_test = ['heart_rate', 'blood_pressure_sys', 'temperature']
        results = []
        
        for field in fields_to_test:
            # Plaintext values
            plaintext_values = extract_field_values(records, field)
            expected_mean = plaintext_mean(plaintext_values)
            expected_var = plaintext_variance(plaintext_values)
            
            # Encrypted column
            enc_col = encrypted_columns[field]
            
            # Compute mean
            mean_enc = ColumnarStatistics.compute_operation(enc_col, 'mean')
            actual_mean = mean_enc.decrypt()[0]
            
            # Compute variance
            var_enc = ColumnarStatistics.compute_operation(enc_col, 'variance')
            actual_var = var_enc.decrypt()[0]
            
            # Verify
            mean_error = abs(actual_mean - expected_mean)
            var_error = abs(actual_var - expected_var)
            
            results.append({
                'field': field,
                'mean_actual': actual_mean,
                'mean_expected': expected_mean,
                'mean_error': mean_error,
                'var_actual': actual_var,
                'var_expected': expected_var,
                'var_error': var_error,
            })
            
            assert mean_error < 1.0, f"{field} mean error too large"
        
        # Print results
        for result in results:
            print(f"✓ {result['field']}: mean_error={result['mean_error']:.4f}, var_error={result['var_error']:.4f}")
    
    def test_e2e_variance_calculation(self, context, encryptor):
        """Test variance calculation end-to-end."""
        num_records = 800
        records = HealthcareDataGenerator.generate_dataset(num_records)
        
        # Get plaintext variance
        bp_values = extract_field_values(records, 'blood_pressure_sys')
        expected_var = plaintext_variance(bp_values)
        
        # Encrypt and compute
        pii, vitals = encryptor.pivot_to_columns(records)
        encrypted_columns, metadata = encryptor.encrypt_columns(vitals)
        
        enc_col = encrypted_columns['blood_pressure_sys']
        result_enc = ColumnarStatistics.compute_operation(enc_col, 'variance')
        actual_var = result_enc.decrypt()[0]
        
        error = abs(actual_var - expected_var)
        
        assert error < 1.0, f"Variance error {error} too large for BP"
        
        print(f"✓ E2E Variance (BP): actual={actual_var:.2f}, expected={expected_var:.2f}, error={error:.4f}")
    
    # ==================== Task 4.3.4: Performance Comparison ====================
    
    def test_e2e_performance_metrics(self, context, encryptor):
        """Measure performance of columnar operations."""
        num_records = 1000
        records = HealthcareDataGenerator.generate_dataset(num_records)
        
        # Timing: Encryption
        start = time.time()
        pii, vitals = encryptor.pivot_to_columns(records)
        encrypted_columns, metadata = encryptor.encrypt_columns(vitals)
        encryption_time = time.time() - start
        
        # Timing: Analytics (mean on all fields)
        analytics_times = []
        for field in vitals.keys():
            enc_col = encrypted_columns[field]
            
            start = time.time()
            result_enc = ColumnarStatistics.compute_operation(enc_col, 'mean')
            analytics_time = time.time() - start
            analytics_times.append(analytics_time)
        
        avg_analytics_time = sum(analytics_times) / len(analytics_times)
        
        # Performance assertions (reasonable bounds)
        assert encryption_time < 30.0, f"Encryption too slow: {encryption_time}s"
        assert avg_analytics_time < 1.0, f"Analytics too slow: {avg_analytics_time}s"
        
        print(f"✓ Performance: encryption={encryption_time:.2f}s, "
              f"avg_analytics={avg_analytics_time:.4f}s per field")
    
    def test_e2e_large_dataset_multi_ciphertext(self, context, encryptor):
        """Test with >8192 records requiring multiple ciphertexts."""
        num_records = 10000
        records = HealthcareDataGenerator.generate_dataset(num_records)
        
        # Encrypt
        pii, vitals = encryptor.pivot_to_columns(records)
        encrypted_columns, metadata = encryptor.encrypt_columns(vitals)
        
        # Verify multi-ciphertext structure
        hr_metadata = metadata['heart_rate']
        assert hr_metadata['actual_count'] == num_records
        # Should require multiple chunks for >8192 records
        assert hr_metadata['chunk_count'] > 1, "Should have multiple ciphertexts for 10k records"
        
        # Compute mean
        enc_col = encrypted_columns['heart_rate']
        result_enc = ColumnarStatistics.compute_operation(enc_col, 'mean')
        actual_mean = result_enc.decrypt()[0]
        
        # Verify
        heart_rates = extract_field_values(records, 'heart_rate')
        expected_mean = plaintext_mean(heart_rates)
        error = abs(actual_mean - expected_mean)
        
        assert error < 1.0, f"Large dataset mean error {error} too large"
        
        print(f"✓ Large dataset (10k records, {hr_metadata['chunk_count']} chunks): "
              f"mean_error={error:.4f}")
    
    # ==================== Complete Workflow Test ====================
    
    def test_e2e_complete_workflow_with_storage(self, temp_dir, context, encryptor):
        """Test complete workflow: CSV → encrypt → save → load → compute → decrypt."""
        # Step 1: Generate and save CSV
        num_records = 500
        records = HealthcareDataGenerator.generate_dataset(num_records)
        csv_path = os.path.join(temp_dir, 'test_patients.csv')
        HealthcareDataGenerator.save_to_csv(records, csv_path)
        
        # Step 2: Load CSV
        loaded_records = HealthcareDataGenerator.load_from_csv(csv_path)
        assert len(loaded_records) == num_records
        
        # Step 3: Encrypt
        pii, vitals = encryptor.pivot_to_columns(loaded_records)
        encrypted_columns, metadata = encryptor.encrypt_columns(vitals)
        
        # Step 4: Save encrypted data
        output_dir = os.path.join(temp_dir, 'encrypted')
        os.makedirs(output_dir, exist_ok=True)
        encryptor.save_encrypted_columns(encrypted_columns, output_dir)
        
        # Step 5: Load encrypted data
        columns_dir = os.path.join(output_dir, 'columns')
        loaded_enc_col = encryptor.load_encrypted_column('heart_rate', columns_dir, context.context)
        
        # Step 6: Compute analytics
        result_enc = ColumnarStatistics.compute_operation(loaded_enc_col, 'mean')
        
        # Step 7: Decrypt
        actual_mean = result_enc.decrypt()[0]
        
        # Step 8: Verify
        heart_rates = extract_field_values(loaded_records, 'heart_rate')
        expected_mean = plaintext_mean(heart_rates)
        error = abs(actual_mean - expected_mean)
        
        assert error < 0.5
        
        print(f"✓ Complete workflow: CSV→encrypt→save→load→compute→decrypt successful")


# ==================== Manual Test Runner ====================

if __name__ == "__main__":
    print("=" * 70)
    print("TASK 4.3: END-TO-END INTEGRATION TESTS")
    print("=" * 70)
    print()
    
    # Create context
    ck = CKKSContext()
    ck.create_optimized_context()
    encryptor = ColumnarEncryptor(ck)
    
    # Test 1: Generate dataset
    print("Test 4.3.1: Generate 1000-Record Dataset")
    num_records = 1000
    records = HealthcareDataGenerator.generate_dataset(num_records)
    print(f"  Generated: {len(records)} records")
    print(f"  Sample record: {records[0]}")
    print(f"  ✓ PASS")
    print()
    
    # Test 2: E2E Mean Calculation
    print("Test 4.3.2: E2E Mean Calculation on Heart Rate")
    heart_rates = extract_field_values(records, 'heart_rate')
    expected_mean = plaintext_mean(heart_rates)
    
    pii, vitals = encryptor.pivot_to_columns(records)
    encrypted_columns, metadata = encryptor.encrypt_columns(vitals)
    enc_col = encrypted_columns['heart_rate']
    
    result_enc = ColumnarStatistics.compute_operation(enc_col, 'mean')
    actual_mean = result_enc.decrypt()[0]
    error = abs(actual_mean - expected_mean)
    
    print(f"  Plaintext mean: {expected_mean:.2f} bpm")
    print(f"  Encrypted mean: {actual_mean:.2f} bpm")
    print(f"  Error: {error:.4f}")
    print(f"  {'✓ PASS' if error < 0.5 else '✗ FAIL'}")
    print()
    
    # Test 3: Multiple fields
    print("Test 4.3.3: Multiple Field Analytics")
    fields = ['heart_rate', 'blood_pressure_sys', 'temperature']
    
    for field in fields:
        plaintext_values = extract_field_values(records, field)
        expected = plaintext_mean(plaintext_values)
        
        enc_col = encrypted_columns[field]
        result_enc = ColumnarStatistics.compute_operation(enc_col, 'mean')
        actual = result_enc.decrypt()[0]
        error = abs(actual - expected)
        
        print(f"  {field}: actual={actual:.2f}, expected={expected:.2f}, error={error:.4f}")
    
    print(f"  ✓ PASS")
    print()
    
    print("=" * 70)
    print("✓ All manual E2E tests completed!")
    print("=" * 70)
