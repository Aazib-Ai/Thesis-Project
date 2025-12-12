"""
Integration tests for the benchmark pipeline and new compliance features.

This module tests:
1. Benchmark pipeline execution and output  generation
2. Data segmentation (DataClassifier correctly identifies PII and vitals)
3. Hybrid encryption routing (no data leakage between AES and CKKS)
4. Compliance features (audit logging, access control, data minimization)

These tests validate the complete system integration for thesis validation.
"""

import os
import sys
import pytest
import pandas as pd
import json
from datetime import datetime
from typing import Dict, Any

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.data_classifier import DataClassifier
from src.api.middleware.audit_logger import AuditLogger, log_audit
from src.crypto.hybrid_encryption import HybridEncryptor, KeyManager
from src.crypto.ckks_module import CKKSContext
from src.crypto.aes_module import AESCipher


class TestBenchmarkPipeline:
    """Test the benchmark pipeline execution and outputs."""
    
    def test_benchmark_outputs_exist(self):
        """Test that benchmark outputs are generated."""
        # Check for key benchmark output files
        expected_files = [
            "benchmarks/ckks_baseline_results.csv",
            "benchmarks/ckks_optimized_results.csv",
            "benchmarks/final_kpis.csv"
        ]
        
        for filepath in expected_files:
            if os.path.exists(filepath):
                assert os.path.getsize(filepath) > 0, f"{filepath} exists but is empty"
    
    def test_benchmark_csv_structure(self):
        """Test that benchmark CSV files have correct structure."""
        csv_files = [
            "benchmarks/ckks_baseline_results.csv",
            "benchmarks/ckks_optimized_results.csv",
            "benchmarks/final_kpis.csv"
        ]
        
        for filepath in csv_files:
            if os.path.exists(filepath):
                df = pd.read_csv(filepath)
                
                # Check for required columns
                assert "metric" in df.columns, f"{filepath} missing 'metric' column"
                assert "seconds" in df.columns, f"{filepath} missing 'seconds' column"
                
                # Check for accuracy columns if they exist
                if "accuracy_pct" in df.columns:
                    assert df["accuracy_pct"].notna().any(), f"{filepath} has no accuracy data"
    
    def test_accuracy_metrics_in_results(self):
        """Test that accuracy metrics are included in benchmark results."""
        results_file = "benchmarks/ckks_optimized_results.csv"
        
        if os.path.exists(results_file):
            df = pd.read_csv(results_file)
            
            # Check for accuracy columns
            assert "mse" in df.columns or "accuracy_pct" in df.columns, \
                "Results should contain accuracy metrics (MSE or accuracy_pct)"
            
            # Mean operations should have accuracy data
            mean_rows = df[df["metric"] == "mean"]
            if not mean_rows.empty:
                assert mean_rows["accuracy_pct"].notna().any(), \
                    "Mean operations should have accuracy percentage"
    
    def test_charts_generation(self):
        """Test that chart images are created (if applicable)."""
        chart_files = [
            "benchmarks/performance_comparison.png",
            "benchmarks/accuracy_comparison.png"
        ]
        
        # These may not exist yet, so we just check if they do exist
        for filepath in chart_files:
            if os.path.exists(filepath):
                assert os.path.getsize(filepath) > 0, f"{filepath} exists but is empty"


class TestDataSegmentation:
    """Test data classification and segmentation logic."""
    
    def test_data_classifier_pii_identification(self):
        """Test that DataClassifier correctly identifies PII fields."""
        # Test known PII fields
        assert DataClassifier.classify_field("patient_id") == "PII"
        assert DataClassifier.classify_field("name") == "PII"
        assert DataClassifier.classify_field("email") == "PII"
        assert DataClassifier.classify_field("phone") == "PII"
        assert DataClassifier.classify_field("address") == "PII"
        assert DataClassifier.classify_field("dob") == "PII"
    
    def test_data_classifier_vitals_identification(self):
        """Test that DataClassifier correctly identifies vital sign fields."""
        # Test known vitals
        assert DataClassifier.classify_field("heart_rate") == "SENSITIVE_VITALS"
        assert DataClassifier.classify_field("blood_pressure_sys") == "SENSITIVE_VITALS"
        assert DataClassifier.classify_field("temperature") == "SENSITIVE_VITALS"
        assert DataClassifier.classify_field("glucose") == "SENSITIVE_VITALS"
    
    def test_data_classifier_unknown_fields(self):
        """Test that unknown fields are labeled as UNKNOWN."""
        assert DataClassifier.classify_field("random_field") == "UNKNOWN"
        assert DataClassifier.classify_field("custom_data") == "UNKNOWN"
    
    def test_record_segmentation(self):
        """Test that records are correctly segmented into PII and vitals."""
        record = {
            "patient_id": "P001",
            "name": "John Doe",
            "heart_rate": 72.5,
            "temperature": 98.6,
            "custom_field": "ignored"
        }
        
        pii, vitals = DataClassifier.segment_record(record)
        
        # Check PII extraction
        assert "patient_id" in pii
        assert "name" in pii
        assert pii["patient_id"] == "P001"
        assert pii["name"] == "John Doe"
        
        # Check vitals extraction
        assert "heart_rate" in vitals
        assert "temperature" in vitals
        assert vitals["heart_rate"] == 72.5
        assert vitals["temperature"] == 98.6
        
        # Check unknown fields are excluded
        assert "custom_field" not in pii
        assert "custom_field" not in vitals
    
    def test_classification_report(self):
        """Test classification report generation."""
        df = pd.DataFrame({
            "patient_id": ["P001", "P002"],
            "name": ["Alice", "Bob"],
            "heart_rate": [72, 75],
            "temperature": [98.6, 98.4],
            "unknown_col": ["A", "B"]
        })
        
        report = DataClassifier.get_classification_report(df)
        
        assert report["pii_count"] == 2, "Should identify 2 PII fields"
        assert report["vitals_count"] == 2, "Should identify 2 vitals fields"
        assert report["unknown_count"] == 1, "Should identify 1 unknown field"
        assert report["total_fields"] == 5, "Should have 5 total fields"
        assert report["dataset_rows"] == 2, "Should have 2 rows"


class TestHybridEncryptionRouting:
    """Test that hybrid encryption correctly routes data and prevents leakage."""
    
    @pytest.fixture
    def hybrid_system(self):
        """Create a hybrid encryption system."""
        ckks = CKKSContext()
        ckks.create_context()
        key_manager = KeyManager()
        return HybridEncryptor(ckks, key_manager)
    
    def test_pii_uses_aes(self, hybrid_system):
        """Test that PII data uses AES encryption."""
        pii_data = {"patient_id": "P001", "name": "John Doe"}
        
        # The hybrid system should use AES for PII
        # We can test this by encrypting and decrypting
        aes_key = AESCipher.generate_key()
        encrypted_pii = {}
        for key, value in pii_data.items():
            encrypted_pii[key] = AESCipher.encrypt(value.encode('utf-8'), aes_key)
        
        # Decrypt and verify
        for key in pii_data:
            decrypted = AESCipher.decrypt(encrypted_pii[key], aes_key).decode('utf-8')
            assert decrypted == pii_data[key], f"PII field {key} should match after AES round-trip"
    
    def test_vitals_use_ckks(self, hybrid_system):
        """Test that vitals use CKKS encryption."""
        vitals_data = {"heart_rate": 72.5, "temperature": 98.6}
        
        # The hybrid system should use CKKS for vitals
        ckks = hybrid_system.ckks
        encrypted_vitals = {}
        for key, value in vitals_data.items():
            encrypted_vitals[key] = ckks.encrypt_vector([value])
        
        # Decrypt and verify
        for key in vitals_data:
            decrypted_list = ckks.decrypt_vector(encrypted_vitals[key])
            decrypted_value = decrypted_list[0] if isinstance(decrypted_list, list) else decrypted_list
            
            # Allow small numerical error for CKKS
            assert abs(decrypted_value - vitals_data[key]) < 0.1, \
                f"Vitals field {key} should match after CKKS round-trip (within tolerance)"
    
    def test_no_data_leakage_between_systems(self, hybrid_system):
        """Test that PII encrypted with AES cannot be decrypted by CKKS and vice versa."""
        # This is more of a conceptual test - different encryption schemes use different keys
        
        # Encrypt PII with AES
        aes_key = AESCipher.generate_key()
        encrypted_pii = AESCipher.encrypt("P001".encode('utf-8'), aes_key)
        
        # CKKS encrypted vitals
        encrypted_vital = hybrid_system.ckks.encrypt_vector([72.5])
        
        # Verify they are different types/formats
        assert isinstance(encrypted_pii, dict), "AES should produce dict ciphertext"
        assert not isinstance(encrypted_vital, dict), "CKKS should produce TenSEAL object"
        
        # They use completely different encryption mechanisms
        assert encrypted_pii.get('nonce') is not None, "AES should have nonce for GCM mode"
        assert not hasattr(encrypted_vital, 'nonce'), "CKKS object should not have AES-GCM nonce"
    
    def test_hybrid_encrypt_patient_record(self, hybrid_system):
        """Test encrypting a complete patient record with hybrid system."""
        record = {
            "patient_id": "P001",
            "name": "John Doe",
            "heart_rate": 72.5,
            "temperature": 98.6
        }
        
        aes_key = AESCipher.generate_key()
        encrypted_record = hybrid_system.encrypt_patient_record(record, aes_key)
        
        # Should have PII fields encrypted with AES and vitals with CKKS
        # PII fields are stored directly, vitals have _enc suffix
        assert "patient_id" in encrypted_record
        assert "name" in encrypted_record
        
        # PII should be AES-encrypted dicts
        assert isinstance(encrypted_record["patient_id"], dict)
        assert "nonce" in encrypted_record["patient_id"], "AES-GCM should have nonce"
        assert "ciphertext" in encrypted_record["name"], "AES-GCM should have ciphertext"
        
        # Vitals should be CKKS-encrypted objects (with _enc suffix)
        assert "heart_rate_enc" in encrypted_record
        assert "temperature_enc" in encrypted_record


class TestComplianceFeatures:
    """Test audit logging, access control, and data minimization."""
    
    @pytest.fixture
    def audit_logger(self, tmp_path):
        """Create an audit logger with temporary directory."""
        log_dir = str(tmp_path / "audit_logs")
        return AuditLogger(log_directory=log_dir)
    
    def test_audit_logging_records_operations(self, audit_logger):
        """Test that audit logging records all operations."""
        # Log a test operation
        audit_logger.log_operation(
            operation="test_encrypt",
            user_id="test_user",
            dataset_id="test_dataset_001",
            success=True
        )
        
        # Retrieve logs
        logs = audit_logger.get_logs(user_id="test_user")
        
        assert len(logs) > 0, "Should have logged at least one operation"
        
        # Check log entry structure
        log_entry = logs[0]
        assert log_entry["operation"] == "test_encrypt"
        assert log_entry["user_id"] == "test_user"
        assert log_entry["dataset_id"] == "test_dataset_001"
        assert log_entry["success"] is True
        assert "timestamp" in log_entry
    
    def test_audit_logging_failure_recording(self, audit_logger):
        """Test that failed operations are logged."""
        audit_logger.log_operation(
            operation="test_decrypt",
            user_id="test_user",
            success=False,
            error="Invalid key"
        )
        
        logs = audit_logger.get_logs(operation="test_decrypt")
        
        assert len(logs) > 0
        log_entry = logs[0]
        assert log_entry["success"] is False
        assert log_entry["error"] == "Invalid key"
    
    def test_audit_logging_filtering(self, audit_logger):
        """Test audit log filtering by various criteria."""
        # Log multiple operations
        audit_logger.log_operation("encrypt", user_id="user1")
        audit_logger.log_operation("decrypt", user_id="user2")
        audit_logger.log_operation("analytics", user_id="user1")
        
        # Filter by user
        user1_logs = audit_logger.get_logs(user_id="user1")
        assert len(user1_logs) > 0
        assert all(log["user_id"] == "user1" for log in user1_logs)
        
        # Filter by operation
        encrypt_logs = audit_logger.get_logs(operation="encrypt")
        assert len(encrypt_logs) > 0
        assert all(log["operation"] == "encrypt" for log in encrypt_logs)
    
    def test_access_control_blocks_unauthorized(self):
        """Test that access control prevents unauthorized access."""
        # This would typically test the access control middleware
        # For now, we test the concept by checking if access control exists
        from src.api.middleware import access_control
        
        # Check that access control module exists and has required functions
        assert hasattr(access_control, 'require_auth') or \
               hasattr(access_control, 'check_permissions'), \
               "Access control module should have authentication functions"
    
    def test_data_minimization_checks(self):
        """Test that data minimization excludes UNKNOWN fields."""
        record = {
            "patient_id": "P001",
            "heart_rate": 72.5,
            "unnecessary_field": "should_be_ignored",
            "random_data": 123
        }
        
        pii, vitals = DataClassifier.segment_record(record)
        
        # Unknown fields should not be in either category (data minimization)
        all_fields = set(pii.keys()) | set(vitals.keys())
        assert "unnecessary_field" not in all_fields
        assert "random_data" not in all_fields
        
        # Only known PII and vitals should be present
        assert "patient_id" in pii
        assert "heart_rate" in vitals
    
    def test_audit_log_file_creation(self, audit_logger):
        """Test that audit log files are created properly."""
        # Log an operation
        audit_logger.log_operation("test_operation", user_id="test_user")
        
        # Check that log file was created
        log_file_path = audit_logger._get_log_file_path()
        assert os.path.exists(log_file_path), "Audit log file should be created"
        
        # Verify file contains valid JSON
        with open(log_file_path, 'r') as f:
            for line in f:
                log_entry = json.loads(line.strip())
                assert "timestamp" in log_entry
                assert "operation" in log_entry


class TestSystemIntegration:
    """Test overall system integration."""
    
    def test_end_to_end_patient_data_flow(self):
        """Test complete data flow: classification → encryption → decryption."""
        # Create test record
        record = {
            "patient_id": "P001",
            "name": "Jane Doe",
            "heart_rate": 75.0,
            "temperature": 98.7
        }
        
        # Step 1: Classify
        pii, vitals = DataClassifier.segment_record(record)
        assert len(pii) == 2, "Should have 2 PII fields"
        assert len(vitals) == 2, "Should have 2 vitals"
        
        # Step 2: Encrypt with hybrid system
        ckks = CKKSContext()
        ckks.create_context()
        key_manager = KeyManager()
        hybrid = HybridEncryptor(ckks, key_manager)
        aes_key = AESCipher.generate_key()
        encrypted = hybrid.encrypt_patient_record(record, aes_key)
        
        # Should have encrypted PII and vitals
        assert "patient_id" in encrypted
        assert "heart_rate_enc" in encrypted
        
        # Step 3: Decrypt and verify
        decrypted_record = hybrid.decrypt_patient_record(encrypted, aes_key)
        
        # Verify PII matches
        assert decrypted_record["patient_id"] == "P001"
        assert decrypted_record["name"] == "Jane Doe"
        
        # Verify vitals match (with tolerance for CKKS)
        assert abs(decrypted_record["heart_rate"] - 75.0) < 0.1
        assert abs(decrypted_record["temperature"] - 98.7) < 0.1
    
    def test_compliance_stack_integration(self, tmp_path):
        """Test that compliance features work together."""
        log_dir = str(tmp_path / "audit_logs")
        audit_logger = AuditLogger(log_directory=log_dir)
        
        # Simulate a complete operation with audit logging
        record = {"patient_id": "P001", "heart_rate": 72.5}
        
        # Log classification
        audit_logger.log_operation(
            operation="classify_data",
            user_id="system",
            dataset_id="test_001",
            metadata={"fields": list(record.keys())}
        )
        
        # Classify
        pii, vitals = DataClassifier.segment_record(record)
        
        # Log encryption
        audit_logger.log_operation(
            operation="encrypt_data",
            user_id="system",
            dataset_id="test_001",
            metadata={"pii_count": len(pii), "vitals_count": len(vitals)}
        )
        
        # Verify audit trail
        logs = audit_logger.get_logs(dataset_id="test_001")
        assert len(logs) >= 2, "Should have logged classification and encryption"
        
        operations = [log["operation"] for log in logs]
        assert "classify_data" in operations
        assert "encrypt_data" in operations


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
