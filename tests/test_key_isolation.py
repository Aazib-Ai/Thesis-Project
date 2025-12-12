"""
Unit Tests for Key Isolation Manager

Tests verify that cryptographic keys are properly isolated between
client and server to maintain zero-knowledge security architecture.

Test Coverage:
1. Secret key not in serialized context
2. AES key CKKS encryption roundtrip
3. Decryption fails without secret key
4. Key isolation report generation
"""

import unittest
import os
from src.crypto.ckks_module import CKKSContext
from src.crypto.aes_module import AESCipher
from src.crypto.key_isolation_manager import KeyIsolationManager


class TestKeyIsolation(unittest.TestCase):
    """Test suite for key isolation verification."""
    
    def setUp(self):
        """Set up CKKS context for tests."""
        self.ckks = CKKSContext()
        self.ckks.create_optimized_context()
        self.aes_key = AESCipher.generate_key()
    
    def test_secret_key_not_in_public_context(self):
        """
        Test that serialized context without secret key verification passes.
        
        Critical security test: If this fails, secret key is uploaded to cloud!
        """
        # Serialize without secret key (safe for cloud upload)
        public_context = self.ckks.serialize_context(save_secret_key=False)
        
        # Verify secret key is absent
        result = KeyIsolationManager.verify_no_secret_key_in_context(public_context)
        
        self.assertTrue(
            result,
            "SECURITY FAILURE: Secret key detected in public context!"
        )
    
    def test_secret_key_in_private_context(self):
        """
        Test that serialized context WITH secret key is detected.
        
        This tests the verification method's sensitivity.
        """
        # Serialize with secret key (NEVER upload to cloud)
        private_context = self.ckks.serialize_context(save_secret_key=True)
        
        # Verify secret key is detected
        result = KeyIsolationManager.verify_no_secret_key_in_context(private_context)
        
        self.assertFalse(
            result,
            "Verification failed to detect secret key in private context"
        )
    
    def test_aes_key_ckks_encryption_roundtrip(self):
        """
        Test that AES key can be encrypted with CKKS and decrypted correctly.
        
        This enables secure AES key storage in cloud (encrypted with CKKS).
        """
        result = KeyIsolationManager.verify_aes_key_encrypted_with_ckks(
            self.aes_key,
            self.ckks
        )
        
        self.assertTrue(
            result,
            "AES key CKKS encryption/decryption failed"
        )
    
    def test_aes_key_encryption_with_different_sizes(self):
        """
        Test AES key encryption works for different key sizes (for future flexibility).
        """
        # Test 128-bit key
        key_128 = AESCipher.generate_key()[:16]
        result_128 = KeyIsolationManager.verify_aes_key_encrypted_with_ckks(
            key_128,
            self.ckks
        )
        self.assertTrue(result_128, "128-bit AES key encryption failed")
        
        # Test 256-bit key (current standard)
        key_256 = AESCipher.generate_key()
        result_256 = KeyIsolationManager.verify_aes_key_encrypted_with_ckks(
            key_256,
            self.ckks
        )
        self.assertTrue(result_256, "256-bit AES key encryption failed")
    
    def test_decryption_fails_without_secret_key(self):
        """
        Test that decryption fails when using context without secret key.
        
        Critical security test: Proves server (with only public context)
        cannot decrypt data.
        """
        # Encrypt data
        test_data = [42.0, 3.14, 2.71, 1.41]
        ciphertext = self.ckks.encrypt_vector(test_data)
        
        # Get public context (no secret key)
        public_context = self.ckks.serialize_context(save_secret_key=False)
        
        # Verify decryption fails
        result = KeyIsolationManager.verify_decryption_fails_without_secret_key(
            ciphertext,
            public_context
        )
        
        self.assertTrue(
            result,
            "SECURITY FAILURE: Decryption succeeded without secret key!"
        )
    
    def test_decryption_succeeds_with_secret_key(self):
        """
        Test that decryption works normally with full context (including secret key).
        
        This is a sanity check that the CKKS implementation is working correctly.
        """
        # Encrypt data
        test_data = [42.0, 3.14, 2.71]
        ciphertext = self.ckks.encrypt_vector(test_data)
        
        # Decrypt with full context (has secret key)
        decrypted = self.ckks.decrypt_vector(ciphertext)
        
        # Verify decryption accuracy
        for i, val in enumerate(test_data):
            self.assertAlmostEqual(
                decrypted[i],
                val,
                places=2,
                msg=f"Decryption inaccurate at index {i}"
            )
    
    def test_key_isolation_report_generation(self):
        """
        Test that comprehensive key isolation report generates successfully.
        
        Report is used for thesis documentation and proof.
        """
        report = KeyIsolationManager.generate_key_isolation_report(
            self.ckks,
            self.aes_key
        )
        
        # Check report structure
        self.assertIn('secret_key_absent', report)
        self.assertIn('aes_key_encryptable', report)
        self.assertIn('decryption_blocked', report)
        self.assertIn('overall_status', report)
        self.assertIn('details', report)
        
        # Check overall status
        self.assertEqual(
            report['overall_status'],
            'PASS',
            f"Key isolation verification failed: {report}"
        )
    
    def test_key_isolation_report_without_aes_key(self):
        """
        Test report generation without AES key (optional test).
        """
        report = KeyIsolationManager.generate_key_isolation_report(self.ckks)
        
        # Should still pass (AES key test is optional)
        self.assertEqual(
            report['overall_status'],
            'PASS',
            f"Key isolation verification failed: {report}"
        )
        
        # AES key test should be None (skipped)
        self.assertIsNone(report['aes_key_encryptable'])
    
    def test_context_serialization_size_difference(self):
        """
        Test that context with secret key is significantly larger.
        
        This validates our size-based detection method.
        """
        # Use explicit flags to ensure we are comparing apples to apples (excluding eval keys)
        public_ctx = self.ckks.context.serialize(
            save_public_key=True, 
            save_secret_key=False, 
            save_galois_keys=False, 
            save_relin_keys=False
        )
        private_ctx = self.ckks.context.serialize(
            save_public_key=True, 
            save_secret_key=True, 
            save_galois_keys=False, 
            save_relin_keys=False
        )
        
        size_diff = len(private_ctx) - len(public_ctx)
        
        # Secret key should add at least 1KB (usually ~650KB)
        self.assertGreater(
            size_diff,
            1000,
            f"Secret key size difference too small: {size_diff} bytes"
        )
    
    @classmethod
    def tearDownClass(cls):
        """Generate test report file."""
        report_path = os.path.join("tests", "key_isolation_report.txt")
        
        # Run full report generation
        ckks = CKKSContext()
        ckks.create_optimized_context()
        aes_key = AESCipher.generate_key()
        
        report = KeyIsolationManager.generate_key_isolation_report(ckks, aes_key)
        
        # Write report to file
        with open(report_path, 'w') as f:
            f.write("="*70 + "\n")
            f.write("KEY ISOLATION VERIFICATION TEST REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Overall Status: {report['overall_status']}\n\n")
            
            f.write("Test Results:\n")
            f.write(f"1. Secret Key Absent:       {'[PASS]' if report['secret_key_absent'] else '[FAIL]'}\n")
            f.write(f"2. AES Key Encryptable:     {'[PASS]' if report['aes_key_encryptable'] else '[FAIL]'}\n")
            f.write(f"3. Decryption Blocked:      {'[PASS]' if report['decryption_blocked'] else '[FAIL]'}\n\n")
            
            f.write("Architecture Details:\n")
            for key, value in report['details'].items():
                f.write(f"  - {key}: {value}\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("CONCLUSION\n")
            f.write("="*70 + "\n")
            
            if report['overall_status'] == 'PASS':
                f.write("\n[PASS] Key isolation is correctly implemented.\n")
                f.write("[PASS] CKKS secret key is NOT transmitted to cloud.\n")
                f.write("[PASS] AES key can be securely encrypted with CKKS.\n")
                f.write("[PASS] Server cannot decrypt data (zero-knowledge architecture).\n")
                f.write("\nH1 (Security Efficacy): VALIDATED\n")
            else:
                f.write("\n[FAIL] Key isolation verification FAILED.\n")
                f.write("[FAIL] Security architecture requires review.\n")
        
        print(f"\nKey isolation test report written to: {report_path}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
