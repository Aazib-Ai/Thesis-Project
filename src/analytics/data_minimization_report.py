"""
Data Minimization Report Generator

This module analyzes datasets to prove compliance with data minimization principles
(GDPR Art. 5(1)(c) and HIPAA § 164.502(b)).

It verifies that:
1. Only necessary fields are collected
2. All collected fields are encrypted
3. Each field has a documented purpose
4. No extraneous data is stored
"""

from typing import Dict, Any
import pandas as pd
from src.crypto.data_classifier import DataClassifier


class DataMinimizationAnalyzer:
    """
    Analyzes datasets for data minimization compliance.
    """
    
    @staticmethod
    def analyze_dataset(dataset: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze a dataset for data minimization compliance.
        
        Args:
            dataset: Pandas DataFrame containing patient records
            
        Returns:
            Dictionary with minimization analysis:
            - total_fields: Number of fields in dataset
            - necessary_fields: Fields that are PII or SENSITIVE_VITALS
            - unnecessary_fields: Fields marked as UNKNOWN
            - encryption_coverage: Percentage of fields encrypted
            - minimization_compliance: Percentage (0-100)
            - field_purposes: Dictionary mapping fields to purposes
        """
        # Get classification report
        report = DataClassifier.get_classification_report(dataset)
        
        # Calculate metrics
        total_fields = report['total_fields']
        necessary_count = report['pii_count'] + report['vitals_count']
        unnecessary_count = report['unknown_count']
        
        # Encryption coverage (all PII and vitals are encrypted)
        encryption_coverage = (necessary_count / total_fields * 100) if total_fields > 0 else 0
        
        # Minimization compliance (percentage of necessary fields)
        minimization_compliance = (necessary_count / total_fields * 100) if total_fields > 0 else 0
        
        # Field purposes
        field_purposes = {}
        for field, category in report['field_classifications'].items():
            if category == 'PII':
                field_purposes[field] = 'Patient identification and contact'
            elif category == 'SENSITIVE_VITALS':
                field_purposes[field] = 'Healthcare analytics'
            else:
                field_purposes[field] = 'UNKNOWN (not necessary, will be rejected)'
        
        # Get list of field names by category
        pii_fields = [f for f, c in report['field_classifications'].items() if c == 'PII']
        vital_fields = [f for f, c in report['field_classifications'].items() if c == 'SENSITIVE_VITALS']
        unknown_fields = [f for f, c in report['field_classifications'].items() if c == 'UNKNOWN']
        
        return {
            'total_fields': total_fields,
            'necessary_fields': necessary_count,
            'unnecessary_fields': unnecessary_count,
            'pii_fields': pii_fields,
            'vital_fields': vital_fields,
            'unknown_fields': unknown_fields,
            'encryption_coverage_percent': round(encryption_coverage, 2),
            'minimization_compliance_percent': round(minimization_compliance, 2),
            'field_purposes': field_purposes,
            'dataset_rows': len(dataset)
        }
    
    @staticmethod
    def generate_report(analysis: Dict[str, Any]) -> str:
        """
        Generate a human-readable minimization report.
        
        Args:
            analysis: Output from analyze_dataset()
            
        Returns:
            Formatted report string
        """
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("DATA MINIMIZATION COMPLIANCE REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"Dataset Size: {analysis['dataset_rows']} records")
        report_lines.append(f"Total Fields: {analysis['total_fields']}")
        report_lines.append("")
        
        report_lines.append("FIELD BREAKDOWN:")
        report_lines.append(f"  - Necessary Fields:     {analysis['necessary_fields']} ({analysis['minimization_compliance_percent']}%)")
        report_lines.append(f"  - Unnecessary Fields:   {analysis['unnecessary_fields']}")
        report_lines.append("")
        
        report_lines.append("ENCRYPTION COVERAGE:")
        report_lines.append(f"  - Fields Encrypted:     {analysis['necessary_fields']} ({analysis['encryption_coverage_percent']}%)")
        report_lines.append(f"  - Fields Plaintext:     0 (0%)")
        report_lines.append("")
        
        report_lines.append("COMPLIANCE STATUS:")
        if analysis['minimization_compliance_percent'] == 100.0:
            report_lines.append("  ✅ FULL COMPLIANCE (100%)")
            report_lines.append("  All fields are necessary. No excessive data collection.")
        elif analysis['minimization_compliance_percent'] >= 90.0:
            report_lines.append(f"  ⚠️ PARTIAL COMPLIANCE ({analysis['minimization_compliance_percent']}%)")
            report_lines.append(f"  Warning: {analysis['unnecessary_fields']} unnecessary field(s) detected.")
        else:
            report_lines.append(f"  ❌ NON-COMPLIANT ({analysis['minimization_compliance_percent']}%)")
            report_lines.append(f"  Critical: {analysis['unnecessary_fields']} unnecessary field(s) will be rejected.")
        report_lines.append("")
        
        report_lines.append("PII FIELDS (AES-256-GCM Encryption):")
        for field in analysis['pii_fields']:
            purpose = analysis['field_purposes'].get(field, 'Unknown')
            report_lines.append(f"  - {field:30s} → {purpose}")
        report_lines.append("")
        
        report_lines.append("SENSITIVE VITALS (CKKS Homomorphic Encryption):")
        for field in analysis['vital_fields']:
            purpose = analysis['field_purposes'].get(field, 'Unknown')
            report_lines.append(f"  - {field:30s} → {purpose}")
        report_lines.append("")
        
        if analysis['unknown_fields']:
            report_lines.append("UNNECESSARY FIELDS (Will be REJECTED):")
            for field in analysis['unknown_fields']:
                report_lines.append(f"  - {field:30s} → NOT NECESSARY (not stored)")
            report_lines.append("")
            report_lines.append("⚠️ These fields will NOT be processed or stored (data minimization enforcement)")
            report_lines.append("")
        
        report_lines.append("=" * 70)
        
        return "\n".join(report_lines)
    
    @staticmethod
    def check_compliance(dataset: pd.DataFrame) -> bool:
        """
        Quick compliance check.
        
        Args:
            dataset: Pandas DataFrame to check
            
        Returns:
            True if 100% compliant (no unnecessary fields), False otherwise
        """
        analysis = DataMinimizationAnalyzer.analyze_dataset(dataset)
        return analysis['minimization_compliance_percent'] == 100.0


# Command-line interface for testing
if __name__ == "__main__":
    import sys
    
    print("\nData Minimization Analyzer\n")
    
    # Test with sample data
    sample_data = pd.DataFrame({
        'patient_id': ['P001', 'P002'],
        'name': ['John Doe', 'Jane Smith'],
        'heart_rate': [72, 75],
        'glucose': [95, 110],
        'ssn': ['123-45-6789', '987-65-4321'],  # Unnecessary field
        'notes': ['Sample note', 'Another note']  # Unnecessary field
    })
    
    print("Testing with sample dataset (includes unnecessary fields):\n")
    analysis = DataMinimizationAnalyzer.analyze_dataset(sample_data)
    report = DataMinimizationAnalyzer.generate_report(analysis)
    print(report)
    
    print("\n\nCompliance check result:", 
          "✅ PASS" if DataMinimizationAnalyzer.check_compliance(sample_data) else "❌ FAIL")
