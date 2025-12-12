"""
Data Classification Module for Hybrid Encryption System

This module provides explicit data segmentation logic to classify healthcare
data fields into categories for appropriate encryption:
- PII (Personally Identifiable Information): Encrypted with AES-256-GCM
- SENSITIVE_VITALS: Encrypted with CKKS for homomorphic computation

Security Rationale:
- PII requires fast, deterministic encryption/decryption (AES-256-GCM)
- Vitals require computation on encrypted data (CKKS homomorphic encryption)
"""

from typing import Dict, Any, Tuple, List
import pandas as pd


class DataClassifier:
    """
    Classifies healthcare data fields for hybrid encryption architecture.
    
    This classifier ensures proper data segmentation to prove H1 (Security Efficacy)
    by explicitly routing PII to AES-256-GCM and vital signs to CKKS encryption.
    """
    
    # PII fields that identify individuals - require AES-256-GCM encryption
    PII_FIELDS = [
        "patient_id",
        "name", 
        "address",
        "phone",
        "email",
        "dob"
    ]
    
    # Sensitive vitals that require homomorphic computation - use CKKS
    SENSITIVE_VITALS = [
        "heart_rate",
        "blood_pressure_sys",
        "blood_pressure_dia",
        "temperature",
        "glucose",
        "bmi",
        "cholesterol"
    ]
    
    @staticmethod
    def classify_field(field_name: str) -> str:
        """
        Classify a single field name into a category.
        
        Args:
            field_name: Name of the field to classify
            
        Returns:
            'PII', 'SENSITIVE_VITALS', or 'UNKNOWN'
            
        Example:
            >>> DataClassifier.classify_field("patient_id")
            'PII'
            >>> DataClassifier.classify_field("heart_rate")
            'SENSITIVE_VITALS'
        """
        field_lower = field_name.lower().strip()
        
        if field_lower in [f.lower() for f in DataClassifier.PII_FIELDS]:
            return 'PII'
        elif field_lower in [f.lower() for f in DataClassifier.SENSITIVE_VITALS]:
            return 'SENSITIVE_VITALS'
        else:
            return 'UNKNOWN'
    
    @staticmethod
    def segment_record(record: Dict[str, Any]) -> Tuple[Dict[str, str], Dict[str, float]]:
        """
        Segment a patient record into PII and vitals dictionaries.
        
        This method enforces data separation to ensure:
        - PII is never processed by CKKS (no homomorphic operations on identifiers)
        - Vitals are never stored in plaintext with AES (maintained as encrypted floats)
        
        Args:
            record: Dictionary containing patient data
            
        Returns:
            Tuple of (pii_dict, vitals_dict)
            - pii_dict: Contains PII fields as strings
            - vitals_dict: Contains vital signs as floats
            
        Example:
            >>> record = {
            ...     "patient_id": "P001",
            ...     "name": "John Doe",
            ...     "heart_rate": 72.5,
            ...     "temperature": 98.6
            ... }
            >>> pii, vitals = DataClassifier.segment_record(record)
            >>> pii
            {'patient_id': 'P001', 'name': 'John Doe'}
            >>> vitals
            {'heart_rate': 72.5, 'temperature': 98.6}
        """
        pii_dict: Dict[str, str] = {}
        vitals_dict: Dict[str, float] = {}
        
        for field_name, value in record.items():
            category = DataClassifier.classify_field(field_name)
            
            if category == 'PII':
                # Convert to string for AES encryption
                pii_dict[field_name] = str(value)
            elif category == 'SENSITIVE_VITALS':
                # Convert to float for CKKS encryption
                try:
                    vitals_dict[field_name] = float(value)
                except (ValueError, TypeError):
                    # Skip non-numeric vitals
                    pass
            # UNKNOWN fields are ignored for security (data minimization)
        
        return pii_dict, vitals_dict
    
    @staticmethod
    def get_classification_report(dataset: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate a classification report for an entire dataset.
        
        This report proves data segmentation for thesis validation:
        - Shows field-by-field classification
        - Counts PII vs vitals fields
        - Calculates percentage of data protected by each encryption scheme
        
        Args:
            dataset: Pandas DataFrame containing patient records
            
        Returns:
            Dictionary with classification statistics:
            - field_classifications: Dict mapping field names to categories
            - pii_count: Number of PII fields
            - vitals_count: Number of vitals fields
            - unknown_count: Number of unclassified fields
            - total_fields: Total number of fields
            - pii_percentage: Percentage of fields classified as PII
            - vitals_percentage: Percentage of fields classified as vitals
            
        Example:
            >>> df = pd.DataFrame({
            ...     "patient_id": ["P001", "P002"],
            ...     "heart_rate": [72, 75],
            ...     "custom_field": ["A", "B"]
            ... })
            >>> report = DataClassifier.get_classification_report(df)
            >>> report['pii_count']
            1
            >>> report['vitals_count']
            1
        """
        field_classifications = {}
        pii_count = 0
        vitals_count = 0
        unknown_count = 0
        
        for column in dataset.columns:
            category = DataClassifier.classify_field(column)
            field_classifications[column] = category
            
            if category == 'PII':
                pii_count += 1
            elif category == 'SENSITIVE_VITALS':
                vitals_count += 1
            else:
                unknown_count += 1
        
        total_fields = len(dataset.columns)
        
        return {
            'field_classifications': field_classifications,
            'pii_count': pii_count,
            'vitals_count': vitals_count,
            'unknown_count': unknown_count,
            'total_fields': total_fields,
            'pii_percentage': (pii_count / total_fields * 100) if total_fields > 0 else 0,
            'vitals_percentage': (vitals_count / total_fields * 100) if total_fields > 0 else 0,
            'dataset_rows': len(dataset)
        }
    
    @staticmethod
    def print_classification_summary(report: Dict[str, Any]) -> None:
        """
        Print a human-readable classification summary.
        
        Args:
            report: Classification report from get_classification_report()
        """
        print("\n" + "="*60)
        print("DATA CLASSIFICATION REPORT")
        print("="*60)
        print(f"Dataset Size: {report['dataset_rows']} records")
        print(f"Total Fields: {report['total_fields']}")
        print(f"\nField Breakdown:")
        print(f"  - PII Fields (AES-256-GCM):        {report['pii_count']} ({report['pii_percentage']:.1f}%)")
        print(f"  - Sensitive Vitals (CKKS):         {report['vitals_count']} ({report['vitals_percentage']:.1f}%)")
        print(f"  - Unknown/Unclassified:            {report['unknown_count']}")
        print(f"\nField-by-Field Classification:")
        for field, category in report['field_classifications'].items():
            print(f"  - {field:30s} → {category}")
        print("="*60 + "\n")
