import numpy as np
from typing import List, Dict, Union, Any
import math

def calculate_mse(plaintext_result: List[float], decrypted_result: List[float]) -> float:
    """
    Calculates Mean Squared Error between plaintext and decrypted values.
    
    Args:
        plaintext_result: List of expected plaintext values
        decrypted_result: List of actual decrypted values
        
    Returns:
        float: The Mean Squared Error
    """
    if len(plaintext_result) != len(decrypted_result):
        # Handle case where one might be a single value wrapping a list and the other is just a list
        if len(plaintext_result) == 1 and len(decrypted_result) > 1:
            # Maybe broadcast? No, strict check for now unless they are both length 1 conceptually
            raise ValueError(f"Length mismatch: {len(plaintext_result)} vs {len(decrypted_result)}")
        elif len(plaintext_result) != len(decrypted_result):
             raise ValueError(f"Length mismatch: {len(plaintext_result)} vs {len(decrypted_result)}")

    # Ensure inputs are numpy arrays
    p_arr = np.array(plaintext_result)
    d_arr = np.array(decrypted_result)
    
    return np.mean((p_arr - d_arr) ** 2)

def calculate_rmse(plaintext_result: List[float], decrypted_result: List[float]) -> float:
    """
    Calculates Root Mean Squared Error between plaintext and decrypted values.
    """
    return np.sqrt(calculate_mse(plaintext_result, decrypted_result))

def calculate_accuracy_percentage(plaintext_result: List[float], decrypted_result: List[float], tolerance: float = 0.01) -> float:
    """
    Calculates the percentage of decrypted values that are within the tolerance of the plaintext values.
    
    Args:
        plaintext_result: List of expected plaintext values
        decrypted_result: List of actual decrypted values
        tolerance: Absolute error tolerance for a 'match'
        
    Returns:
        float: Percentage of matches (0.0 to 100.0)
    """
    if len(plaintext_result) != len(decrypted_result):
        raise ValueError(f"Length mismatch: {len(plaintext_result)} vs {len(decrypted_result)}")
        
    p_arr = np.array(plaintext_result)
    d_arr = np.array(decrypted_result)
    
    diff = np.abs(p_arr - d_arr)
    matches = np.sum(diff <= tolerance)
    
    if len(p_arr) == 0:
        return 0.0
        
    return (matches / len(p_arr)) * 100.0

def calculate_relative_error_percentage(plaintext_val: float, decrypted_val: float) -> float:
    """
    Calculates relative error as a percentage.
    If plaintext is 0, returns absolute error (best effort).
    """
    if plaintext_val == 0:
        return abs(plaintext_val - decrypted_val) * 100 # Treat as abs error %? Or just error.
    
    return (abs(plaintext_val - decrypted_val) / abs(plaintext_val)) * 100.0

def generate_accuracy_report(plaintext_values: List[float], 
                           encrypted_values: List[Any], 
                           ckks_context) -> Dict[str, Union[float, List[float]]]:
    """
    Decrypts encrypted values and generates a comprehensive accuracy report.
    This assumes encrypted_values is a list of encrypted CKKS vectors that correspond 1-to-1 with plaintext_values.
    
    Args:
        plaintext_values: List of original values
        encrypted_values: List of encrypted vectors (tenseal objects)
        ckks_context: The context wrapper (must have decrypt_vector method)
        
    Returns:
        Dictionary containing MSE, RMSE, Accuracy Percentage, and decrypted values
    """
    
    decrypted_values = []
    
    # Decrypt everything first
    # Depending on how encrypted_values is structured:
    # It might be a list of CKKSVectors, each containing 1 element.
    for enc in encrypted_values:
        # Using the context wrapper's decrypt method if it exists, otherwise calling decrypt directly on object
        if hasattr(ckks_context, 'decrypt_vector'):
            res = ckks_context.decrypt_vector(enc)
        else:
            res = enc.decrypt()
            
        # Result is usually a list. If we expect scalars, take the first one.
        # But we should be careful. 
        # Assuming 1-to-1 mapping for now.
        if isinstance(res, list) and len(res) >= 1:
            decrypted_values.append(res[0])
        elif isinstance(res, (float, int)):
            decrypted_values.append(float(res))
        else:
            decrypted_values.append(0.0) # Fallback?

    mse = calculate_mse(plaintext_values, decrypted_values)
    rmse = calculate_rmse(plaintext_values, decrypted_values)
    accuracy = calculate_accuracy_percentage(plaintext_values, decrypted_values)
    
    return {
        "mse": mse,
        "rmse": rmse,
        "accuracy_pct": accuracy,
        "decrypted_values": decrypted_values
    }
