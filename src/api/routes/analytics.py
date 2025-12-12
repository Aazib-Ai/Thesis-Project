import os
import json
import base64
import time
import logging
import tenseal as ts
from flask import Blueprint, request, jsonify
from src.analytics.advanced_statistics import AdvancedStatistics
from src.analytics.columnar_statistics import ColumnarStatistics
from src.crypto.ckks_module import CKKSContext

logger = logging.getLogger(__name__)
analytics_bp = Blueprint("analytics", __name__)

def _load_context(dataset_id: str):
    ctx_path = os.path.join("data", "encrypted", dataset_id, "context.bin")
    if not os.path.exists(ctx_path):
        raise FileNotFoundError("Context not found")
    with open(ctx_path, "rb") as f:
        blob = f.read()
    return ts.context_from(blob)

def _load_metadata(dataset_id: str):
    """Load metadata.json for a dataset."""
    meta_path = os.path.join("data", "encrypted", dataset_id, "metadata.json")
    if not os.path.exists(meta_path):
        return {}
    with open(meta_path, "r") as f:
        return json.load(f)

def _load_records(dataset_id: str):
    rec_path = os.path.join("data", "encrypted", dataset_id, "records.json")
    if not os.path.exists(rec_path):
        raise FileNotFoundError("Records not found")
    with open(rec_path, "r") as f:
        return json.load(f)

def _get_vectors(dataset_id, field_name):
    """
    Get encrypted data for a specific field from the dataset.
    
    Handles three formats:
    1. Columnar SIMD (NEW): Load from columns/ directory - returns encrypted column
    2. Row SIMD: _vitals_encrypted with _vitals_field_order - returns plaintext (legacy)
    3. Legacy: individual {field}_enc entries - returns encrypted vectors (legacy)
    """
    try:
        ctx = _load_context(dataset_id)
        metadata = _load_metadata(dataset_id)
    except FileNotFoundError:
        return None, None, None
    
    # Check if this is columnar SIMD format (Phase 1 implementation)
    if metadata.get('encryption_mode') == 'columnar_simd':
        # NEW: Load from columns/ directory
        columns_dir = os.path.join("data", "encrypted", dataset_id, "columns")
        
        if not os.path.exists(columns_dir):
            logger.warning(f"Columnar mode but columns/ directory not found")
            return None, None, None
        
        try:
            from src.crypto.columnar_encryption import ColumnarEncryptor
            ck = CKKSContext()  # Dummy context for loading
            columnar_enc = ColumnarEncryptor(ck)
            
            # Load encrypted column (stays encrypted)
            enc_col = columnar_enc.load_encrypted_column(field_name, columns_dir, ctx)
            
            # Get actual count from metadata
            actual_counts = metadata.get('actual_counts', {})
            actual_count = actual_counts.get(field_name, metadata.get('actual_count', 0))
            
            logger.info(f"Loaded columnar encrypted field '{field_name}' with {actual_count} records")
            return enc_col, ctx, actual_count
        except FileNotFoundError:
            logger.error(f"Column file not found for field '{field_name}'")
            return None, None, None
        except Exception as e:
            logger.error(f"Error loading columnar data: {e}")
            return None, None, None
    
    # Legacy formats - load records.json
    try:
        records = _load_records(dataset_id)
    except FileNotFoundError:
        return None, None, None

    vectors = []
    
    # Check first record to determine format
    if records and '_vitals_encrypted' in records[0] and '_vitals_field_order' in records[0]:
        # Row SIMD format: extract specific field from packed vector
        for rec in records:
            field_order = rec.get('_vitals_field_order', [])
            if field_name not in field_order:
                continue
            
            field_idx = field_order.index(field_name)
            vitals_data = rec.get('_vitals_encrypted')
            
            if not vitals_data or 'ckks' not in vitals_data:
                continue
            
            b = base64.b64decode(vitals_data['ckks'])
            vec = ts.ckks_vector_from(ctx, b)
            # Store tuple of (vector, field_index) for SIMD extraction
            vectors.append((vec, field_idx))
        
        # For Row SIMD, we need to decrypt and extract the specific slot
        # Return plaintext values extracted from SIMD vectors for computation
        if vectors:
            extracted_values = []
            for vec, idx in vectors:
                dec = vec.decrypt()
                if idx < len(dec):
                    extracted_values.append(float(dec[idx]))
            return extracted_values, ctx, None
    else:
        # Legacy format: individual encrypted fields
        key = f"{field_name}_enc"
        for rec in records:
            item = rec.get(key)
            if not item or "ckks" not in item:
                continue
            b = base64.b64decode(item["ckks"])
            vec = ts.ckks_vector_from(ctx, b)
            vectors.append(vec)
        return vectors, ctx, None
    
    return vectors, ctx, None

@analytics_bp.get("/operations")
def list_operations():
    return jsonify({
        "operations": [
            {"id": "mean", "name": "Mean (Average)", "icon": "fa-calculator"},
            {"id": "sum", "name": "Sum (Total)", "icon": "fa-plus"},
            {"id": "variance", "name": "Variance", "icon": "fa-chart-bar"},
            {"id": "std_dev", "name": "Standard Deviation", "icon": "fa-ruler-horizontal"}
        ]
    })

@analytics_bp.post("/mean")
def compute_mean():
    data = request.get_json(force=True)
    dataset_id = data.get("dataset_id")
    field_name = data.get("field_name")
    
    result_data, ctx, actual_count = _get_vectors(dataset_id, field_name)
    if not result_data:
        return jsonify({"error": "No data found"}), 404

    start_time = time.time()
    
    # Check data format
    if isinstance(result_data, dict) and ('ciphertext' in result_data or 'ciphertexts' in result_data):
        # Columnar SIMD format: TRUE HOMOMORPHIC computation
        try:
            # CRITICAL: Inject actual_count into the dict for correct mean/variance calculation
            result_data['actual_count'] = actual_count
            result_enc = ColumnarStatistics.compute_operation(result_data, 'mean')
            duration = time.time() - start_time
            
            logger.info(f"Computed homomorphic mean for '{field_name}' in {duration:.4f}s (ENCRYPTED)")
            
            return jsonify({
                "result": {"ckks": base64.b64encode(result_enc.serialize()).decode("ascii")},
                "metrics": {
                    "duration_seconds": duration,
                    "operation": "mean",
                    "record_count": actual_count,
                    "format": "columnar_simd"
                }
            })
        except Exception as e:
            logger.error(f"Error in columnar mean: {e}")
            return jsonify({"error": str(e)}), 500
    elif isinstance(result_data, list) and result_data and isinstance(result_data[0], (int, float)):
        # Row SIMD format: values are already decrypted (legacy)
        result_value = sum(result_data) / len(result_data)
        duration = time.time() - start_time
        return jsonify({
            "value": result_value,
            "metrics": {"duration_seconds": duration, "operation": "mean", "record_count": len(result_data), "format": "row_simd"}
        })
    else:
        # Legacy format: use homomorphic computation
        res = AdvancedStatistics.homomorphic_mean(result_data)
        duration = time.time() - start_time
        return jsonify({
            "result": {"ckks": base64.b64encode(res.serialize()).decode("ascii")},
            "metrics": {"duration_seconds": duration, "operation": "mean", "record_count": len(result_data), "format": "legacy"}
        })

@analytics_bp.post("/sum")
def compute_sum():
    data = request.get_json(force=True)
    dataset_id = data.get("dataset_id")
    field_name = data.get("field_name")
    
    result_data, ctx, actual_count = _get_vectors(dataset_id, field_name)
    if not result_data:
        return jsonify({"error": "No data found"}), 404

    start_time = time.time()
    
    # Check data format
    if isinstance(result_data, dict) and ('ciphertext' in result_data or 'ciphertexts' in result_data):
        # Columnar SIMD format: TRUE HOMOMORPHIC computation
        try:
            # Inject actual_count into the dict (for consistency, though sum doesn't use it)
            result_data['actual_count'] = actual_count
            result_enc = ColumnarStatistics.compute_operation(result_data, 'sum')
            duration = time.time() - start_time
            
            logger.info(f"Computed homomorphic sum for '{field_name}' in {duration:.4f}s (ENCRYPTED)")
            
            return jsonify({
                "result": {"ckks": base64.b64encode(result_enc.serialize()).decode("ascii")},
                "metrics": {
                    "duration_seconds": duration,
                    "operation": "sum",
                    "record_count": actual_count,
                    "format": "columnar_simd"
                }
            })
        except Exception as e:
            logger.error(f"Error in columnar sum: {e}")
            return jsonify({"error": str(e)}), 500
    elif isinstance(result_data, list) and result_data and isinstance(result_data[0], (int, float)):
        # Row SIMD format: values are already decrypted (legacy)
        result_value = sum(result_data)
        duration = time.time() - start_time
        return jsonify({
            "value": result_value,
            "metrics": {"duration_seconds": duration, "operation": "sum", "record_count": len(result_data), "format": "row_simd"}
        })
    else:
        # Legacy format: use homomorphic computation
        res = AdvancedStatistics.homomorphic_sum(result_data)
        duration = time.time() - start_time
        return jsonify({
            "result": {"ckks": base64.b64encode(res.serialize()).decode("ascii")},
            "metrics": {"duration_seconds": duration, "operation": "sum", "record_count": len(result_data), "format": "legacy"}
        })

@analytics_bp.post("/variance")
def compute_variance():
    data = request.get_json(force=True)
    dataset_id = data.get("dataset_id")
    field_name = data.get("field_name")
    
    result_data, ctx, actual_count = _get_vectors(dataset_id, field_name)
    if not result_data:
        return jsonify({"error": "No data found"}), 404

    start_time = time.time()
    try:
        # Check data format
        if isinstance(result_data, dict) and ('ciphertext' in result_data or 'ciphertexts' in result_data):
            # Columnar SIMD format: TRUE HOMOMORPHIC computation
            try:
                # CRITICAL: Inject actual_count into the dict for correct variance calculation
                result_data['actual_count'] = actual_count
                result_enc = ColumnarStatistics.compute_operation(result_data, 'variance')
                duration = time.time() - start_time
                
                logger.info(f"Computed homomorphic variance for '{field_name}' in {duration:.4f}s (ENCRYPTED)")
                
                return jsonify({
                    "result": {"ckks": base64.b64encode(result_enc.serialize()).decode("ascii")},
                    "metrics": {
                        "duration_seconds": duration,
                        "operation": "variance",
                        "record_count": actual_count,
                        "format": "columnar_simd"
                    }
                })
            except Exception as e:
                logger.error(f"Error in columnar variance: {e}")
                return jsonify({"error": str(e)}), 500
        elif isinstance(result_data, list) and result_data and isinstance(result_data[0], (int, float)):
            # Row SIMD format: values are already decrypted (legacy)
            mean_val = sum(result_data) / len(result_data)
            variance = sum((x - mean_val) ** 2 for x in result_data) / len(result_data)
            duration = time.time() - start_time
            return jsonify({
                "value": variance,
                "metrics": {"duration_seconds": duration, "operation": "variance", "record_count": len(result_data), "format": "row_simd"}
            })
        else:
            # Legacy format: use homomorphic computation
            res = AdvancedStatistics.homomorphic_variance(result_data)
            duration = time.time() - start_time
            return jsonify({
                "result": {"ckks": base64.b64encode(res.serialize()).decode("ascii")},
                "metrics": {"duration_seconds": duration, "operation": "variance", "record_count": len(result_data), "format": "legacy"}
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@analytics_bp.post("/decrypt/result")
def decrypt_result():
    # Note: In production this should be protected
    data = request.get_json(force=True)
    dataset_id = data.get("dataset_id")
    result_obj = data.get("result")
    
    if not dataset_id or not result_obj or "ckks" not in result_obj:
        return jsonify({"error": "Invalid request"}), 400

    try:
        ctx = _load_context(dataset_id)
        b = base64.b64decode(result_obj["ckks"])
        vec = ts.ckks_vector_from(ctx, b)
        dec = vec.decrypt()
        return jsonify({"value": float(dec[0])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@analytics_bp.post("/plaintext")
def compute_plaintext():
    """
    Compute operation on decrypted (plaintext) values for accuracy comparison.
    This decrypts all encrypted values first, then performs the calculation.
    """
    data = request.get_json(force=True)
    dataset_id = data.get("dataset_id")
    field_name = data.get("field_name")
    operation = data.get("operation", "mean")
    
    vectors, ctx, actual_count = _get_vectors(dataset_id, field_name)
    if not vectors:
        return jsonify({"error": "No data found"}), 404

    try:
        # Decrypt all values
        plaintext_values = []
        
        # Case 1: Columnar SIMD (Dict)
        if isinstance(vectors, dict):
            # Extract vectors from the dictionary structure
            chunk_vectors = []
            if 'ciphertext' in vectors:
                chunk_vectors = [vectors['ciphertext']]
            elif 'ciphertexts' in vectors:
                chunk_vectors = vectors['ciphertexts']
            
            # Decrypt each chunk and extend the list
            for vec in chunk_vectors:
                dec = vec.decrypt()
                plaintext_values.extend(dec)
                
            # Truncate to actual count if available (to remove padding)
            if actual_count is not None and actual_count > 0:
                plaintext_values = plaintext_values[:actual_count]
                
        # Case 2: Row SIMD (List of floats - already decrypted)
        elif isinstance(vectors, list) and len(vectors) > 0 and isinstance(vectors[0], (int, float)):
            plaintext_values = vectors
            
        # Case 3: Legacy (List of encrypted vectors)
        else:
            for vec in vectors:
                dec = vec.decrypt()
                # Legacy format usually stores one value per vector
                if dec:
                    plaintext_values.append(float(dec[0]))
        
        # Compute operation
        if not plaintext_values:
             return jsonify({"error": "No values to compute"}), 400

        if operation == "mean":
            result = sum(plaintext_values) / len(plaintext_values)
        elif operation == "sum":
            result = sum(plaintext_values)
        elif operation == "variance":
            mean_val = sum(plaintext_values) / len(plaintext_values)
            result = sum((x - mean_val) ** 2 for x in plaintext_values) / len(plaintext_values)
        else:
            return jsonify({"error": f"Unknown operation: {operation}"}), 400
        
        return jsonify({
            "value": result,
            "operation": operation,
            "record_count": len(plaintext_values)
        })
    except Exception as e:
        logger.error(f"Error in compute_plaintext: {e}")
        return jsonify({"error": str(e)}), 500

