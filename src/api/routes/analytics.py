import os
import json
import base64
import time
import tenseal as ts
from flask import Blueprint, request, jsonify
from src.analytics.advanced_statistics import AdvancedStatistics

analytics_bp = Blueprint("analytics", __name__)

def _load_context(dataset_id: str):
    ctx_path = os.path.join("data", "encrypted", dataset_id, "context.bin")
    if not os.path.exists(ctx_path):
        raise FileNotFoundError("Context not found")
    with open(ctx_path, "rb") as f:
        blob = f.read()
    return ts.context_from(blob)

def _load_records(dataset_id: str):
    rec_path = os.path.join("data", "encrypted", dataset_id, "records.json")
    if not os.path.exists(rec_path):
        raise FileNotFoundError("Records not found")
    with open(rec_path, "r") as f:
        return json.load(f)

def _get_vectors(dataset_id, field_name):
    try:
        ctx = _load_context(dataset_id)
        records = _load_records(dataset_id)
    except FileNotFoundError:
        return None, None

    key = f"{field_name}_enc"
    vectors = []
    for rec in records:
        item = rec.get(key)
        if not item or "ckks" not in item:
            continue
        b = base64.b64decode(item["ckks"])
        vec = ts.ckks_vector_from(ctx, b)
        vectors.append(vec)
    return vectors, ctx

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
    
    vectors, _ = _get_vectors(dataset_id, field_name)
    if not vectors:
        return jsonify({"error": "No data found"}), 404

    start_time = time.time()
    res = AdvancedStatistics.homomorphic_mean(vectors)
    duration = time.time() - start_time
    
    return jsonify({
        "result": {"ckks": base64.b64encode(res.serialize()).decode("ascii")},
        "metrics": {"duration_seconds": duration, "operation": "mean", "record_count": len(vectors)}
    })

@analytics_bp.post("/sum")
def compute_sum():
    data = request.get_json(force=True)
    dataset_id = data.get("dataset_id")
    field_name = data.get("field_name")
    
    vectors, _ = _get_vectors(dataset_id, field_name)
    if not vectors:
        return jsonify({"error": "No data found"}), 404

    start_time = time.time()
    res = AdvancedStatistics.homomorphic_sum(vectors)
    duration = time.time() - start_time
    
    return jsonify({
        "result": {"ckks": base64.b64encode(res.serialize()).decode("ascii")},
        "metrics": {"duration_seconds": duration, "operation": "sum", "record_count": len(vectors)}
    })

@analytics_bp.post("/variance")
def compute_variance():
    data = request.get_json(force=True)
    dataset_id = data.get("dataset_id")
    field_name = data.get("field_name")
    
    vectors, _ = _get_vectors(dataset_id, field_name)
    if not vectors:
        return jsonify({"error": "No data found"}), 404

    start_time = time.time()
    try:
        res = AdvancedStatistics.homomorphic_variance(vectors)
        duration = time.time() - start_time
        
        return jsonify({
            "result": {"ckks": base64.b64encode(res.serialize()).decode("ascii")},
            "metrics": {"duration_seconds": duration, "operation": "variance", "record_count": len(vectors)}
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
    
    vectors, ctx = _get_vectors(dataset_id, field_name)
    if not vectors:
        return jsonify({"error": "No data found"}), 404

    try:
        # Decrypt all values
        plaintext_values = []
        for vec in vectors:
            dec = vec.decrypt()
            plaintext_values.append(float(dec[0]))
        
        # Compute operation
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
        return jsonify({"error": str(e)}), 500

