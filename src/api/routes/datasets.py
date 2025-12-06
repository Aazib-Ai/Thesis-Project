import os
import shutil
import json
import time
from flask import Blueprint, jsonify, request
from datetime import datetime

datasets_bp = Blueprint("datasets", __name__)

DATA_DIR = os.path.join("data", "encrypted")

def get_dataset_path(dataset_id):
    return os.path.join(DATA_DIR, dataset_id)

@datasets_bp.get("/list")
def list_datasets():
    if not os.path.exists(DATA_DIR):
        return jsonify({"datasets": []})
    
    datasets = []
    for d in os.listdir(DATA_DIR):
        path = os.path.join(DATA_DIR, d)
        if os.path.isdir(path):
            # Try to read metadata if it exists, otherwise infer
            meta_path = os.path.join(path, "metadata.json")
            metadata = {}
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    metadata = json.load(f)
            
            # Fallback/Default values
            stats = os.stat(path)
            created_at = datetime.fromtimestamp(stats.st_ctime).isoformat()
            
            datasets.append({
                "id": d,
                "name": metadata.get("name", d),
                "created_at": metadata.get("created_at", created_at),
                "record_count": metadata.get("record_count", "Unknown"),
                "size_bytes": sum(os.path.getsize(os.path.join(path, f)) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))),
                "status": "Encrypted" # Assuming if it exists here it's done
            })
    
    # Sort by newest first
    datasets.sort(key=lambda x: x["created_at"], reverse=True)
    return jsonify({"datasets": datasets})

@datasets_bp.get("/<dataset_id>/info")
def get_dataset_info(dataset_id):
    path = get_dataset_path(dataset_id)
    if not os.path.exists(path):
        return jsonify({"error": "Dataset not found"}), 404
        
    meta_path = os.path.join(path, "metadata.json")
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            metadata = json.load(f)
    else:
        metadata = {"id": dataset_id, "name": dataset_id}
        
    # Get file list
    files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    metadata["files"] = files
    
    return jsonify(metadata)

@datasets_bp.delete("/<dataset_id>")
def delete_dataset(dataset_id):
    path = get_dataset_path(dataset_id)
    if not os.path.exists(path):
        return jsonify({"error": "Dataset not found"}), 404
    
    try:
        shutil.rmtree(path)
        return jsonify({"status": "deleted", "id": dataset_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@datasets_bp.put("/<dataset_id>/rename")
def rename_dataset(dataset_id):
    path = get_dataset_path(dataset_id)
    if not os.path.exists(path):
        return jsonify({"error": "Dataset not found"}), 404
        
    data = request.get_json()
    new_name = data.get("name")
    if not new_name:
        return jsonify({"error": "New name required"}), 400
        
    # Update metadata
    meta_path = os.path.join(path, "metadata.json")
    metadata = {}
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            metadata = json.load(f)
            
    metadata["name"] = new_name
    
    with open(meta_path, 'w') as f:
        json.dump(metadata, f)
        
    return jsonify({"status": "renamed", "name": new_name})
