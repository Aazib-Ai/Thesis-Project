import os
import json
import base64
import time
import threading
import uuid
from flask import Blueprint, request, jsonify, render_template
from src.crypto.ckks_module import CKKSContext
from src.crypto.aes_module import AESCipher
import tenseal as ts

decrypt_bp = Blueprint("decrypt", __name__)

# Global dictionary to store batch decryption progress
decryption_tasks = {}

def get_dataset_files(dataset_id):
    outdir = os.path.join("data", "encrypted", dataset_id)
    rec_path = os.path.join(outdir, "records.json")
    ctx_path = os.path.join(outdir, "context.bin")
    aes_path = os.path.join(outdir, "aes_key.bin")
    return rec_path, ctx_path, aes_path

@decrypt_bp.get("/ui")
def decrypt_ui():
    return render_template("decrypt.html")

@decrypt_bp.get("/preview/<dataset_id>")
def preview_dataset(dataset_id: str):
    rec_path, ctx_path, aes_path = get_dataset_files(dataset_id)
    
    if not (os.path.isfile(rec_path) and os.path.isfile(ctx_path) and os.path.isfile(aes_path)):
        return jsonify({"error": "dataset not found"}), 404
        
    limit = request.args.get("limit", default=10, type=int)
    offset = request.args.get("offset", default=0, type=int)
    
    try:
        with open(rec_path, "r") as f:
            records = json.load(f)
        
        # Pagination
        total_records = len(records)
        paginated_records = records[offset : offset + limit]
        
        # We return the RAW encrypted records structure for the frontend to handle visualization
        # The frontend will call /decrypt/field or /decrypt/record to get plaintext
        
        return jsonify({
            "dataset_id": dataset_id,
            "total": total_records,
            "limit": limit,
            "offset": offset,
            "records": paginated_records
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@decrypt_bp.post("/record")
def decrypt_record():
    data = request.get_json()
    dataset_id = data.get("dataset_id")
    record_index = data.get("record_index") # Index in the full list
    
    rec_path, ctx_path, aes_path = get_dataset_files(dataset_id)
    
    try:
        with open(rec_path, "r") as f:
            records = json.load(f)
        
        if record_index < 0 or record_index >= len(records):
            return jsonify({"error": "Index out of bounds"}), 400
            
        record = records[record_index]
        
        with open(ctx_path, "rb") as f:
            ctx = ts.context_from(f.read())
        with open(aes_path, "rb") as f:
            aes_key = f.read()
            
        decrypted_row = {}
        for k, v in record.items():
            if isinstance(v, dict) and {"nonce", "ciphertext", "tag"} <= set(v.keys()):
                # AES
                pt = AESCipher.decrypt(v, aes_key)
                decrypted_row[k] = pt.decode("utf-8", errors="ignore")
            elif isinstance(v, dict) and "ckks" in v:
                # CKKS
                b = base64.b64decode(v["ckks"])
                vec = ts.ckks_vector_from(ctx, b)
                dec = vec.decrypt()
                base = k.replace("_enc", "")
                decrypted_row[base] = float(dec[0])
            else:
                decrypted_row[k] = v
                
        return jsonify({"decrypted_record": decrypted_row})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@decrypt_bp.post("/field")
def decrypt_field():
    data = request.get_json()
    dataset_id = data.get("dataset_id")
    field_name = data.get("field_name")
    record_indices = data.get("record_indices") # List of indices to decrypt
    
    rec_path, ctx_path, aes_path = get_dataset_files(dataset_id)
    
    try:
        with open(rec_path, "r") as f:
            records = json.load(f)
            
        with open(ctx_path, "rb") as f:
            ctx = ts.context_from(f.read())
        with open(aes_path, "rb") as f:
            aes_key = f.read()
            
        results = {}
        
        for idx in record_indices:
            if idx < 0 or idx >= len(records):
                continue
            
            rec = records[idx]
            val = rec.get(field_name)
            
            if not val:
                continue
                
            if isinstance(val, dict) and {"nonce", "ciphertext", "tag"} <= set(val.keys()):
                # AES
                pt = AESCipher.decrypt(val, aes_key)
                results[idx] = pt.decode("utf-8", errors="ignore")
            elif isinstance(val, dict) and "ckks" in val:
                # CKKS
                b = base64.b64decode(val["ckks"])
                vec = ts.ckks_vector_from(ctx, b)
                dec = vec.decrypt()
                results[idx] = float(dec[0])
                
        return jsonify({"results": results})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_batch_decryption(task_id, dataset_id):
    try:
        decryption_tasks[task_id] = {"status": "processing", "progress": 0}
        
        rec_path, ctx_path, aes_path = get_dataset_files(dataset_id)
        
        with open(rec_path, "r") as f:
            records = json.load(f)
        with open(ctx_path, "rb") as f:
            ctx = ts.context_from(f.read())
        with open(aes_path, "rb") as f:
            aes_key = f.read()
            
        decrypted_data = []
        total = len(records)
        
        for i, rec in enumerate(records):
            row = {}
            for k, v in rec.items():
                if isinstance(v, dict) and {"nonce", "ciphertext", "tag"} <= set(v.keys()):
                    pt = AESCipher.decrypt(v, aes_key)
                    row[k] = pt.decode("utf-8", errors="ignore")
                elif isinstance(v, dict) and "ckks" in v:
                    b = base64.b64decode(v["ckks"])
                    vec = ts.ckks_vector_from(ctx, b)
                    dec = vec.decrypt()
                    base = k.replace("_enc", "")
                    row[base] = float(dec[0])
                else:
                    row[k] = v
            decrypted_data.append(row)
            
            if i % 10 == 0:
                decryption_tasks[task_id]["progress"] = int((i / total) * 100)
                
        # Save decrypted file temporarily for download
        out_file = os.path.join("data", "encrypted", dataset_id, "decrypted_export.json")
        with open(out_file, "w") as f:
            json.dump(decrypted_data, f)
            
        decryption_tasks[task_id] = {
            "status": "completed", 
            "progress": 100, 
            "download_url": f"/decrypt/download/{dataset_id}"
        }
        
    except Exception as e:
        decryption_tasks[task_id] = {"status": "failed", "error": str(e)}

@decrypt_bp.post("/batch")
def batch_decrypt():
    data = request.get_json()
    dataset_id = data.get("dataset_id")
    
    task_id = str(uuid.uuid4())
    
    # Initialize task status immediately to avoid race condition
    decryption_tasks[task_id] = {"status": "starting", "progress": 0}
    
    thread = threading.Thread(target=run_batch_decryption, args=(task_id, dataset_id))
    thread.start()
    
    return jsonify({"task_id": task_id})

@decrypt_bp.get("/status/<task_id>")
def batch_status(task_id):
    task = decryption_tasks.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)

@decrypt_bp.get("/download/<dataset_id>")
def download_decrypted(dataset_id):
    path = os.path.join("data", "encrypted", dataset_id, "decrypted_export.json")
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404
    from flask import send_file
    return send_file(path, as_attachment=True, download_name=f"decrypted_{dataset_id}.json")
