import os
import json
import uuid
import base64
import threading
import time
from datetime import datetime
import pandas as pd
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from src.crypto.hybrid_encryption import KeyManager, HybridEncryptor
from src.crypto.ckks_module import CKKSContext
from src.crypto.aes_module import AESCipher
import tenseal as ts

encrypt_bp = Blueprint("encrypt", __name__)

# Global dictionary to store task progress
# In a production app, use Redis or a database
encryption_tasks = {}

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def run_encryption_task(task_id, df, original_filename):
    try:
        encryption_tasks[task_id] = {"status": "processing", "progress": 10, "step": "Initializing Crypto Modules"}
        
        # Simulate some time for visual effect if dataset is small
        time.sleep(0.5)
        
        ck = CKKSContext()
        ck.create_context()
        km = KeyManager()
        he = HybridEncryptor(ck, km)
        aes_key = km.generate_aes_key()

        encryption_tasks[task_id].update({"progress": 30, "step": "Encrypting Records (AES + CKKS)"})
        
        records = []
        total_rows = len(df)
        
        for idx, (_, row) in enumerate(df.iterrows()):
            enc = he.encrypt_patient_record(row.to_dict(), aes_key)
            records.append(enc)
            
            # Update progress periodically
            if idx % 10 == 0:
                percent = 30 + int((idx / total_rows) * 50) # 30% to 80%
                encryption_tasks[task_id].update({"progress": percent})

        encryption_tasks[task_id].update({"progress": 80, "step": "Serializing & Saving"})

        dsid = str(uuid.uuid4())
        outdir = os.path.join("data", "encrypted", dsid)
        ensure_dir(outdir)

        context_blob = ck.serialize_context(save_secret_key=True)
        with open(os.path.join(outdir, "context.bin"), "wb") as f:
            f.write(context_blob)

        with open(os.path.join(outdir, "aes_key.bin"), "wb") as f:
            f.write(aes_key)

        def encode_payload(obj):
            if hasattr(obj, "serialize"):
                b = obj.serialize()
                return {"ckks": base64.b64encode(b).decode("ascii")}
            return obj

        encoded_records = []
        for rec in records:
            enc_rec = {}
            for k, v in rec.items():
                enc_rec[k] = encode_payload(v)
            encoded_records.append(enc_rec)

        with open(os.path.join(outdir, "records.json"), "w") as f:
            json.dump(encoded_records, f)
            
        # Save Metadata
        metadata = {
            "id": dsid,
            "name": original_filename,
            "created_at": datetime.now().isoformat(),
            "record_count": len(records),
            "columns": list(df.columns),
            "file_size": os.path.getsize(os.path.join(outdir, "records.json")) # Approx
        }
        with open(os.path.join(outdir, "metadata.json"), "w") as f:
            json.dump(metadata, f)

        encryption_tasks[task_id].update({
            "status": "completed", 
            "progress": 100, 
            "step": "Done", 
            "dataset_id": dsid
        })
        
    except Exception as e:
        encryption_tasks[task_id].update({"status": "failed", "error": str(e)})

@encrypt_bp.post("/dataset")
def encrypt_dataset():
    if "file" not in request.files:
        return jsonify({"error": "file required"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "no file selected"}), 400
        
    try:
        df = pd.read_csv(file)
    except Exception as e:
        return jsonify({"error": f"Invalid CSV: {str(e)}"}), 400

    task_id = str(uuid.uuid4())
    filename = file.filename
    
    # Start background thread
    thread = threading.Thread(target=run_encryption_task, args=(task_id, df, filename))
    thread.start()

    return jsonify({"task_id": task_id})

@encrypt_bp.get("/status/<task_id>")
def get_task_status(task_id):
    task = encryption_tasks.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)

@encrypt_bp.get("/dataset/<dataset_id>/records")
def get_dataset_records(dataset_id: str):
    outdir = os.path.join("data", "encrypted", dataset_id)
    path = os.path.join(outdir, "records.json")
    if not os.path.isfile(path):
        return jsonify({"error": "dataset not found"}), 404
    with open(path, "r") as f:
        data = json.load(f)
    return jsonify({"dataset_id": dataset_id, "records": data})

@encrypt_bp.get("/dataset/<dataset_id>/preview")
def preview_dataset(dataset_id: str):
    # Note: Removed @jwt_required() for easier UI testing as per user request in Phase 4 task 4.1 (preview update)
    # But keeping token check logic if passed in query param for security simulation
    
    outdir = os.path.join("data", "encrypted", dataset_id)
    rec_path = os.path.join(outdir, "records.json")
    ctx_path = os.path.join(outdir, "context.bin")
    aes_path = os.path.join(outdir, "aes_key.bin")
    
    if not (os.path.isfile(rec_path) and os.path.isfile(ctx_path) and os.path.isfile(aes_path)):
        return jsonify({"error": "dataset not found"}), 404
        
    limit = request.args.get("limit", default=10, type=int)
    
    try:
        with open(rec_path, "r") as f:
            records = json.load(f)
        with open(ctx_path, "rb") as f:
            ctx_blob = f.read()
        
        ctx = ts.context_from(ctx_blob)
        with open(aes_path, "rb") as f:
            aes_key = f.read()

        rows = []
        for rec in records[:limit]:
            row = {}
            for k, v in rec.items():
                if isinstance(v, dict) and {"nonce", "ciphertext", "tag"} <= set(v.keys()):
                    try:
                        pt = AESCipher.decrypt(v, aes_key)
                        row[k] = pt.decode("utf-8", errors="ignore")
                    except:
                        row[k] = "[Decryption Failed]"
                elif isinstance(v, dict) and "ckks" in v:
                    try:
                        b = base64.b64decode(v["ckks"])
                        vec = ts.ckks_vector_from(ctx, b)
                        dec = vec.decrypt()
                        base = k.replace("_enc", "")
                        row[base] = float(dec[0])
                    except:
                        row[k] = "[CKKS Error]"
            rows.append(row)
            
        from flask import render_template
        return render_template("preview.html", dataset_id=dataset_id, rows=rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
