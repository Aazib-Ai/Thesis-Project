import os
import json
import uuid
import base64
import threading
import time
import logging
from datetime import datetime
import pandas as pd
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from src.crypto.hybrid_encryption import KeyManager, HybridEncryptor
from src.crypto.ckks_module import CKKSContext
from src.crypto.aes_module import AESCipher
from src.crypto.columnar_encryption import ColumnarEncryptor
import tenseal as ts

logger = logging.getLogger(__name__)

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
        
        # Initialize CKKS context with optimized parameters
        ck = CKKSContext()
        ck.create_optimized_context()  # poly_degree=16384, 8192 SIMD slots
        km = KeyManager()
        aes_key = km.generate_aes_key()
        
        # Initialize columnar encryptor
        columnar_enc = ColumnarEncryptor(ck, simd_slot_count=8192)

        encryption_tasks[task_id].update({"progress": 20, "step": "Converting to Columnar Format"})
        
        # Convert DataFrame rows to list of dictionaries
        records = [row.to_dict() for _, row in df.iterrows()]
        total_rows = len(records)
        
        # Pivot records into columnar format (separates PII and vitals)
        pii_columns, vitals_columns = columnar_enc.pivot_to_columns(records)
        
        encryption_tasks[task_id].update({"progress": 40, "step": "Encrypting Vitals Columns (CKKS)"})
        
        # Encrypt vitals columns with CKKS
        encrypted_vitals, vitals_metadata = columnar_enc.encrypt_columns(vitals_columns)
        
        encryption_tasks[task_id].update({"progress": 60, "step": "Encrypting PII Records (AES)"})
        
        # Encrypt PII records row-wise with AES for fast preview
        pii_records = []
        for i in range(total_rows):
            pii_record = {}
            for field_name, values in pii_columns.items():
                if i < len(values):
                    value = values[i]
                    encrypted_value = AESCipher.encrypt(value.encode('utf-8'), aes_key)
                    pii_record[field_name] = encrypted_value
            pii_records.append(pii_record)

        encryption_tasks[task_id].update({"progress": 80, "step": "Serializing & Saving"})

        # Create output directory
        dsid = str(uuid.uuid4())
        outdir = os.path.join("data", "encrypted", dsid)
        ensure_dir(outdir)

        # Save CKKS context
        context_blob = ck.serialize_context(save_secret_key=True)
        with open(os.path.join(outdir, "context.bin"), "wb") as f:
            f.write(context_blob)

        # Save AES key
        with open(os.path.join(outdir, "aes_key.bin"), "wb") as f:
            f.write(aes_key)
        
        # Save encrypted vitals columns
        columnar_enc.save_encrypted_columns(encrypted_vitals, outdir)
        
        # Save PII records as JSON
        with open(os.path.join(outdir, "pii_records.json"), "w") as f:
            json.dump(pii_records, f)
            
        # Save Metadata
        metadata = {
            "id": dsid,
            "name": original_filename,
            "created_at": datetime.now().isoformat(),
            "record_count": total_rows,
            "actual_count": total_rows,
            "columns": list(df.columns),
            "vitals_columns": vitals_metadata['column_names'],
            "pii_columns": list(pii_columns.keys()),
            "simd_slot_count": vitals_metadata['simd_slot_count'],
            "encryption_mode": "columnar_simd",
            "file_size": 0  # Will be calculated below
        }
        
        # Calculate total storage size
        columns_dir = os.path.join(outdir, "columns")
        total_size = 0
        if os.path.exists(columns_dir):
            for filename in os.listdir(columns_dir):
                filepath = os.path.join(columns_dir, filename)
                if os.path.isfile(filepath):
                    total_size += os.path.getsize(filepath)
        
        pii_path = os.path.join(outdir, "pii_records.json")
        if os.path.exists(pii_path):
            total_size += os.path.getsize(pii_path)
        
        metadata["file_size"] = total_size
        
        with open(os.path.join(outdir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

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
    # Preview endpoint now works with columnar storage structure
    # Reads PII from pii_records.json and vitals from columns/ directory
    
    outdir = os.path.join("data", "encrypted", dataset_id)
    metadata_path = os.path.join(outdir, "metadata.json")
    ctx_path = os.path.join(outdir, "context.bin")
    aes_path = os.path.join(outdir, "aes_key.bin")
    pii_path = os.path.join(outdir, "pii_records.json")
    columns_dir = os.path.join(outdir, "columns")
    
    # Check if this is a columnar dataset
    is_columnar = os.path.exists(columns_dir) and os.path.exists(pii_path)
    
    # Legacy path for backward compatibility
    legacy_rec_path = os.path.join(outdir, "records.json")
    
    if not os.path.isfile(ctx_path) or not os.path.isfile(aes_path):
        return jsonify({"error": "dataset not found"}), 404
    
    if not is_columnar and not os.path.isfile(legacy_rec_path):
        return jsonify({"error": "dataset not found"}), 404
        
    limit = request.args.get("limit", default=10, type=int)
    
    try:
        # Load context and AES key
        with open(ctx_path, "rb") as f:
            ctx_blob = f.read()
        ctx = ts.context_from(ctx_blob)
        
        with open(aes_path, "rb") as f:
            aes_key = f.read()
        
        # Load metadata
        metadata = {}
        if os.path.exists(metadata_path):
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
        
        rows = []
        
        if is_columnar:
            # NEW: Columnar storage format
            # Load PII records
            with open(pii_path, "r") as f:
                pii_records = json.load(f)
            
            # Load and decrypt vitals columns
            vitals_data = {}
            if os.path.exists(columns_dir):
                from src.crypto.columnar_encryption import ColumnarEncryptor
                ck = CKKSContext()  # Dummy context for loading
                columnar_enc = ColumnarEncryptor(ck)
                
                vitals_columns = metadata.get('vitals_columns', [])
                for field_name in vitals_columns:
                    try:
                        enc_col = columnar_enc.load_encrypted_column(field_name, columns_dir, ctx)
                        
                        # Decrypt the column
                        if enc_col['chunk_count'] == 1:
                            decrypted_values = enc_col['ciphertext'].decrypt()
                        else:
                            # Multi-chunk column - concatenate decrypted chunks
                            decrypted_values = []
                            for chunk in enc_col['ciphertexts']:
                                decrypted_values.extend(chunk.decrypt())
                        
                        vitals_data[field_name] = decrypted_values
                    except Exception as e:
                        logger.warning(f"Failed to load column '{field_name}': {e}")
            
            # Combine PII and vitals for each record
            actual_count = metadata.get('actual_count', len(pii_records))
            for i in range(min(limit, actual_count)):
                row = {}
                
                # Decrypt PII for this record
                if i < len(pii_records):
                    pii_record = pii_records[i]
                    for k, v in pii_record.items():
                        if isinstance(v, dict) and {"nonce", "ciphertext", "tag"} <= set(v.keys()):
                            try:
                                pt = AESCipher.decrypt(v, aes_key)
                                row[k] = pt.decode("utf-8", errors="ignore")
                            except:
                                row[k] = "[Decryption Failed]"
                
                # Add vitals for this record (extract by index from decrypted columns)
                for field_name, values in vitals_data.items():
                    if i < len(values):
                        row[field_name] = float(values[i])
                
                rows.append(row)
        else:
            # LEGACY: Row-wise storage format (backward compatibility)
            with open(legacy_rec_path, "r") as f:
                records = json.load(f)
            
            for rec in records[:limit]:
                row = {}
                
                # Handle SIMD-batched vitals (old format)
                if '_vitals_encrypted' in rec and '_vitals_field_order' in rec:
                    try:
                        field_order = rec['_vitals_field_order']
                        vitals_data = rec['_vitals_encrypted']
                        if isinstance(vitals_data, dict) and 'ckks' in vitals_data:
                            b = base64.b64decode(vitals_data['ckks'])
                            vec = ts.ckks_vector_from(ctx, b)
                            dec = vec.decrypt()
                            for i, field_name in enumerate(field_order):
                                if i < len(dec):
                                    row[field_name] = float(dec[i])
                    except Exception:
                        row['vitals'] = "[CKKS SIMD Error]"
                
                # Handle other fields
                for k, v in rec.items():
                    if k in ('_vitals_encrypted', '_vitals_field_order', '_classification_metadata'):
                        continue  # Skip metadata
                    if isinstance(v, dict) and {"nonce", "ciphertext", "tag"} <= set(v.keys()):
                        try:
                            pt = AESCipher.decrypt(v, aes_key)
                            row[k] = pt.decode("utf-8", errors="ignore")
                        except:
                            row[k] = "[Decryption Failed]"
                    elif isinstance(v, dict) and "ckks" in v:
                        # Legacy format: individual CKKS encrypted field
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
        import traceback
        logger.error(f"Preview error: {e}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
