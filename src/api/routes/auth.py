import sqlite3
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from src.api.app import get_db_path
from src.api.middleware.audit_logger import log_audit


auth_bp = Blueprint("auth", __name__)


def get_conn():
    return sqlite3.connect(get_db_path())


@auth_bp.post("/register")
def register():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "viewer")  # Default role is viewer for new users
    
    # Validate role
    valid_roles = ["admin", "analyst", "viewer"]
    if role not in valid_roles:
        log_audit(
            operation="register",
            user_id=username,
            metadata={"invalid_role": role},
            success=False,
            error=f"Invalid role. Must be one of: {valid_roles}"
        )
        return jsonify({"error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"}), 400
    
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    
    pwh = generate_password_hash(password)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO users(username, password_hash, role) VALUES(?, ?, ?)", (username, pwh, role))
        conn.commit()
        
        log_audit(
            operation="register",
            user_id=username,
            metadata={"role": role},
            success=True
        )
        
        return jsonify({"message": "registered", "role": role}), 201
    except sqlite3.IntegrityError:
        log_audit(
            operation="register",
            user_id=username,
            metadata={"role": role},
            success=False,
            error="username exists"
        )
        return jsonify({"error": "username exists"}), 409
    finally:
        conn.close()


@auth_bp.post("/login")
def login():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row or not check_password_hash(row[0], password or ""):
            log_audit(
                operation="login",
                user_id=username,
                metadata={"reason": "invalid credentials"},
                success=False,
                error="invalid credentials"
            )
            return jsonify({"error": "invalid credentials"}), 401
        
        # Get role (default to 'admin' for backward compatibility with existing users)
        role = row[1] if len(row) > 1 and row[1] else "admin"
        
        # Create JWT token with role in claims
        token = create_access_token(identity=username, additional_claims={"role": role})
        
        log_audit(
            operation="login",
            user_id=username,
            metadata={"role": role},
            success=True
        )
        
        return jsonify({"access_token": token, "role": role})
    finally:
        conn.close()

