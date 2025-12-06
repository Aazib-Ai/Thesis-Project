import sqlite3
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from src.api.app import get_db_path


auth_bp = Blueprint("auth", __name__)


def get_conn():
    return sqlite3.connect(get_db_path())


@auth_bp.post("/register")
def register():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    pwh = generate_password_hash(password)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO users(username, password_hash) VALUES(?, ?)", (username, pwh))
        conn.commit()
        return jsonify({"message": "registered"}), 201
    except sqlite3.IntegrityError:
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
        cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row or not check_password_hash(row[0], password or ""):
            return jsonify({"error": "invalid credentials"}), 401
        token = create_access_token(identity=username)
        return jsonify({"access_token": token})
    finally:
        conn.close()

