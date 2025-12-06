import os
import sqlite3
from flask import Flask, jsonify, render_template
from flask_cors import CORS
from flask_jwt_extended import JWTManager


def get_db_path():
    os.makedirs(os.path.join("data", "api"), exist_ok=True)
    return os.path.join("data", "api", "app.db")


def init_db():
    conn = sqlite3.connect(get_db_path())
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def create_app():
    tpl_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "templates"))
    static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "static"))
    app = Flask(__name__, template_folder=tpl_dir, static_folder=static_dir)
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-secret")
    app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
    app.config["JWT_QUERY_STRING_NAME"] = "token"
    CORS(app)
    JWTManager(app)

    init_db()

    from src.api.routes.auth import auth_bp
    from src.api.routes.encrypt import encrypt_bp
    from src.api.routes.analytics import analytics_bp
    from src.api.routes.datasets import datasets_bp
    from src.api.routes.decrypt import decrypt_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(encrypt_bp, url_prefix="/encrypt")
    app.register_blueprint(analytics_bp, url_prefix="/analytics")
    app.register_blueprint(datasets_bp, url_prefix="/datasets")
    app.register_blueprint(decrypt_bp, url_prefix="/decrypt")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.get("/register")
    def register():
        return render_template("register.html")
        
    @app.get("/how-it-works")
    def how_it_works():
        return render_template("how_it_works.html")

    @app.get("/health-dashboard")
    def health_dashboard():
        return render_template("health_dashboard.html")

    @app.get("/reports")
    def reports():
        return render_template("reports.html")

    @app.get("/profile")
    def profile():
        return render_template("profile.html")

    @app.get("/upload")
    def upload():
        return render_template("upload.html")

    @app.get("/ui/analytics")
    def ui_analytics():
        return render_template("analytics.html")

    @app.get("/ui/datasets")
    def ui_datasets():
        return render_template("datasets.html")

    @app.get("/results")
    def results():
        return render_template("results.html")

    @app.get("/comparison")
    def comparison():
        return render_template("comparison.html")

    @app.get("/ui/benchmarks/data")
    def ui_benchmarks_data():
        def load_csv(path):
            out = {"encrypt": {}, "mean": {}}
            if not os.path.isfile(path):
                return out
            import csv
            with open(path, newline="") as f:
                for r in csv.DictReader(f):
                    m = r.get("metric")
                    n = int(r.get("records", "0"))
                    s = float(r.get("seconds", "0"))
                    if m in out:
                        out[m][n] = s
            return out
        baseline = load_csv(os.path.join("benchmarks", "ckks_baseline_results.csv"))
        optimized = load_csv(os.path.join("benchmarks", "ckks_optimized_results.csv"))
        return jsonify({"baseline": baseline, "optimized": optimized})

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500

    return app


app = create_app()
