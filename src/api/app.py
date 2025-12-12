import os
import sqlite3
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, get_jwt_identity
from src.api.middleware.audit_logger import audit_logger, log_audit
from src.api.middleware.rbac import require_role


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
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin'
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

    # Audit logging middleware - log all API requests
    @app.before_request
    def before_request_audit():
        """Log all API requests for GDPR/HIPAA compliance"""
        # Skip static files and health checks
        if request.path.startswith('/static') or request.path == '/health':
            return
        
        # Try to get user from JWT if present
        user_id = None
        try:
            user_id = get_jwt_identity()
        except:
            pass
        
        # Store request info in g for after_request logging
        from flask import g
        g.request_start_time = __import__('time').time()
        g.audit_user_id = user_id

    @app.after_request
    def after_request_audit(response):
        """Log request completion with response status"""
        # Skip static files and health checks
        if request.path.startswith('/static') or request.path == '/health':
            return response
        
        from flask import g
        duration = __import__('time').time() - getattr(g, 'request_start_time', 0)
        
        log_audit(
            operation=f"{request.method}_{request.endpoint or request.path}",
            user_id=getattr(g, 'audit_user_id', None),
            metadata={
                "path": request.path,
                "status_code": response.status_code,
                "duration_seconds": round(duration, 3)
            },
            success=response.status_code < 400
        )
        
        return response

    from src.api.routes.auth import auth_bp
    from src.api.routes.encrypt import encrypt_bp
    from src.api.routes.analytics import analytics_bp
    from src.api.routes.datasets import datasets_bp
    from src.api.routes.decrypt import decrypt_bp
    from src.api.routes.metrics import metrics_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(encrypt_bp, url_prefix="/encrypt")
    app.register_blueprint(analytics_bp, url_prefix="/analytics")
    app.register_blueprint(datasets_bp, url_prefix="/datasets")
    app.register_blueprint(decrypt_bp, url_prefix="/decrypt")
    app.register_blueprint(metrics_bp)

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
    
    @app.get("/metrics-dashboard")
    def metrics_dashboard():
        return render_template("metrics_dashboard.html")

    @app.get("/ui/benchmarks/data")
    def ui_benchmarks_data():
        """Load all benchmark CSV files and return structured JSON data."""
        import csv
        
        def load_csv_generic(path):
            """Load any CSV file as list of dicts."""
            if not os.path.isfile(path):
                return []
            with open(path, newline="") as f:
                return list(csv.DictReader(f))
        
        def load_baseline_optimized(path):
            """Load baseline/optimized CSV in old format."""
            out = {"encrypt": {}, "mean": {}}
            if not os.path.isfile(path):
                return out
            with open(path, newline="") as f:
                for r in csv.DictReader(f):
                    m = r.get("metric")
                    n = int(r.get("records", "0"))
                    s = float(r.get("seconds", "0"))
                    if m in out:
                        out[m][n] = s
            return out
        
        # Load baseline/optimized (existing format)
        baseline = load_baseline_optimized(os.path.join("benchmarks", "ckks_baseline_results.csv"))
        optimized = load_baseline_optimized(os.path.join("benchmarks", "ckks_optimized_results.csv"))
        
        # Load all other benchmark files
        accuracy = load_csv_generic(os.path.join("benchmarks", "accuracy_metrics.csv"))
        decryption_latency = load_csv_generic(os.path.join("benchmarks", "decryption_latency_results.csv"))
        end_to_end = load_csv_generic(os.path.join("benchmarks", "end_to_end_latency_results.csv"))
        final_kpis = load_csv_generic(os.path.join("benchmarks", "final_kpis.csv"))
        memory_usage = load_csv_generic(os.path.join("benchmarks", "memory_usage_results.csv"))
        memory_keygen = load_csv_generic(os.path.join("benchmarks", "memory_keygen_results.csv"))
        storage_overhead = load_csv_generic(os.path.join("benchmarks", "storage_overhead_results.csv"))
        
        return jsonify({
            "baseline": baseline,
            "optimized": optimized,
            "accuracy": accuracy,
            "decryption_latency": decryption_latency,
            "end_to_end": end_to_end[0] if end_to_end else {},
            "final_kpis": final_kpis,
            "memory_usage": memory_usage,
            "memory_keygen": memory_keygen[0] if memory_keygen else {},
            "storage_overhead": storage_overhead
        })
    
    @app.get("/admin/audit-logs")
    @require_role(["admin"])
    def admin_audit_logs():
        """API endpoint to retrieve audit logs (admin only)"""
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        user_id = request.args.get("user_id")
        operation = request.args.get("operation")
        limit = request.args.get("limit", default=1000, type=int)
        
        logs = audit_logger.get_logs(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            operation=operation,
            limit=limit
        )
        
        log_audit(
            operation="view_audit_logs",
            metadata={"filters": {"start_date": start_date, "end_date": end_date, "user_id": user_id, "operation": operation}}
        )
        
        return jsonify({"logs": logs, "count": len(logs)})
    
    @app.get("/admin/audit-logs-ui")
    @require_role(["admin"])
    def admin_audit_logs_ui():
        """UI page to view audit logs (admin only)"""
        return render_template("audit_logs.html")

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500

    return app


app = create_app()
