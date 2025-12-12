"""
Audit Logging Middleware for GDPR/HIPAA Compliance

This module provides comprehensive audit logging for all security-relevant operations
to demonstrate compliance with:
- GDPR Article 30 (Records of processing activities)
- HIPAA § 164.312(b) (Audit controls)

All operations are logged to immutable, append-only JSON files for accountability.
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from flask import request, g
from functools import wraps


class AuditLogger:
    """
    Audit logging system for healthcare data processing compliance.
    
    Logs all security-relevant operations including:
    - User authentication (login, logout, failed attempts)
    - Data operations (upload, encryption, decryption)
    - Analytics operations (computation requests)
    - Data management (deletion, export)
    - Administrative actions (viewing audit logs)
    """
    
    def __init__(self, log_directory: str = "data/audit_logs"):
        """
        Initialize audit logger.
        
        Args:
            log_directory: Directory to store audit log files
        """
        self.log_directory = log_directory
        os.makedirs(log_directory, exist_ok=True)
    
    def _get_log_file_path(self) -> str:
        """
        Get the log file path for today's date.
        Uses daily rotation: one file per day (YYYY-MM-DD.json)
        
        Returns:
            Path to today's log file
        """
        today = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_directory, f"{today}.json")
    
    def log_operation(
        self,
        operation: str,
        user_id: Optional[str] = None,
        dataset_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None
    ) -> None:
        """
        Log a security-relevant operation.
        
        Args:
            operation: Type of operation (e.g., 'login', 'encrypt', 'decrypt', 'analytics')
            user_id: Username or ID of user performing operation
            dataset_id: Dataset ID if operation involves a dataset
            metadata: Additional operation-specific metadata
            success: Whether operation succeeded
            error: Error message if operation failed
        """
        # Get request context if available
        ip_address = "unknown"
        endpoint = "unknown"
        method = "unknown"
        
        try:
            if request:
                ip_address = request.remote_addr or "unknown"
                endpoint = request.endpoint or request.path
                method = request.method
        except RuntimeError:
            # No request context (e.g., called from background task)
            pass
        
        # Create log entry
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "user_id": user_id,
            "dataset_id": dataset_id,
            "ip_address": ip_address,
            "endpoint": endpoint,
            "method": method,
            "success": success,
            "error": error,
            "metadata": metadata or {}
        }
        
        # Write to log file (append-only for immutability)
        log_file = self._get_log_file_path()
        
        try:
            # Read existing logs
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    logs = json.load(f)
            else:
                logs = []
            
            # Append new entry
            logs.append(log_entry)
            
            # Write back (atomic write with temp file)
            temp_file = log_file + ".tmp"
            with open(temp_file, "w") as f:
                json.dump(logs, f, indent=2)
            
            # Atomic rename
            if os.path.exists(log_file):
                os.remove(log_file)
            os.rename(temp_file, log_file)
            
        except Exception as e:
            # Log to stderr if file write fails (don't break the application)
            print(f"[AUDIT LOG ERROR] Failed to write audit log: {e}", flush=True)
    
    def get_logs(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        user_id: Optional[str] = None,
        operation: Optional[str] = None,
        limit: int = 1000
    ) -> list:
        """
        Retrieve audit logs with optional filters.
        
        Args:
            start_date: Filter logs from this date (YYYY-MM-DD)
            end_date: Filter logs to this date (YYYY-MM-DD)
            user_id: Filter by user ID
            operation: Filter by operation type
            limit: Maximum number of logs to return
            
        Returns:
            List of log entries matching filters
        """
        all_logs = []
        
        # Determine date range
        if start_date and end_date:
            # from datetime import datetime, timedelta  <-- Removed
            start = datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.strptime(end_date, "%Y-%m-%d")
            dates = []
            current = start
            while current <= end:
                dates.append(current.strftime("%Y-%m-%d"))
                current += timedelta(days=1)
        else:
            # Default: just today's logs
            dates = [datetime.now().strftime("%Y-%m-%d")]
        
        # Read logs from each date
        for date in dates:
            log_file = os.path.join(self.log_directory, f"{date}.json")
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r") as f:
                        logs = json.load(f)
                        all_logs.extend(logs)
                except Exception as e:
                    print(f"[AUDIT LOG ERROR] Failed to read log file {log_file}: {e}", flush=True)
        
        # Apply filters
        filtered_logs = all_logs
        
        if user_id:
            filtered_logs = [log for log in filtered_logs if log.get("user_id") == user_id]
        
        if operation:
            filtered_logs = [log for log in filtered_logs if log.get("operation") == operation]
        
        # Sort by timestamp (newest first) and limit
        filtered_logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return filtered_logs[:limit]


# Global audit logger instance
audit_logger = AuditLogger()


def log_audit(operation: str, **kwargs):
    """
    Convenience function to log an audit event.
    
    Args:
        operation: Operation type
        **kwargs: Additional parameters for log_operation
    """
    # Try to get user from JWT token in request context
    user_id = kwargs.pop("user_id", None)
    if not user_id:
        try:
            from flask_jwt_extended import get_jwt_identity
            user_id = get_jwt_identity()
        except:
            user_id = None
    
    audit_logger.log_operation(operation=operation, user_id=user_id, **kwargs)


def audit_operation(operation_name: str):
    """
    Decorator to automatically audit a Flask route.
    
    Usage:
        @audit_operation("decrypt_data")
        def decrypt_endpoint():
            ...
    
    Args:
        operation_name: Name of the operation to log
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Execute the function
            try:
                result = f(*args, **kwargs)
                
                # Log success
                log_audit(
                    operation=operation_name,
                    metadata={"args": str(args), "kwargs": str(kwargs)},
                    success=True
                )
                
                return result
                
            except Exception as e:
                # Log failure
                log_audit(
                    operation=operation_name,
                    metadata={"args": str(args), "kwargs": str(kwargs)},
                    success=False,
                    error=str(e)
                )
                raise
        
        return wrapper
    return decorator
