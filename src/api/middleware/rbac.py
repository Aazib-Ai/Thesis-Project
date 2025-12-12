"""
Role-Based Access Control (RBAC) Middleware

Implements role-based access control for demonstrating compliance with:
- GDPR Article 32(1)(b) (Access control)
- HIPAA § 164.312(a)(1) (Access control standard)
- HIPAA § 164.308(a)(4) (Information access management)

Defines three roles with different permission levels:
- admin: Full access to all operations
- analyst: Can view analytics and decrypt results, cannot upload or delete
- viewer: Can only view encrypted analytics results
"""

from functools import wraps
from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt


# Role definitions with permissions
ROLES = {
    "admin": [
        "upload",
        "encrypt",
        "decrypt",
        "analytics",
        "delete",
        "view_audit_logs",
        "manage_users"
    ],
    "analyst": [
        "analytics",
        "decrypt"
    ],
    "viewer": [
        "analytics"
    ]
}


def get_user_role() -> str:
    """
    Get the role of the currently authenticated user from JWT token.
    
    Returns:
        Role name (admin, analyst, viewer) or None if not authenticated
    """
    try:
        verify_jwt_in_request()
        claims = get_jwt()
        return claims.get("role", "viewer")  # Default to viewer if role not in token
    except:
        return None


def has_permission(permission: str) -> bool:
    """
    Check if current user has a specific permission.
    
    Args:
        permission: Permission to check (e.g., 'decrypt', 'upload')
        
    Returns:
        True if user has permission, False otherwise
    """
    role = get_user_role()
    if not role:
        return False
    
    return permission in ROLES.get(role, [])


def require_role(required_roles: list):
    """
    Decorator to enforce role-based access control on Flask routes.
    
    Usage:
        @require_role(["admin"])
        def delete_dataset():
            ...
        
        @require_role(["admin", "analyst"])
        def decrypt_data():
            ...
    
    Args:
        required_roles: List of roles that can access this route
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Verify JWT token
            try:
                verify_jwt_in_request()
            except Exception as e:
                return jsonify({"error": "Authentication required", "message": str(e)}), 401
            
            # Get user role
            role = get_user_role()
            
            # Check if user's role is in the list of required roles
            if role not in required_roles:
                from src.api.middleware.audit_logger import log_audit
                log_audit(
                    operation="access_denied",
                    metadata={
                        "endpoint": f.__name__,
                        "user_role": role,
                        "required_roles": required_roles
                    },
                    success=False,
                    error=f"Insufficient permissions. Required: {required_roles}, User has: {role}"
                )
                
                return jsonify({
                    "error": "Access denied",
                    "message": f"This operation requires one of the following roles: {', '.join(required_roles)}",
                    "your_role": role
                }), 403
            
            # User has required role, proceed
            return f(*args, **kwargs)
        
        return wrapper
    return decorator


def require_permission(permission: str):
    """
    Decorator to enforce permission-based access control on Flask routes.
    
    Usage:
        @require_permission("decrypt")
        def decrypt_data():
            ...
    
    Args:
        permission: Permission required to access this route
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Verify JWT token
            try:
                verify_jwt_in_request()
            except Exception as e:
                return jsonify({"error": "Authentication required", "message": str(e)}), 401
            
            # Check permission
            if not has_permission(permission):
                role = get_user_role()
                from src.api.middleware.audit_logger import log_audit
                log_audit(
                    operation="access_denied",
                    metadata={
                        "endpoint": f.__name__,
                        "user_role": role,
                        "required_permission": permission
                    },
                    success=False,
                    error=f"Insufficient permissions. Required: {permission}"
                )
                
                return jsonify({
                    "error": "Access denied",
                    "message": f"This operation requires '{permission}' permission",
                    "your_role": role
                }), 403
            
            # User has permission, proceed
            return f(*args, **kwargs)
        
        return wrapper
    return decorator
