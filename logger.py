"""
Logging module for the authentication system.
"""
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    filename='auth_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Create logger instance
logger = logging.getLogger(__name__)

def log_audit_event(event_type: str, username: str, details: str, success: bool):
    """Log security audit events."""
    status = "SUCCESS" if success else "FAILURE"
    logger.info(f"Event: {event_type} | User: {username} | Details: {details} | Status: {status}")

def log_error(error_type: str, message: str):
    """Log error events."""
    logger.error(f"Error Type: {error_type} | Message: {message}")

def log_login_attempt(username: str, success: bool, details: str = ""):
    """Log login attempts."""
    log_audit_event("LOGIN_ATTEMPT", username, details, success)

def log_password_change(username: str, success: bool, details: str = ""):
    """Log password change attempts."""
    log_audit_event("PASSWORD_CHANGE", username, details, success)

def log_session_event(username: str, event_type: str, details: str = ""):
    """Log session-related events."""
    log_audit_event(f"SESSION_{event_type}", username, details, True)

def log_security_event(username: str, event_type: str, details: str, success: bool):
    """Log security-related events."""
    log_audit_event(f"SECURITY_{event_type}", username, details, success)

def log_system_event(event_type: str, details: str):
    """Log system-related events."""
    logger.info(f"System Event: {event_type} | Details: {details}") 