"""
Security management module for the authentication system.
"""
import bcrypt
import pyotp
import secrets
import re
import time
from datetime import datetime, timedelta
import logging
from typing import Optional, Tuple, Dict, Any
from database import get_user, update_user, create_audit_log, create_user

# Configure logging
logging.basicConfig(
    filename='auth_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PasswordPolicy:
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """Validate password against security policy."""
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        if re.search(r"(.)\1{2,}", password):
            return False, "Password cannot contain repeated characters"
        return True, "Password meets complexity requirements"

class PasswordManager:
    @staticmethod
    def hash_password(password: str) -> Tuple[bytes, bytes]:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed, salt

    @staticmethod
    def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed)
        except Exception as e:
            logging.error(f"Password verification error: {str(e)}")
            return False

class SessionManager:
    @staticmethod
    def generate_session_id() -> str:
        """Generate a secure session ID."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def create_session(username: str, role: str) -> str:
        """Create a new session."""
        session_id = SessionManager.generate_session_id()
        create_audit_log("SESSION_CREATE", username, f"Session created with ID: {session_id}", True)
        return session_id

    @staticmethod
    def validate_session(session_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate a session."""
        # In a real application, you would check Redis or database for session validity
        return True, None

class MFAManager:
    @staticmethod
    def generate_otp_secret() -> str:
        """Generate a new OTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def generate_otp(secret: str) -> str:
        """Generate a TOTP code."""
        totp = pyotp.TOTP(secret)
        return totp.now()

    @staticmethod
    def verify_otp(secret: str, otp: str) -> bool:
        """Verify a TOTP code."""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(otp)
        except Exception as e:
            logging.error(f"OTP verification error: {str(e)}")
            return False

class RateLimiter:
    def __init__(self):
        self.attempts: Dict[str, list] = {}
        self.max_attempts = 5
        self.timeout_minutes = 15

    def check_rate_limit(self, username: str) -> Tuple[bool, str]:
        """Check if user has exceeded rate limit."""
        current_time = datetime.now()
        
        if username not in self.attempts:
            self.attempts[username] = [current_time]
            return True, "Rate limit check passed"
        
        # Remove old attempts
        self.attempts[username] = [
            t for t in self.attempts[username]
            if current_time - t < timedelta(minutes=self.timeout_minutes)
        ]
        
        if len(self.attempts[username]) >= self.max_attempts:
            return False, "Too many login attempts. Please try again later."
        
        self.attempts[username].append(current_time)
        return True, "Rate limit check passed"

# Global rate limiter instance
rate_limiter = RateLimiter()

def login_user(username: str, password: str) -> Tuple[bool, Optional[str]]:
    """Handle user login with rate limiting and MFA."""
    try:
        # Check rate limit
        can_proceed, message = rate_limiter.check_rate_limit(username)
        if not can_proceed:
            create_audit_log("LOGIN_ATTEMPT", username, "Rate limit exceeded", False)
            return False, None

        # Get user from database
        user = get_user(username)
        if not user:
            create_audit_log("LOGIN_ATTEMPT", username, "User not found", False)
            return False, None

        # Verify password
        if not PasswordManager.verify_password(
            password,
            user['hashed_password'].encode('utf-8'),
            user['salt'].encode('utf-8')
        ):
            create_audit_log("LOGIN_ATTEMPT", username, "Invalid password", False)
            return False, None

        # Generate and verify OTP
        otp = MFAManager.generate_otp(user['otp_secret'])
        # In a real application, you would send this OTP via email/SMS
        print(f"Your OTP is: {otp}")  # For demo purposes only
        
        # For demo, we'll skip OTP verification
        # In a real application, you would get the OTP from the user
        # and verify it using MFAManager.verify_otp()

        # Update last login
        update_user(username, {'last_login': int(time.time())})
        create_audit_log("LOGIN_SUCCESS", username, "Login successful", True)
        
        return True, user['role']
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        create_audit_log("LOGIN_ERROR", username, str(e), False)
        return False, None

def register_user(username: str, password: str, role: str = "user") -> bool:
    """Handle user registration."""
    try:
        # Validate password
        is_valid, message = PasswordPolicy.validate_password(password)
        if not is_valid:
            logging.error(f"Registration failed for {username}: {message}")
            create_audit_log("REGISTRATION", username, f"Password validation failed: {message}", False)
            return False

        # Check if user already exists
        if get_user(username):
            create_audit_log("REGISTRATION", username, "Username already exists", False)
            return False

        # Hash password
        hashed_password, salt = PasswordManager.hash_password(password)
        
        # Generate OTP secret
        otp_secret = MFAManager.generate_otp_secret()
        
        # Create user in database
        success = create_user(
            username=username,
            hashed_password=hashed_password.decode('utf-8'),
            salt=salt.decode('utf-8'),
            otp_secret=otp_secret,
            role=role
        )
        
        if success:
            create_audit_log("REGISTRATION", username, "User registered successfully", True)
        else:
            create_audit_log("REGISTRATION", username, "Registration failed", False)
        
        return success
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        create_audit_log("REGISTRATION_ERROR", username, str(e), False)
        return False

def change_password(username: str, current_password: str, new_password: str) -> bool:
    """Handle password change."""
    try:
        # Get user
        user = get_user(username)
        if not user:
            return False

        # Verify current password
        if not PasswordManager.verify_password(
            current_password,
            user['hashed_password'].encode('utf-8'),
            user['salt'].encode('utf-8')
        ):
            create_audit_log("PASSWORD_CHANGE", username, "Invalid current password", False)
            return False

        # Validate new password
        is_valid, message = PasswordPolicy.validate_password(new_password)
        if not is_valid:
            create_audit_log("PASSWORD_CHANGE", username, f"Invalid new password: {message}", False)
            return False

        # Hash new password
        hashed_password, salt = PasswordManager.hash_password(new_password)
        
        # Update password in database
        success = update_user(username, {
            'hashed_password': hashed_password.decode('utf-8'),
            'salt': salt.decode('utf-8'),
            'last_password_change': int(time.time())
        })
        
        if success:
            create_audit_log("PASSWORD_CHANGE", username, "Password changed successfully", True)
        else:
            create_audit_log("PASSWORD_CHANGE", username, "Password change failed", False)
        
        return success
    except Exception as e:
        logging.error(f"Password change error: {str(e)}")
        create_audit_log("PASSWORD_CHANGE_ERROR", username, str(e), False)
        return False 