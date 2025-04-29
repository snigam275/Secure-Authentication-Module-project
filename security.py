"""
Security management module for the authentication system.
"""
import bcrypt
import pyotp
import secrets
import re
import time
import qrcode
from io import BytesIO
import base64
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

    @staticmethod
    def generate_qr_code(username: str, secret: str) -> str:
        """Generate QR code for OTP setup."""
        try:
            # Create the OTP URI
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(username, issuer_name="Secure Auth System")
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            
            return f"data:image/png;base64,{img_str}"
        except Exception as e:
            logging.error(f"QR code generation error: {str(e)}")
            return ""

class RateLimiter:
    def __init__(self):
        self.failed_attempts: Dict[str, int] = {}  # Track number of failed attempts
        self.max_attempts = 4
        self.timeout_minutes = 1
        self.lockouts: Dict[str, datetime] = {}  # Track lockout times

    def check_rate_limit(self, username: str) -> Tuple[bool, str, Optional[datetime]]:
        """Check if user has exceeded rate limit."""
        current_time = datetime.now()
        
        # Check if user is in lockout
        if username in self.lockouts:
            lockout_time = self.lockouts[username]
            if current_time < lockout_time:
                return False, "Account temporarily locked", lockout_time
            else:
                # Lockout period is over, remove lockout and reset attempts
                del self.lockouts[username]
                if username in self.failed_attempts:
                    del self.failed_attempts[username]
        
        # Initialize failed attempts counter if not exists
        if username not in self.failed_attempts:
            self.failed_attempts[username] = 0
            
        return True, "Rate limit check passed", None

    def record_failed_attempt(self, username: str) -> Tuple[bool, str, Optional[datetime]]:
        """Record a failed login attempt and check if account should be locked."""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = 0
            
        self.failed_attempts[username] += 1
        
        if self.failed_attempts[username] >= self.max_attempts:
            # Lock the account
            lockout_time = datetime.now() + timedelta(minutes=self.timeout_minutes)
            self.lockouts[username] = lockout_time
            return False, "Too many failed attempts", lockout_time
            
        return True, f"{self.max_attempts - self.failed_attempts[username]} attempts remaining", None

    def reset_attempts(self, username: str) -> None:
        """Reset attempts for a user after successful login."""
        if username in self.failed_attempts:
            del self.failed_attempts[username]
        if username in self.lockouts:
            del self.lockouts[username]

# Global rate limiter instance
rate_limiter = RateLimiter()

def login_user(username: str, password: str, otp_code: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str], Optional[datetime]]:
    """Handle user login with rate limiting."""
    try:
        # Check if user is locked out first
        can_proceed, message, lockout_time = rate_limiter.check_rate_limit(username)
        if not can_proceed:
            create_audit_log("LOGIN_ATTEMPT", username, "Account locked", False)
            return False, None, message, lockout_time

        # Get user from database
        user = get_user(username)
        if not user:
            create_audit_log("LOGIN_ATTEMPT", username, "User not found", False)
            # Record failed attempt
            _, _, lockout_time = rate_limiter.record_failed_attempt(username)
            return False, None, "Invalid credentials", lockout_time

        # Verify password
        if not PasswordManager.verify_password(
            password,
            user['hashed_password'].encode('utf-8'),
            user['salt'].encode('utf-8')
        ):
            create_audit_log("LOGIN_ATTEMPT", username, "Invalid password", False)
            # Record failed attempt and check if should lock
            can_proceed, message, lockout_time = rate_limiter.record_failed_attempt(username)
            if not can_proceed:
                return False, None, "Account locked due to too many failed attempts", lockout_time
            return False, None, message, None

        # Password is correct, login successful
        rate_limiter.reset_attempts(username)  # Reset attempts after successful login
        update_user(username, {'last_login': int(time.time())})
        create_audit_log("LOGIN_SUCCESS", username, "Login successful", True)
        return True, user['role'], None, None

    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        create_audit_log("LOGIN_ERROR", username, str(e), False)
        return False, None, str(e), None

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
        
        # Generate OTP secret if not already in session
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
            # Log the OTP secret for debugging
            logging.info(f"User {username} registered with OTP secret: {otp_secret}")
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