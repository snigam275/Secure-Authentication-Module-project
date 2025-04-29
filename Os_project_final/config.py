"""
Configuration settings for the authentication system.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Database settings
DATABASE_PATH = BASE_DIR / "data" / "user_auth.db"
DATABASE_TIMEOUT = 30

# Security settings
SECURITY = {
    "MAX_LOGIN_ATTEMPTS": 5,
    "LOGIN_TIMEOUT_MINUTES": 15,
    "SESSION_TIMEOUT_MINUTES": 30,
    "ACCOUNT_LOCK_DURATION": 300,  # 5 minutes
    "PASSWORD_MIN_LENGTH": 12,
    "PASSWORD_EXPIRY_DAYS": 90,
    "BCRYPT_ROUNDS": 12,
}

# File operation settings
FILE_OPERATIONS = {
    "ALLOWED_EXTENSIONS": {'.txt', '.log', '.db'},
    "MAX_FILE_SIZE": 10 * 1024 * 1024,  # 10MB
    "UPLOAD_DIR": BASE_DIR / "uploads",
}

# Email settings
EMAIL = {
    "SMTP_SERVER": "smtp.gmail.com",
    "SMTP_PORT": 587,
    "USE_TLS": True,
    "FROM_EMAIL": os.getenv("EMAIL_FROM", ""),
    "EMAIL_PASSWORD": os.getenv("EMAIL_PASSWORD", ""),
}

# Redis settings
REDIS = {
    "HOST": os.getenv("REDIS_HOST", "localhost"),
    "PORT": int(os.getenv("REDIS_PORT", 6379)),
    "DB": int(os.getenv("REDIS_DB", 0)),
}

# Logging settings
LOGGING = {
    "AUDIT_LOG_FILE": BASE_DIR / "logs" / "audit.log",
    "ERROR_LOG_FILE": BASE_DIR / "logs" / "error.log",
    "MAX_LOG_SIZE": 10 * 1024 * 1024,  # 10MB
    "BACKUP_COUNT": 5,
    "LOG_FORMAT": "%(asctime)s - %(levelname)s - %(message)s",
}

# Create necessary directories
def create_directories():
    """Create necessary directories if they don't exist."""
    directories = [
        BASE_DIR / "data",
        BASE_DIR / "logs",
        FILE_OPERATIONS["UPLOAD_DIR"],
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

# Initialize directories
create_directories() 