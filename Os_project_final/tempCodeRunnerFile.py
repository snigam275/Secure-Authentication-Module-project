"""
Main application module for the secure authentication system.
"""
import os
import sys
import time
from typing import Optional, Tuple
from database import init_db, get_user, update_user, create_audit_log
from security import (
    PasswordPolicy,
    PasswordManager,
    SessionManager,
    MFAManager,
    RateLimiter
)
from logger import logger
from config import SECURITY, FILE_OPERATIONS
import redis
import psutil
from plyer import notification
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# Initialize Redis client
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=int(os.getenv("REDIS_DB", 0))
)

# Initialize rate limiter
rate_limiter = RateLimiter(redis_client)

def send_email_notification(to_email: str, subject: str, body: str) -> bool:
    """Send email notification."""
    try:
        message = MIMEMultipart()
        message['From'] = os.getenv("EMAIL_FROM")
        message['To'] = to_email
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(os.getenv("SMTP_SERVER", "smtp.gmail.com"), 
                         int(os.getenv("SMTP_PORT", 587))) as server:
            server.starttls()
            server.login(os.getenv("EMAIL_FROM"), os.getenv("EMAIL_PASSWORD"))
            server.send_message(message)
        
        logger.log_system_event("EMAIL_SENT", f"Email sent to {to_email}", True)
        return True
    except Exception as e:
        logger.log_error("EMAIL_ERROR", str(e))
        return False

def register_user(username: str, password: str, email: str, role: str = "user") -> bool:
    """Register a new user."""
    # Validate password
    is_valid, message = PasswordPolicy.validate_password(password)
    if not is_valid:
        print(f"Registration failed: {message}")
        return False
    
    # Check if username exists
    if get_user(username):
        print("Username already exists!")
        return False
    
    # Hash password
    hashed_password, salt = PasswordManager.hash_password(password)
    
    # Generate OTP secret
    otp_secret = MFAManager.generate_otp_secret()
    
    # Create user
    try:
        update_user(username, {
            'hashed_password': hashed_password.decode('utf-8'),
            'salt': salt.decode('utf-8'),
            'otp_secret': otp_secret,
            'role': role,
            'email': email,
            'last_password_change': int(time.time())
        })
        
        logger.log_audit("USER_REGISTER", username, "User registered", True)
        print("User registered successfully!")
        return True
    except Exception as e:
        logger.log_error("REGISTRATION_ERROR", str(e), username)
        print("Registration failed!")
        return False

def login_user(username: str, password: str) -> Tuple[bool, Optional[str]]:
    """Login user with 2FA."""
    # Check rate limiting
    can_proceed, message = rate_limiter.check_rate_limit(username)
    if not can_proceed:
        print(message)
        return False, None
    
    # Get user
    user = get_user(username)
    if not user:
        logger.log_login_attempt(username, False)
        print("Invalid credentials!")
        return False, None
    
    # Check if account is locked
    if user['failed_attempts'] >= 3:
        lock_time = user['lock_time']
        if time.time() - lock_time < SECURITY["ACCOUNT_LOCK_DURATION"]:
            print("Account is temporarily locked. Please try again later.")
            return False, None
    
    # Verify password
    if not PasswordManager.verify_password(password, 
                                         user['hashed_password'].encode('utf-8'),
                                         user['salt'].encode('utf-8')):
        # Increment failed attempts
        update_user(username, {'failed_attempts': user['failed_attempts'] + 1})
        if user['failed_attempts'] + 1 >= 3:
            update_user(username, {'lock_time': int(time.time())})
        
        logger.log_login_attempt(username, False)
        print("Invalid credentials!")
        return False, None
    
    # Check password expiry
    needs_change, message = PasswordManager.check_password_expiry(username)
    if needs_change:
        print("Your password has expired. Please change it.")
        return False, "EXPIRED_PASSWORD"
    
    # Generate and send OTP
    otp = MFAManager.generate_otp(user['otp_secret'])
    notification.notify(
        title="Your OTP Code",
        message=f"Your OTP code is: {otp}",
        timeout=5
    )
    print("OTP sent as a notification. Please check your desktop.")
    
    # Verify OTP
    entered_otp = input("Enter OTP from notification: ")
    if not MFAManager.verify_otp(user['otp_secret'], entered_otp):
        logger.log_login_attempt(username, False)
        print("Invalid OTP!")
        return False, None
    
    # Reset failed attempts and update last login
    update_user(username, {
        'failed_attempts': 0,
        'lock_time': 0,
        'last_login': int(time.time())
    })
    
    # Create session
    session_id = SessionManager.create_session(username)
    if not session_id:
        print("Session creation failed!")
        return False, None
    
    logger.log_login_attempt(username, True)
    print("Login successful!")
    return True, user['role']

def change_password(username: str, current_password: str, new_password: str) -> bool:
    """Change user password."""
    # Validate new password
    is_valid, message = PasswordPolicy.validate_password(new_password)
    if not is_valid:
        print(f"Password change failed: {message}")
        return False
    
    # Get user
    user = get_user(username)
    if not user:
        print("User not found!")
        return False
    
    # Verify current password
    if not PasswordManager.verify_password(current_password,
                                         user['hashed_password'].encode('utf-8'),
                                         user['salt'].encode('utf-8')):
        print("Current password is incorrect!")
        return False
    
    # Hash new password
    hashed_password, salt = PasswordManager.hash_password(new_password)
    
    # Update password
    try:
        update_user(username, {
            'hashed_password': hashed_password.decode('utf-8'),
            'salt': salt.decode('utf-8'),
            'last_password_change': int(time.time())
        })
        
        logger.log_password_change(username, True)
        print("Password changed successfully!")
        return True
    except Exception as e:
        logger.log_error("PASSWORD_CHANGE_ERROR", str(e), username)
        print("Password change failed!")
        return False

def main():
    """Main application loop."""
    # Initialize database
    init_db()
    
    while True:
        print("\nWelcome to the Secure Authentication System!")
        print("1. Register")
        print("2. Login")
        print("3. Change Password")
        print("4. Exit")
        
        choice = input("Select an option: ")
        
        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            email = input("Enter email: ")
            register_user(username, password, email)
        
        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            success, role = login_user(username, password)
            if success:
                print(f"Welcome {username} ({role})!")
                # Add user dashboard functionality here
        
        elif choice == "3":
            username = input("Enter username: ")
            current_password = input("Enter current password: ")
            new_password = input("Enter new password: ")
            change_password(username, current_password, new_password)
        
        elif choice == "4":
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main() 