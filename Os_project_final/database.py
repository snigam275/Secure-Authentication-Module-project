"""
Database management module for the authentication system.
"""
import sqlite3
import time
from typing import Optional, Dict, Any
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    filename='auth_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def init_db():
    """Initialize the database with required tables."""
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    
    # Enable foreign keys and WAL mode for better concurrency
    c.execute('PRAGMA foreign_keys = ON')
    c.execute('PRAGMA journal_mode = WAL')
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            otp_secret TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            failed_attempts INTEGER DEFAULT 0,
            lock_time INTEGER DEFAULT 0,
            last_password_change INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (unixepoch()),
            last_login INTEGER DEFAULT 0
        )
    ''')
    
    # Create audit logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER DEFAULT (unixepoch()),
            event_type TEXT NOT NULL,
            username TEXT NOT NULL,
            details TEXT,
            success BOOLEAN DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()

def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Get user information from database."""
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    try:
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'hashed_password': user[2],
                'salt': user[3],
                'otp_secret': user[4],
                'role': user[5],
                'failed_attempts': user[6],
                'lock_time': user[7],
                'last_password_change': user[8],
                'created_at': user[9],
                'last_login': user[10]
            }
        return None
    finally:
        conn.close()

def create_user(username: str, hashed_password: str, salt: str, otp_secret: str, role: str = "user") -> bool:
    """Create a new user in the database."""
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO users (
                username, hashed_password, salt, otp_secret, role, last_password_change
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, hashed_password, salt, otp_secret, role, int(time.time())))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_user(username: str, data: Dict[str, Any]) -> bool:
    """Update user information in database."""
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    try:
        # Check if user exists
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if not c.fetchone() and 'hashed_password' in data:
            # If user doesn't exist and we have password data, create new user
            return create_user(
                username=username,
                hashed_password=data['hashed_password'],
                salt=data['salt'],
                otp_secret=data['otp_secret'],
                role=data.get('role', 'user')
            )
        
        # Build update query dynamically
        update_fields = []
        values = []
        for key, value in data.items():
            update_fields.append(f"{key} = ?")
            values.append(value)
        
        values.append(username)
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE username = ?"
        
        c.execute(query, values)
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logging.error(f"Error updating user {username}: {str(e)}")
        return False
    finally:
        conn.close()

def create_audit_log(event_type: str, username: str, details: str, success: bool) -> bool:
    """Create an audit log entry."""
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO audit_logs (event_type, username, details, success)
            VALUES (?, ?, ?, ?)
        ''', (event_type, username, details, success))
        conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error creating audit log: {str(e)}")
        return False
    finally:
        conn.close()

def get_audit_logs(limit: int = 100) -> list:
    """Get recent audit logs."""
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    try:
        c.execute('''
            SELECT timestamp, event_type, username, details, success
            FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        return c.fetchall()
    finally:
        conn.close()

def get_all_users() -> list:
    """Get all users from database."""
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    try:
        c.execute('SELECT username, role, created_at, last_login FROM users')
        return c.fetchall()
    finally:
        conn.close()

def delete_user(username: str) -> bool:
    """Delete a user from database."""
    conn = sqlite3.connect('user_auth.db')
    c = conn.cursor()
    try:
        c.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        return c.rowcount > 0
    finally:
        conn.close()

def backup_database() -> bool:
    """Create a backup of the database."""
    try:
        backup_path = Path(f"user_auth_backup_{int(time.time())}.db")
        conn = sqlite3.connect('user_auth.db')
        backup = sqlite3.connect(backup_path)
        conn.backup(backup)
        backup.close()
        conn.close()
        return True
    except Exception as e:
        logging.error(f"Error backing up database: {str(e)}")
        return False 