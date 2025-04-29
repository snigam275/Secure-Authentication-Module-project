"""
Streamlit UI for the Authentication System
"""
import streamlit as st
import sys
import os
from pathlib import Path
import time
from database import init_db, get_user, update_user, create_audit_log, get_all_users, get_audit_logs, create_user
from security import (
    PasswordPolicy,
    PasswordManager,
    SessionManager,
    MFAManager,
    RateLimiter,
    login_user,
    register_user,
    change_password
)
from logger import logger
import psutil
from datetime import datetime, timedelta

# Initialize database
init_db()

# Create default admin user if not exists
def create_default_admin():
    admin_username = "admin"
    admin_password = "Admin@123"  # Simple password for testing
    
    # Check if admin exists
    user = get_user(admin_username)
    if not user:
        # Create admin user
        hashed, salt = PasswordManager.hash_password(admin_password)
        otp_secret = MFAManager.generate_otp_secret()
        success = create_user(
            username=admin_username,
            hashed_password=hashed.decode('utf-8'),
            salt=salt.decode('utf-8'),
            otp_secret=otp_secret,
            role="admin"
        )
        if success:
            st.info(f"""
            Default admin credentials created:
            Username: {admin_username}
            Password: {admin_password}
            """)

# Create default admin user
create_default_admin()

# Set page config
st.set_page_config(
    page_title="Secure Authentication System",
    page_icon="🔒",
    layout="wide"
)

# Initialize session state for tabs
if 'open_tabs' not in st.session_state:
    st.session_state['open_tabs'] = set()

# Initialize session state for restricted users
if 'restricted_users' not in st.session_state:
    st.session_state['restricted_users'] = set()

# Custom CSS for better presentation
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
        margin-top: 1rem;
    }
    .success-message {
        color: green;
        padding: 1rem;
        border: 1px solid green;
        border-radius: 4px;
        margin: 1rem 0;
    }
    .error-message {
        color: red;
        padding: 1rem;
        border: 1px solid red;
        border-radius: 4px;
        margin: 1rem 0;
    }
    .info-message {
        color: blue;
        padding: 1rem;
        border: 1px solid blue;
        border-radius: 4px;
        margin: 1rem 0;
    }
    /* Custom button styles */
    .stButton>button.change-password-btn {
        background-color: #4CAF50;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .stButton>button.change-password-btn:hover {
        background-color: #45a049;
    }
    .stButton>button.logout-btn {
        background-color: #f44336;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .stButton>button.logout-btn:hover {
        background-color: #da190b;
    }
    .stButton>button.system-status-btn {
        background-color: #2196F3;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .stButton>button.system-status-btn:hover {
        background-color: #0b7dda;
    }
    .stButton>button.admin-btn {
        background-color: #9c27b0;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .stButton>button.admin-btn:hover {
        background-color: #7B1FA2;
    }
    </style>
""", unsafe_allow_html=True)

def toggle_tab(tab_name):
    if tab_name in st.session_state['open_tabs']:
        st.session_state['open_tabs'].remove(tab_name)
    else:
        st.session_state['open_tabs'].add(tab_name)

def restrict_user(username):
    st.session_state['restricted_users'].add(username)
    create_audit_log(
        st.session_state['username'],
        f"Restricted user: {username}",
        "User restriction",
        True
    )

def unrestrict_user(username):
    if username in st.session_state['restricted_users']:
        st.session_state['restricted_users'].remove(username)
        create_audit_log(
            st.session_state['username'],
            f"Unrestricted user: {username}",
            "User unrestriction",
            True
        )

def show_login_page():
    st.title("🔒 Secure Authentication System")
    st.markdown("### Login")
    
    # Initialize session states
    if 'failed_attempts' not in st.session_state:
        st.session_state['failed_attempts'] = 0
    if 'lockout_time' not in st.session_state:
        st.session_state['lockout_time'] = None
    
    # Add a register button
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("Register New User"):
            st.session_state['show_login'] = False
            st.session_state['registration_step'] = 1
            st.rerun()
    
    # Check if account is locked
    if st.session_state['lockout_time'] is not None:
        current_time = datetime.now()
        if current_time < st.session_state['lockout_time']:
            # Calculate remaining time
            remaining_time = (st.session_state['lockout_time'] - current_time).seconds
            
            # Show lockout message in a prominent error box
            st.error("🔒 Oops attempt over! Try again after one minute")
            
            # Show countdown timer
            st.warning(f"⏳ Time remaining: {remaining_time} seconds")
            
            # Auto refresh every second
            time.sleep(1)
            st.rerun()
            return
        else:
            # Reset lockout after timeout
            st.session_state['lockout_time'] = None
            st.session_state['failed_attempts'] = 0
    
    # Show login form
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if not username or not password:
                st.error("Please enter both username and password.")
                return
            
            try:
                # Get user from database
                user = get_user(username)
                if not user:
                    st.session_state['failed_attempts'] += 1
                    if st.session_state['failed_attempts'] >= 4:
                        # Set lockout time to 1 minute from now
                        st.session_state['lockout_time'] = datetime.now() + timedelta(minutes=1)
                        st.error("🔒 Oops attempt over! Try again after one minute")
                        create_audit_log(
                            "ACCOUNT_LOCKED",
                            username,
                            "Account locked due to multiple failed attempts",
                            True
                        )
                        st.rerun()
                    else:
                        remaining = 4 - st.session_state['failed_attempts']
                        st.error(f"Invalid username or password. {remaining} attempts remaining.")
                    return
                
                # Verify password
                hashed = user['hashed_password'].encode('utf-8')
                salt = user['salt'].encode('utf-8')
                if PasswordManager.verify_password(password, hashed, salt):
                    # Reset failed attempts on successful login
                    st.session_state['failed_attempts'] = 0
                    
                    # Update last login time
                    update_user(username, {'last_login': int(time.time())})
                    
                    # Set session state
                    st.session_state['logged_in'] = True
                    st.session_state['username'] = username
                    st.session_state['role'] = user['role']
                    
                    # Create audit log
                    create_audit_log(
                        "LOGIN",
                        username,
                        "Successful login",
                        True
                    )
                    
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.session_state['failed_attempts'] += 1
                    if st.session_state['failed_attempts'] >= 4:
                        # Set lockout time to 1 minute from now
                        st.session_state['lockout_time'] = datetime.now() + timedelta(minutes=1)
                        st.error("🔒 Oops attempt over! Try again after one minute")
                        create_audit_log(
                            "ACCOUNT_LOCKED",
                            username,
                            "Account locked due to multiple failed attempts",
                            True
                        )
                        st.rerun()
                    else:
                        remaining = 4 - st.session_state['failed_attempts']
                        st.error(f"Invalid username or password. {remaining} attempts remaining.")
                        # Create audit log for failed attempt
                        create_audit_log(
                            "LOGIN_FAILED",
                            username,
                            f"Failed login attempt ({st.session_state['failed_attempts']}/4)",
                            False
                        )
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
                logger.error(f"Login error: {str(e)}")

def show_register_page():
    st.title("🔒 Secure Authentication System")
    st.markdown("### Register New User")
    
    # Add a login button
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("Back to Login"):
            st.session_state['show_login'] = True
            st.session_state['registration_step'] = 1
            st.rerun()
    
    # Initialize session state for registration steps
    if 'registration_step' not in st.session_state:
        st.session_state['registration_step'] = 1
        st.session_state['temp_username'] = None
        st.session_state['temp_password'] = None
        st.session_state['temp_role'] = None
        st.session_state['temp_secret'] = None
    
    if st.session_state['registration_step'] == 1:
        with st.form("register_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            role = st.selectbox("Role", ["user", "admin"])
            
            # Show password requirements
            st.markdown("""
            #### Password Requirements:
            - At least 12 characters long
            - At least one uppercase letter
            - At least one lowercase letter
            - At least one number
            - At least one special character (!@#$%^&*(),.?":{}|<>)
            - No repeated characters (e.g., 'aaa')
            """)
            
            submit = st.form_submit_button("Register")
            
            if submit:
                if not username or not password or not confirm_password:
                    st.error("Please fill in all fields.")
                    return
                
                try:
                    if password != confirm_password:
                        st.error("Passwords do not match!")
                    else:
                        # Validate password before registration
                        is_valid, message = PasswordPolicy.validate_password(password)
                        if not is_valid:
                            st.error(f"Password validation failed: {message}")
                            return
                        
                        # Generate OTP secret
                        otp_secret = MFAManager.generate_otp_secret()
                        
                        # Store temporary data
                        st.session_state['temp_username'] = username
                        st.session_state['temp_password'] = password
                        st.session_state['temp_role'] = role
                        st.session_state['temp_secret'] = otp_secret
                        st.session_state['registration_step'] = 2
                        st.rerun()
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")
                    logger.error(f"Registration error: {str(e)}")
    
    elif st.session_state['registration_step'] == 2:
        st.markdown("### One-Time Setup: Two-Factor Authentication")
        st.markdown("""
        To secure your account, you need to set up 2FA once during registration:
        1. Install Google Authenticator or any other TOTP app on your phone
        2. Scan the QR code below with your authenticator app
        3. Enter the verification code from your app to complete registration
        
        Note: You won't need to use 2FA for future logins - this is just for registration security.
        """)
        
        # Generate and display QR code
        qr_code = MFAManager.generate_qr_code(
            st.session_state['temp_username'],
            st.session_state['temp_secret']
        )
        if qr_code:
            st.markdown(f'<img src="{qr_code}" alt="2FA QR Code">', unsafe_allow_html=True)
            
            # Display the secret key as backup
            st.info(f"If you cannot scan the QR code, manually enter this secret key in your authenticator app: {st.session_state['temp_secret']}")
        else:
            st.error("Error generating QR code")
            return
        
        with st.form("2fa_setup_form"):
            verification_code = st.text_input("Enter the verification code from your app")
            submit = st.form_submit_button("Complete Registration")
            
            if submit:
                if not verification_code:
                    st.error("Please enter the verification code.")
                    return
                
                try:
                    # Verify the OTP code
                    if MFAManager.verify_otp(st.session_state['temp_secret'], verification_code):
                        # Complete registration
                        success = register_user(
                            st.session_state['temp_username'],
                            st.session_state['temp_password'],
                            st.session_state['temp_role']
                        )
                        
                        if success:
                            st.success("Registration successful! You can now login with just your username and password.")
                            # Clear temporary data
                            st.session_state['registration_step'] = 1
                            st.session_state['temp_username'] = None
                            st.session_state['temp_password'] = None
                            st.session_state['temp_role'] = None
                            st.session_state['temp_secret'] = None
                            st.session_state['show_login'] = True
                            st.rerun()
                        else:
                            st.error("Registration failed. Username might already exist.")
                    else:
                        st.error("Invalid verification code. Please try again.")
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")
                    logger.error(f"2FA setup error: {str(e)}")

def show_dashboard():
    st.title(f"Welcome, {st.session_state['username']}!")
    st.markdown(f"Role: {st.session_state['role']}")
    
    # Create columns for different sections
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 👤 Profile Information")
        st.write(f"Username: {st.session_state['username']}")
        st.write(f"Role: {st.session_state['role']}")
        
        # Custom CSS for button text
        st.markdown("""
            <style>
            .stButton > button {
                color: #4CAF50 !important;
                font-weight: bold;
            }
            </style>
        """, unsafe_allow_html=True)
        
        if st.button("🔑 Change Password", key="change_password"):
            st.session_state['show_change_password'] = True
            st.rerun()
    
    with col2:
        st.markdown("### 📊 System Status")
        
        # Initialize show_status in session state if not exists
        if 'show_status' not in st.session_state:
            st.session_state['show_status'] = True
            
        # Toggle button for system status
        if st.button("👁️ " + ("Hide Status" if st.session_state['show_status'] else "Show Status")):
            st.session_state['show_status'] = not st.session_state['show_status']
            st.rerun()
        
        if st.session_state['show_status']:
            # Get system metrics
            cpu_usage = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # CPU Usage
            st.write("CPU Usage:")
            st.progress(cpu_usage / 100)
            st.write(f"{cpu_usage:.1f}%")
            
            # Memory Usage
            st.write("Memory Usage:")
            st.progress(memory.percent / 100)
            st.write(f"{memory.percent:.1f}% ({memory.used // (1024*1024)} MB used of {memory.total // (1024*1024)} MB)")
            
            # Disk Usage
            st.write("Disk Usage:")
            st.progress(disk.percent / 100)
            st.write(f"{disk.percent:.1f}% ({disk.used // (1024*1024*1024)} GB used of {disk.total // (1024*1024*1024)} GB)")
            
            # System Status Indicators
            st.markdown("#### System Components")
            st.write("✅ Authentication System: Active")
            st.write("✅ Database: Connected")
            st.write("✅ Security Features: Enabled")
        else:
            st.info("Click 'Show Status' to view system metrics")
    
    # Admin features
    if st.session_state['role'] == 'admin':
        st.markdown("### 🛠️ Admin Controls")
        admin_col1, admin_col2 = st.columns(2)
        
        with admin_col1:
            if st.button("👥 Users", key="users_tab"):
                toggle_tab('users')
            
            if 'users' in st.session_state['open_tabs']:
                users = get_all_users()
                st.markdown("### User List")
                for user in users:
                    username = user[0]
                    if username != st.session_state['username']:  # Don't show restrict button for self
                        with st.expander(f"User: {username}"):
                            st.write(f"Role: {user[1]}")
                            st.write(f"Created: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user[2]))}")
                            st.write(f"Last Login: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user[3]))}")
                            
                            if username in st.session_state['restricted_users']:
                                if st.button("🔓 Unrestrict", key=f"unrestrict_{username}"):
                                    unrestrict_user(username)
                                    st.success(f"User {username} has been unrestricted")
                                    st.rerun()
                            else:
                                if st.button("🔒 Restrict", key=f"restrict_{username}"):
                                    restrict_user(username)
                                    st.warning(f"User {username} has been restricted")
                                    st.rerun()
            
            if st.button("📋 Logs", key="logs_tab"):
                toggle_tab('logs')
            
            if 'logs' in st.session_state['open_tabs']:
                logs = get_audit_logs(limit=10)
                st.markdown("### Recent Audit Logs")
                for log in logs:
                    with st.expander(f"Log: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log[0]))}"):
                        st.write(f"Event: {log[1]}")
                        st.write(f"User: {log[2]}")
                        st.write(f"Details: {log[3]}")
                        st.write(f"Success: {'✅' if log[4] else '❌'}")
        
        with admin_col2:
            if st.button("⚙️ System", key="sysinfo_tab"):
                toggle_tab('sysinfo')
            
            if 'sysinfo' in st.session_state['open_tabs']:
                st.markdown("### System Information")
                # CPU Details
                with st.expander("CPU Information"):
                    cpu_freq = psutil.cpu_freq()
                    st.write(f"CPU Frequency: {cpu_freq.current:.1f} MHz")
                    st.write(f"CPU Cores: {psutil.cpu_count()}")
                
                # Memory Details
                with st.expander("Memory Information"):
                    swap = psutil.swap_memory()
                    st.write(f"Swap Usage: {swap.percent}%")
                    st.progress(swap.percent / 100)
                
                # Network Details
                with st.expander("Network Information"):
                    net_io = psutil.net_io_counters()
                    st.write(f"Bytes Sent: {net_io.bytes_sent // (1024*1024)} MB")
                    st.write(f"Bytes Received: {net_io.bytes_recv // (1024*1024)} MB")
            
            if st.button("💾 Database", key="db_tab"):
                toggle_tab('database')
            
            if 'database' in st.session_state['open_tabs']:
                st.markdown("### Database Management")
                if st.button("Create Backup", key="backup_db"):
                    try:
                        from database import backup_database
                        if backup_database():
                            st.success("Database backup created successfully!")
                        else:
                            st.error("Failed to create database backup.")
                    except Exception as e:
                        st.error(f"Backup error: {str(e)}")
    
    if st.button("🚪 Logout", key="logout"):
        st.session_state['logged_in'] = False
        st.rerun()

def show_change_password():
    st.title("Change Password")
    
    # Add a back button
    if st.button("Back to Dashboard"):
        st.session_state['show_change_password'] = False
        st.experimental_rerun()
    
    with st.form("change_password_form"):
        current_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        
        # Show password requirements
        st.markdown("""
        #### Password Requirements:
        - At least 12 characters long
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character (!@#$%^&*(),.?":{}|<>)
        - No repeated characters (e.g., 'aaa')
        """)
        
        submit = st.form_submit_button("Change Password")
        
        if submit:
            if not current_password or not new_password or not confirm_password:
                st.error("Please fill in all fields.")
                return
            
            try:
                if new_password != confirm_password:
                    st.error("New passwords do not match!")
                else:
                    # Validate new password
                    is_valid, message = PasswordPolicy.validate_password(new_password)
                    if not is_valid:
                        st.error(f"Password validation failed: {message}")
                        return
                    
                    success = change_password(
                        st.session_state['username'],
                        current_password,
                        new_password
                    )
                    if success:
                        st.success("Password changed successfully!")
                        st.session_state['show_change_password'] = False
                        st.experimental_rerun()
                    else:
                        st.error("Failed to change password. Please check your current password.")
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
                logger.error(f"Password change error: {str(e)}")

def main():
    # Initialize session state
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    if 'show_login' not in st.session_state:
        st.session_state['show_login'] = True
    if 'show_change_password' not in st.session_state:
        st.session_state['show_change_password'] = False
    
    # Show appropriate page based on session state
    if st.session_state['logged_in']:
        if st.session_state['show_change_password']:
            show_change_password()
        else:
            show_dashboard()
    elif st.session_state['show_login']:
        show_login_page()
    else:
        show_register_page()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"An unexpected error occurred: {str(e)}")
        logger.error(f"Application error: {str(e)}") 
