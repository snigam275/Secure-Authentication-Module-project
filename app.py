"""
Streamlit UI for the Authentication System
"""
import streamlit as st
import sys
import os
from pathlib import Path
import time
from database import init_db, get_user, update_user, create_audit_log, get_all_users, get_audit_logs
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

# Initialize database
init_db()

# Set page config
st.set_page_config(
    page_title="Secure Authentication System",
    page_icon="🔒",
    layout="wide"
)

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
    </style>
""", unsafe_allow_html=True)

def show_login_page():
    st.title("🔒 Secure Authentication System")
    st.markdown("### Login")
    
    # Add a register button
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("Register New User"):
            st.session_state['show_login'] = False
            st.experimental_rerun()
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if not username or not password:
                st.error("Please enter both username and password.")
                return
            
            try:
                success, role = login_user(username, password)
                if success:
                    st.session_state['logged_in'] = True
                    st.session_state['username'] = username
                    st.session_state['role'] = role
                    st.success("Login successful!")
                    st.experimental_rerun()
                else:
                    st.error("Invalid credentials. Please try again.")
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
            st.experimental_rerun()
    
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
                    
                    success = register_user(username, password, role)
                    if success:
                        st.success("Registration successful! Please login.")
                        st.session_state['show_login'] = True
                        st.experimental_rerun()
                    else:
                        st.error("Registration failed. Username might already exist.")
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
                logger.error(f"Registration error: {str(e)}")

def show_dashboard():
    st.title(f"Welcome, {st.session_state['username']}!")
    st.markdown(f"Role: {st.session_state['role']}")
    
    # Create columns for different sections
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Profile Information")
        st.write(f"Username: {st.session_state['username']}")
        st.write(f"Role: {st.session_state['role']}")
        
        if st.button("Change Password"):
            st.session_state['show_change_password'] = True
            st.experimental_rerun()
    
    with col2:
        st.markdown("### System Status")
        st.write("✅ Authentication System: Active")
        st.write("✅ Database: Connected")
        st.write("✅ Security Features: Enabled")
    
    # Admin features
    if st.session_state['role'] == 'admin':
        st.markdown("### Admin Controls")
        admin_col1, admin_col2 = st.columns(2)
        
        with admin_col1:
            if st.button("View Users"):
                users = get_all_users()
                st.markdown("### User List")
                for user in users:
                    st.write(f"Username: {user[0]}, Role: {user[1]}")
                    st.write(f"Created: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user[2]))}")
                    st.write(f"Last Login: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user[3]))}")
                    st.write("---")
            
            if st.button("View Logs"):
                logs = get_audit_logs(limit=10)
                st.markdown("### Recent Audit Logs")
                for log in logs:
                    st.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log[0]))}")
                    st.write(f"Event: {log[1]}, User: {log[2]}")
                    st.write(f"Details: {log[3]}, Success: {log[4]}")
                    st.write("---")
        
        with admin_col2:
            if st.button("System Info"):
                st.markdown("### System Information")
                st.write(f"CPU Usage: {psutil.cpu_percent()}%")
                st.write(f"Memory Usage: {psutil.virtual_memory().percent}%")
                st.write(f"Disk Usage: {psutil.disk_usage('/').percent}%")
            
            if st.button("Backup Database"):
                try:
                    from database import backup_database
                    if backup_database():
                        st.success("Database backup created successfully!")
                    else:
                        st.error("Failed to create database backup.")
                except Exception as e:
                    st.error(f"Backup error: {str(e)}")
    
    if st.button("Logout"):
        st.session_state['logged_in'] = False
        st.experimental_rerun()

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