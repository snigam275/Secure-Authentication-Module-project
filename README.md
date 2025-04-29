# 🔐 Secure Authentication System
A robust and secure authentication system designed for university-level projects. This system incorporates multi-factor authentication and modern security practices for user management and file handling.
"Secure Authentication Module: A robust authentication system with encryption, multi-factor authentication, and secure session management."
Fixed logging bypass vulnerability by enhancing input validation.(bug fixes)

## 🧰 Features
- ✅ Two-Factor Authentication (2FA) using TOTP
- 🔒 Secure password hashing with bcrypt
- 🚫 Rate limiting to block brute-force attacks
- ⏳ Session management with timeout and single session per user
- 📝 Audit logging with log rotation
- 🛡️ Role-based access control (RBAC)
- 🧩 Password policy enforcement
- 🧱 Account locking mechanism
- 📁 Secure file operations
- 📊 System monitoring and activity logging

## 🛡️ Security Practices
- 🔐 Password complexity & expiry
- ⏲️ Session timeout after 30 minutes
- 🔄 Single active session per user
- 🚷 Account lock after 3 failed attempts and block and only user 
- 🚫 Only admin can restrict and unrestrict any user
- ✍️ Input sanitization
- 🧭 File path validation
- 🧼 SQL injection prevention
- 🧾 Secure error handling
- 📚 Audit logs for all user activities

## 🧪 How to Use
- 1)📝 Register: Create a new user following the password policy
- 2)🔐 Login: Provide credentials and complete 2FA using an authenticator app
- 3)🕒 Session Handling: Secure sessions with auto-timeout
- 4)📊 Monitoring: All activity logged securely
- 5)⚙️ Access Control: Roles determine feature accessibility

## 🔐 Password & Session Policy
- 📏 Minimum 12 characters with mixed character types
- 🚫 No repeated characters
- 🔄 Password expiry enforcement
- 🔑 Cryptographically secure session tokens
- ⌛ Session expires after 30 minutes
- 🚷 Only one session per user

## 📂 File Security
- 📎 File size and type validation
- 🔍 Prevent directory traversal
- 🧼 Secure file operations

## 🧪 Testing
* Run tests using: streamlit run app.py  (Command to execute program)

## 🗂️ Project Structure
- config.py – Application configuration settings
- database.py – Handles database initialization and schema
- security.py – Contains all security functions (password hashing, TOTP, validations)
- logger.py – Manages audit logging and log rotation
- main.py – Main entry point of the application
- requirements.txt – Lists all Python dependencies

## 🧠 Future Enhancements
We can add these all features in future to make this project more enhacing by working on it:
- OAuth2 / SSO integration
- Admin dashboard for user/session monitoring
- Biometric or hardware token support
- Dark mode for UI 
- Docker containerization for easier deployment
