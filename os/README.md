# Secure Authentication System

A robust and secure authentication system with multi-factor authentication, designed for university-level projects.

## Features

- Multi-factor authentication (2FA) using TOTP
- Secure password hashing with bcrypt
- Rate limiting to prevent brute force attacks
- Session management with timeout
- Audit logging with rotation
- Role-based access control
- Password policy enforcement
- Account locking mechanism
- Email notifications
- File operation security
- System monitoring capabilities

## Security Features

- Password complexity requirements
- Password expiry
- Session timeout
- Rate limiting
- Input sanitization
- File path validation
- SQL injection prevention
- XSS prevention
- CSRF protection
- Secure session management
- Audit logging
- Error handling

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-auth-system.git
cd secure-auth-system
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with the following variables:
```env
EMAIL_FROM=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

5. Initialize the database:
```bash
python -c "from database import init_db; init_db()"
```

## Usage

1. Start the application:
```bash
python main.py
```

2. Register a new user:
```bash
# Follow the prompts to create a new user account
```

3. Login:
```bash
# Enter your credentials and complete 2FA
```

## Project Structure

```
secure-auth-system/
├── config.py           # Configuration settings
├── database.py         # Database management
├── security.py         # Security functionality
├── logger.py          # Logging management
├── main.py            # Main application
├── requirements.txt   # Dependencies
├── .env              # Environment variables
├── data/             # Database files
├── logs/             # Log files
└── uploads/          # File uploads
```

## Security Considerations

1. Password Security:
   - Minimum length: 12 characters
   - Must contain uppercase, lowercase, numbers, and special characters
   - No repeated characters
   - Regular password expiry

2. Session Security:
   - Cryptographically secure session IDs
   - Session timeout after 30 minutes of inactivity
   - Single session per user

3. Rate Limiting:
   - Maximum 5 login attempts per 15 minutes
   - Account locking after 3 failed attempts

4. File Security:
   - Path traversal prevention
   - File size limits
   - File type validation
   - Secure file operations

## Testing

Run the test suite:
```bash
pytest tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [bcrypt](https://github.com/pyca/bcrypt/) for password hashing
- [pyotp](https://github.com/pyauth/pyotp) for 2FA implementation
- [email-validator](https://github.com/JoshData/python-email-validator) for email validation

## Contact

For questions or support, please open an issue in the GitHub repository. 