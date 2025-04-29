"""
Test suite for security functionality.
"""
import pytest
from security import (
    PasswordPolicy,
    PasswordManager,
    SessionManager,
    MFAManager,
    RateLimiter
)
from database import init_db, get_user, create_audit_log
import time

@pytest.fixture
def setup_database():
    """Set up test database."""
    init_db()
    yield
    # Clean up after tests

class TestPasswordPolicy:
    """Test password policy enforcement."""
    
    def test_valid_password(self):
        """Test valid password."""
        password = "Test123!@#"
        is_valid, message = PasswordPolicy.validate_password(password)
        assert is_valid
        assert message == "Password meets complexity requirements"
    
    def test_short_password(self):
        """Test short password."""
        password = "Test123"
        is_valid, message = PasswordPolicy.validate_password(password)
        assert not is_valid
        assert "at least" in message
    
    def test_no_uppercase(self):
        """Test password without uppercase."""
        password = "test123!@#"
        is_valid, message = PasswordPolicy.validate_password(password)
        assert not is_valid
        assert "uppercase" in message
    
    def test_no_lowercase(self):
        """Test password without lowercase."""
        password = "TEST123!@#"
        is_valid, message = PasswordPolicy.validate_password(password)
        assert not is_valid
        assert "lowercase" in message
    
    def test_no_number(self):
        """Test password without number."""
        password = "TestTest!@#"
        is_valid, message = PasswordPolicy.validate_password(password)
        assert not is_valid
        assert "number" in message
    
    def test_no_special(self):
        """Test password without special character."""
        password = "TestTest123"
        is_valid, message = PasswordPolicy.validate_password(password)
        assert not is_valid
        assert "special" in message
    
    def test_repeated_chars(self):
        """Test password with repeated characters."""
        password = "Testtt123!@#"
        is_valid, message = PasswordPolicy.validate_password(password)
        assert not is_valid
        assert "repeated" in message

class TestPasswordManager:
    """Test password management functionality."""
    
    def test_password_hashing(self):
        """Test password hashing."""
        password = "Test123!@#"
        hashed, salt = PasswordManager.hash_password(password)
        assert isinstance(hashed, bytes)
        assert isinstance(salt, bytes)
        assert len(hashed) > 0
        assert len(salt) > 0
    
    def test_password_verification(self):
        """Test password verification."""
        password = "Test123!@#"
        hashed, salt = PasswordManager.hash_password(password)
        assert PasswordManager.verify_password(password, hashed, salt)
        assert not PasswordManager.verify_password("WrongPass", hashed, salt)

class TestSessionManager:
    """Test session management functionality."""
    
    def test_session_id_generation(self):
        """Test session ID generation."""
        session_id = SessionManager.generate_session_id()
        assert isinstance(session_id, str)
        assert len(session_id) > 0
    
    def test_session_creation(self, setup_database):
        """Test session creation."""
        username = "testuser"
        session_id = SessionManager.create_session(username)
        assert session_id is not None
        assert isinstance(session_id, str)
    
    def test_session_validation(self, setup_database):
        """Test session validation."""
        username = "testuser"
        session_id = SessionManager.create_session(username)
        is_valid, user = SessionManager.validate_session(session_id)
        assert is_valid
        assert user == username
    
    def test_session_expiry(self, setup_database):
        """Test session expiry."""
        username = "testuser"
        session_id = SessionManager.create_session(username)
        time.sleep(31)  # Wait for session to expire
        is_valid, user = SessionManager.validate_session(session_id)
        assert not is_valid
        assert user is None

class TestMFAManager:
    """Test multi-factor authentication functionality."""
    
    def test_otp_generation(self):
        """Test OTP generation."""
        secret = MFAManager.generate_otp_secret()
        otp = MFAManager.generate_otp(secret)
        assert isinstance(otp, str)
        assert len(otp) == 6
        assert otp.isdigit()
    
    def test_otp_verification(self):
        """Test OTP verification."""
        secret = MFAManager.generate_otp_secret()
        otp = MFAManager.generate_otp(secret)
        assert MFAManager.verify_otp(secret, otp)
        assert not MFAManager.verify_otp(secret, "000000")

class TestRateLimiter:
    """Test rate limiting functionality."""
    
    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter instance."""
        class MockRedis:
            def __init__(self):
                self.data = {}
            
            def incr(self, key):
                if key not in self.data:
                    self.data[key] = 0
                self.data[key] += 1
                return self.data[key]
            
            def expire(self, key, seconds):
                return True
            
            def delete(self, key):
                if key in self.data:
                    del self.data[key]
                    return 1
                return 0
        
        return RateLimiter(MockRedis())
    
    def test_rate_limit_check(self, rate_limiter):
        """Test rate limit checking."""
        username = "testuser"
        for _ in range(5):
            can_proceed, message = rate_limiter.check_rate_limit(username)
            assert can_proceed
            assert "passed" in message
        
        can_proceed, message = rate_limiter.check_rate_limit(username)
        assert not can_proceed
        assert "exceeded" in message
    
    def test_rate_limit_reset(self, rate_limiter):
        """Test rate limit reset."""
        username = "testuser"
        for _ in range(5):
            rate_limiter.check_rate_limit(username)
        
        assert rate_limiter.reset_rate_limit(username)
        can_proceed, message = rate_limiter.check_rate_limit(username)
        assert can_proceed
        assert "passed" in message 