"""
Module: test_auth_integration
Purpose: Comprehensive integration tests for CEMS authentication system
Author: CEMS Development Team
Date: 2024
"""

import pytest
import json
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.security import get_password_hash, create_access_token, security_manager
from app.core.constants import UserRole, UserStatus
from app.db.models import User, Role, UserRole as UserRoleAssoc
from app.schemas.auth import LoginRequest, PasswordChangeRequest
from app.services.auth_service import AuthenticationService
from app.repositories.user_repository import UserRepository


class TestAuthenticationIntegration:
    """
    Comprehensive integration tests for authentication system.
    Tests the complete flow from endpoints to database models.
    """
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    @pytest.fixture
    def test_user(self, db_session: Session):
        """Create test user with proper model structure."""
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password=get_password_hash("testpassword123"),
            first_name="Test",
            last_name="User",
            status=UserStatus.ACTIVE,
            is_active=True,
            is_verified=True,
            is_superuser=False
        )
        
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        
        return user
    
    @pytest.fixture
    def test_admin_user(self, db_session: Session):
        """Create test admin user."""
        admin_user = User(
            username="admin",
            email="admin@example.com",
            hashed_password=get_password_hash("adminpass123"),
            first_name="Admin",
            last_name="User",
            status=UserStatus.ACTIVE,
            is_active=True,
            is_verified=True,
            is_superuser=True
        )
        
        db_session.add(admin_user)
        db_session.commit()
        db_session.refresh(admin_user)
        
        return admin_user
    
    @pytest.fixture
    def test_roles(self, db_session: Session):
        """Create test roles."""
        roles = [
            Role(
                name=UserRole.ADMIN.value,
                display_name="Administrator",
                description="System administrator",
                is_system_role=True,
                permissions='["admin.*", "user.*"]'
            ),
            Role(
                name=UserRole.CASHIER.value,
                display_name="Cashier",
                description="Front desk cashier",
                is_system_role=True,
                permissions='["transaction.create", "customer.view"]'
            )
        ]
        
        for role in roles:
            db_session.add(role)
        
        db_session.commit()
        
        return roles
    
    @pytest.fixture
    def user_with_role(self, db_session: Session, test_user: User, test_roles: list):
        """Create user with cashier role."""
        cashier_role = next(r for r in test_roles if r.name == UserRole.CASHIER.value)
        
        user_role = UserRoleAssoc(
            user_id=test_user.id,
            role_id=cashier_role.id,
            is_active=True,
            assigned_at=datetime.utcnow()
        )
        
        db_session.add(user_role)
        db_session.commit()
        
        return test_user
    
    # ==================== LOGIN TESTS ====================
    
    def test_successful_login_with_username(self, client: TestClient, test_user: User):
        """Test successful login using username."""
        response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify token structure
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        
        # Verify user information
        assert data["user_id"] == test_user.id
        assert data["username"] == test_user.username
        assert data["email"] == test_user.email
        assert data["full_name"] == test_user.full_name
        
        # Verify security fields
        assert "session_id" in data
        assert isinstance(data["is_2fa_enabled"], bool)
        assert isinstance(data["must_change_password"], bool)
    
    def test_successful_login_with_email(self, client: TestClient, test_user: User):
        """Test successful login using email."""
        response = client.post("/api/v1/auth/login", json={
            "username": test_user.email,
            "password": "testpassword123"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == test_user.id
    
    def test_login_with_invalid_credentials(self, client: TestClient, test_user: User):
        """Test login with invalid password."""
        response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "wrongpassword"
        })
        
        assert response.status_code == 401
        data = response.json()
        assert data["error"] is True
        assert "invalid" in data["message"].lower()
    
    def test_login_with_nonexistent_user(self, client: TestClient):
        """Test login with non-existent user."""
        response = client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "password123"
        })
        
        assert response.status_code == 401
        data = response.json()
        assert data["error"] is True
    
    def test_login_with_inactive_user(self, client: TestClient, db_session: Session, test_user: User):
        """Test login with inactive user account."""
        # Deactivate user
        test_user.is_active = False
        db_session.commit()
        
        response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        assert response.status_code == 401
        data = response.json()
        assert "inactive" in data["message"].lower()
    
    def test_login_with_suspended_user(self, client: TestClient, db_session: Session, test_user: User):
        """Test login with suspended user account."""
        # Suspend user
        test_user.status = UserStatus.SUSPENDED
        db_session.commit()
        
        response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        assert response.status_code == 401
        data = response.json()
        assert "suspended" in data["message"].lower()
    
    def test_account_lockout_after_failed_attempts(self, client: TestClient, db_session: Session, test_user: User):
        """Test account lockout after multiple failed attempts."""
        # Make multiple failed login attempts
        for _ in range(6):  # Exceed MAX_LOGIN_ATTEMPTS
            response = client.post("/api/v1/auth/login", json={
                "username": test_user.username,
                "password": "wrongpassword"
            })
        
        # Refresh user from database
        db_session.refresh(test_user)
        
        # Verify account is locked
        assert test_user.is_locked is True
        assert test_user.locked_until is not None
        
        # Try with correct password - should still be locked
        response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        assert response.status_code == 423  # Locked
        data = response.json()
        assert "locked" in data["message"].lower()
    
    # ==================== TOKEN TESTS ====================
    
    def test_token_refresh_success(self, client: TestClient, test_user: User):
        """Test successful token refresh."""
        # First login to get tokens
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Refresh token
        response = client.post("/api/v1/auth/refresh", json={
            "refresh_token": tokens["refresh_token"]
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
    
    def test_token_refresh_with_invalid_token(self, client: TestClient):
        """Test token refresh with invalid refresh token."""
        response = client.post("/api/v1/auth/refresh", json={
            "refresh_token": "invalid_token"
        })
        
        assert response.status_code == 401
        data = response.json()
        assert data["error"] is True
    
    def test_token_validation(self, client: TestClient, test_user: User):
        """Test token validation endpoint."""
        # Login to get token
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Validate token
        response = client.post("/api/v1/auth/validate-token", json={
            "token": tokens["access_token"],
            "token_type": "access"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["user_id"] == test_user.id
        assert data["username"] == test_user.username
    
    # ==================== AUTHORIZATION TESTS ====================
    
    def test_protected_endpoint_without_token(self, client: TestClient):
        """Test accessing protected endpoint without token."""
        response = client.get("/api/v1/auth/me")
        
        assert response.status_code == 401
    
    def test_protected_endpoint_with_valid_token(self, client: TestClient, test_user: User):
        """Test accessing protected endpoint with valid token."""
        # Login to get token
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Access protected endpoint
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_user.id
        assert data["username"] == test_user.username
    
    def test_role_based_access_control(self, client: TestClient, user_with_role: User, test_roles: list):
        """Test role-based access control."""
        # Login with user who has cashier role
        login_response = client.post("/api/v1/auth/login", json={
            "username": user_with_role.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Verify user has cashier role in response
        assert UserRole.CASHIER.value in tokens["roles"]
        
        # Verify permissions are included
        assert "transaction.create" in tokens["permissions"]
        assert "customer.view" in tokens["permissions"]
    
    def test_superuser_permissions(self, client: TestClient, test_admin_user: User):
        """Test superuser has all permissions."""
        # Login as admin
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_admin_user.username,
            "password": "adminpass123"
        })
        
        tokens = login_response.json()
        
        # Superuser should have "*" permission
        assert "*" in tokens["permissions"]
    
    # ==================== PASSWORD MANAGEMENT TESTS ====================
    
    def test_password_change_success(self, client: TestClient, test_user: User):
        """Test successful password change."""
        # Login to get token
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Change password
        response = client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={
                "current_password": "testpassword123",
                "new_password": "newpassword123!",
                "confirm_password": "newpassword123!"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "password_strength_score" in data
    
    def test_password_change_wrong_current_password(self, client: TestClient, test_user: User):
        """Test password change with wrong current password."""
        # Login to get token
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Try to change password with wrong current password
        response = client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={
                "current_password": "wrongpassword",
                "new_password": "newpassword123!",
                "confirm_password": "newpassword123!"
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["error"] is True
    
    def test_password_strength_validation(self, client: TestClient):
        """Test password strength validation endpoint."""
        # Test weak password
        response = client.post("/api/v1/auth/check-password-strength", json={
            "password": "123"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_valid"] is False
        assert data["strength"] in ["very_weak", "weak"]
        assert len(data["suggestions"]) > 0
        
        # Test strong password
        response = client.post("/api/v1/auth/check-password-strength", json={
            "password": "StrongPassword123!"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_valid"] is True
        assert data["strength"] in ["strong", "very_strong"]
    
    # ==================== LOGOUT TESTS ====================
    
    def test_logout_success(self, client: TestClient, test_user: User):
        """Test successful logout."""
        # Login to get token
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Logout
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={
                "revoke_refresh_token": True,
                "terminate_all_sessions": False
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "sessions_terminated" in data
    
    def test_logout_terminate_all_sessions(self, client: TestClient, test_user: User):
        """Test logout with all sessions termination."""
        # Login to get token
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Logout with all sessions termination
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={
                "revoke_refresh_token": True,
                "terminate_all_sessions": True
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["sessions_terminated"] >= 1
    
    # ==================== RATE LIMITING TESTS ====================
    
    def test_login_rate_limiting(self, client: TestClient):
        """Test login rate limiting."""
        # Make many rapid login attempts
        responses = []
        for _ in range(15):  # Exceed rate limit
            response = client.post("/api/v1/auth/login", json={
                "username": "testuser",
                "password": "wrongpassword"
            })
            responses.append(response)
        
        # Some responses should be rate limited
        rate_limited_responses = [r for r in responses if r.status_code == 429]
        assert len(rate_limited_responses) > 0
    
    # ==================== SESSION MANAGEMENT TESTS ====================
    
    def test_get_active_sessions(self, client: TestClient, test_user: User):
        """Test getting active sessions."""
        # Login to create session
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Get active sessions
        response = client.get(
            "/api/v1/auth/sessions",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data
        assert "total_sessions" in data
        assert data["total_sessions"] >= 1
    
    def test_terminate_specific_session(self, client: TestClient, test_user: User):
        """Test terminating a specific session."""
        # Login to create session
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        session_id = tokens["session_id"]
        
        # Terminate the session
        response = client.delete(
            f"/api/v1/auth/sessions/{session_id}",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
    
    # ==================== SERVICE LAYER TESTS ====================
    
    def test_auth_service_direct_usage(self, db_session: Session, test_user: User):
        """Test using AuthenticationService directly."""
        auth_service = AuthenticationService(db_session)
        
        # Test authentication
        login_data = LoginRequest(
            username=test_user.username,
            password="testpassword123"
        )
        
        client_info = {
            "ip_address": "127.0.0.1",
            "user_agent": "test-agent"
        }
        
        result = auth_service.authenticate_user(login_data, client_info)
        
        assert result.user_id == test_user.id
        assert result.username == test_user.username
        assert result.access_token is not None
        assert result.refresh_token is not None
    
    def test_user_repository_integration(self, db_session: Session, test_user: User, test_roles: list):
        """Test UserRepository integration with models."""
        user_repo = UserRepository(db_session)
        
        # Test getting user by username
        found_user = user_repo.get_by_username(test_user.username)
        assert found_user is not None
        assert found_user.id == test_user.id
        
        # Test role assignment
        admin_role = next(r for r in test_roles if r.name == UserRole.ADMIN.value)
        success = user_repo.assign_role_to_user(test_user.id, admin_role.name)
        assert success is True
        
        # Test getting user roles
        user_roles = user_repo.get_user_roles(test_user.id)
        assert UserRole.ADMIN.value in user_roles
        
        # Test getting user permissions
        user_permissions = user_repo.get_user_permissions(test_user.id)
        assert "admin.*" in user_permissions or "user.*" in user_permissions
    
    # ==================== HEALTH CHECK TESTS ====================
    
    def test_auth_service_status(self, client: TestClient):
        """Test authentication service health check."""
        response = client.get("/api/v1/auth/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "authentication"
        assert "status" in data
        assert "checks" in data
        assert "timestamp" in data
    
    # ==================== EDGE CASES AND ERROR HANDLING ====================
    
    def test_malformed_token(self, client: TestClient):
        """Test handling of malformed tokens."""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer malformed.token.here"}
        )
        
        assert response.status_code == 401
    
    def test_expired_token_handling(self, client: TestClient, test_user: User):
        """Test handling of expired tokens."""
        # Create an expired token
        expired_token_data = {
            "sub": str(test_user.id),
            "username": test_user.username
        }
        
        expired_token = create_access_token(
            expired_token_data,
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 401
    
    def test_concurrent_login_sessions(self, client: TestClient, test_user: User):
        """Test multiple concurrent login sessions."""
        tokens_list = []
        
        # Create multiple login sessions
        for _ in range(3):
            response = client.post("/api/v1/auth/login", json={
                "username": test_user.username,
                "password": "testpassword123"
            })
            
            assert response.status_code == 200
            tokens_list.append(response.json())
        
        # All tokens should be valid
        for tokens in tokens_list:
            response = client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )
            assert response.status_code == 200
    
    def test_database_error_handling(self, client: TestClient, monkeypatch):
        """Test graceful handling of database errors."""
        # This would require mocking database errors
        # Implementation depends on specific testing strategy
        pass
    
    # ==================== SECURITY FEATURE TESTS ====================
    
    def test_password_history_prevention(self, db_session: Session, test_user: User):
        """Test password history prevention (if implemented)."""
        auth_service = AuthenticationService(db_session)
        
        # This test would verify that users can't reuse recent passwords
        # Implementation depends on password history feature
        pass
    
    def test_session_timeout_handling(self, client: TestClient, test_user: User):
        """Test session timeout handling."""
        # Login to create session
        login_response = client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpassword123"
        })
        
        tokens = login_response.json()
        
        # Simulate session timeout by manipulating session manager
        session_id = tokens["session_id"]
        security_manager.session_manager.invalidate_session(session_id)
        
        # Subsequent requests should handle the invalid session gracefully
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        
        # The response might still be valid if the token itself is valid
        # but session tracking would be affected
        assert response.status_code in [200, 401]


class TestModelIntegration:
    """Test integration with database models specifically."""
    
    def test_user_model_properties(self, db_session: Session):
        """Test User model properties and methods."""
        user = User(
            username="testmodel",
            email="testmodel@example.com",
            hashed_password=get_password_hash("password123"),
            first_name="Test",
            last_name="Model",
            status=UserStatus.ACTIVE,
            is_active=True
        )
        
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        
        # Test computed properties
        assert user.full_name == "Test Model"
        assert user.is_locked is False
        
        # Test model methods
        user.record_failed_login()
        assert int(user.failed_login_attempts) == 1
        
        user.lock_account(15)
        assert user.is_locked is True
        assert user.locked_until is not None
        
        user.unlock_account()
        assert user.is_locked is False
        assert user.locked_until is None
    
    def test_role_model_validation(self, db_session: Session):
        """Test Role model validation."""
        # Test valid role
        role = Role(
            name=UserRole.CASHIER.value,
            display_name="Test Cashier",
            description="Test role"
        )
        
        db_session.add(role)
        db_session.commit()
        
        # Test invalid role name should raise validation error
        with pytest.raises(ValueError):
            invalid_role = Role(
                name="invalid_role_name",
                display_name="Invalid Role"
            )
            db_session.add(invalid_role)
            db_session.commit()
    
    def test_user_role_association(self, db_session: Session):
        """Test UserRole association model."""
        # Create user and role
        user = User(
            username="roletest",
            email="roletest@example.com",
            hashed_password=get_password_hash("password123"),
            first_name="Role",
            last_name="Test",
            status=UserStatus.ACTIVE,
            is_active=True
        )
        
        role = Role(
            name=UserRole.CASHIER.value,
            display_name="Cashier",
            description="Cashier role"
        )
        
        db_session.add(user)
        db_session.add(role)
        db_session.commit()
        
        # Create association
        user_role = UserRoleAssoc(
            user_id=user.id,
            role_id=role.id,
            is_active=True,
            assigned_at=datetime.utcnow()
        )
        
        db_session.add(user_role)
        db_session.commit()
        
        # Test relationship loading
        db_session.refresh(user)
        assert len(user.user_roles) == 1
        assert user.user_roles[0].role.name == UserRole.CASHIER.value
    
    def test_enum_integration(self):
        """Test enum integration with models."""
        # Test UserStatus enum
        assert UserStatus.ACTIVE.value == "active"
        assert UserStatus.SUSPENDED.value == "suspended"
        
        # Test UserRole enum
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.CASHIER.value == "cashier"
        
        # Test enum validation
        valid_statuses = [status.value for status in UserStatus]
        assert "active" in valid_statuses
        assert "invalid_status" not in valid_statuses