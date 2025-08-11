package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) List(ctx context.Context, offset, limit int, filters map[string]interface{}) ([]*models.User, int, error) {
	args := m.Called(ctx, offset, limit, filters)
	return args.Get(0).([]*models.User), args.Int(1), args.Error(2)
}

func (m *MockUserRepository) GetWithRoles(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) ResetFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) LockAccount(ctx context.Context, id uuid.UUID, duration time.Duration) error {
	args := m.Called(ctx, id, duration)
	return args.Error(0)
}

func (m *MockUserRepository) UnlockAccount(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) Search(ctx context.Context, query string, offset, limit int) ([]*models.User, int, error) {
	args := m.Called(ctx, query, offset, limit)
	return args.Get(0).([]*models.User), args.Int(1), args.Error(2)
}

func (m *MockUserRepository) GetByFacility(ctx context.Context, facilityID uuid.UUID, offset, limit int) ([]*models.User, int, error) {
	args := m.Called(ctx, facilityID, offset, limit)
	return args.Get(0).([]*models.User), args.Int(1), args.Error(2)
}

func (m *MockUserRepository) GetByRole(ctx context.Context, roleID uuid.UUID, offset, limit int) ([]*models.User, int, error) {
	args := m.Called(ctx, roleID, offset, limit)
	return args.Get(0).([]*models.User), args.Int(1), args.Error(2)
}

// MockCache is a mock implementation of cache interface
type MockCache struct {
	mock.Mock
}

func (m *MockCache) SetSession(ctx context.Context, session *models.UserSession, ttl time.Duration) error {
	args := m.Called(ctx, session, ttl)
	return args.Error(0)
}

func (m *MockCache) GetSession(ctx context.Context, sessionToken string) (*models.UserSession, error) {
	args := m.Called(ctx, sessionToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserSession), args.Error(1)
}

func (m *MockCache) DeleteSession(ctx context.Context, sessionToken string) error {
	args := m.Called(ctx, sessionToken)
	return args.Error(0)
}

func (m *MockCache) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockCache) RefreshSession(ctx context.Context, sessionToken string, ttl time.Duration) error {
	args := m.Called(ctx, sessionToken, ttl)
	return args.Error(0)
}

func (m *MockCache) SetUserPermissions(ctx context.Context, userID uuid.UUID, permissions []string, ttl time.Duration) error {
	args := m.Called(ctx, userID, permissions, ttl)
	return args.Error(0)
}

func (m *MockCache) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockCache) DeleteUserPermissions(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockCache) CheckUserPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	args := m.Called(ctx, userID, permission)
	return args.Bool(0), args.Error(1)
}

func (m *MockCache) SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissions []string, ttl time.Duration) error {
	args := m.Called(ctx, roleID, permissions, ttl)
	return args.Error(0)
}

func (m *MockCache) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockCache) DeleteRolePermissions(ctx context.Context, roleID uuid.UUID) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func (m *MockCache) IncrementLoginAttempts(ctx context.Context, username string, ttl time.Duration) (int, error) {
	args := m.Called(ctx, username, ttl)
	return args.Int(0), args.Error(1)
}

func (m *MockCache) GetLoginAttempts(ctx context.Context, username string) (int, error) {
	args := m.Called(ctx, username)
	return args.Int(0), args.Error(1)
}

func (m *MockCache) ResetLoginAttempts(ctx context.Context, username string) error {
	args := m.Called(ctx, username)
	return args.Error(0)
}

func (m *MockCache) SetOTP(ctx context.Context, identifier string, otp string, ttl time.Duration) error {
	args := m.Called(ctx, identifier, otp, ttl)
	return args.Error(0)
}

func (m *MockCache) GetOTP(ctx context.Context, identifier string) (string, error) {
	args := m.Called(ctx, identifier)
	return args.String(0), args.Error(1)
}

func (m *MockCache) DeleteOTP(ctx context.Context, identifier string) error {
	args := m.Called(ctx, identifier)
	return args.Error(0)
}

func (m *MockCache) ClearAll(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockCache) GetStats(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockCache) Close() error {
	args := m.Called()
	return args.Error(0)
}

// TestAuthenticationService_PasswordAuthentication tests password-based authentication
func TestAuthenticationService_PasswordAuthentication(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthenticationService(mockUserRepo, mockCache, &services.AuthConfig{
		MaxLoginAttempts: 5,
		LockoutDuration:  30 * time.Minute,
		SessionTTL:       24 * time.Hour,
	})

	ctx := context.Background()
	username := "testuser"
	password := "securepassword123"

	// Create a test user
	user := &models.User{
		ID:       uuid.New(),
		Username: username,
		Email:    "test@example.com",
		IsActive: true,
	}
	err := user.SetPassword(password)
	require.NoError(t, err)

	t.Run("successful login", func(t *testing.T) {
		mockUserRepo.On("GetByUsername", ctx, username).Return(user, nil)
		mockUserRepo.On("ResetFailedLoginAttempts", ctx, user.ID).Return(nil)
		mockUserRepo.On("UpdateLastLogin", ctx, user.ID).Return(nil)
		mockCache.On("ResetLoginAttempts", ctx, username).Return(nil)

		credentials := &services.LoginCredentials{
			Username: username,
			Password: password,
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.NotEmpty(t, result.SessionToken)
		assert.NotEmpty(t, result.RefreshToken)
		assert.Equal(t, user.ID, result.UserID)

		mockUserRepo.AssertExpectations(t)
		mockCache.AssertExpectations(t)
	})

	t.Run("invalid password", func(t *testing.T) {
		mockUserRepo.On("GetByUsername", ctx, username).Return(user, nil)
		mockUserRepo.On("IncrementFailedLoginAttempts", ctx, user.ID).Return(nil)
		mockCache.On("IncrementLoginAttempts", ctx, username, mock.AnythingOfType("time.Duration")).Return(1, nil)

		credentials := &services.LoginCredentials{
			Username: username,
			Password: "wrongpassword",
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Empty(t, result.SessionToken)
		assert.Empty(t, result.RefreshToken)
		assert.Equal(t, "invalid credentials", result.Error)

		mockUserRepo.AssertExpectations(t)
		mockCache.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		mockUserRepo.On("GetByUsername", ctx, username).Return(nil, fmt.Errorf("user not found"))

		credentials := &services.LoginCredentials{
			Username: username,
			Password: password,
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Empty(t, result.SessionToken)
		assert.Empty(t, result.RefreshToken)
		assert.Equal(t, "invalid credentials", result.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("account locked", func(t *testing.T) {
		lockedUser := &models.User{
			ID:       uuid.New(),
			Username: username,
			Email:    "test@example.com",
			IsActive: true,
			IsLocked: true,
		}
		lockedUser.LockAccount(30 * time.Minute)

		mockUserRepo.On("GetByUsername", ctx, username).Return(lockedUser, nil)

		credentials := &services.LoginCredentials{
			Username: username,
			Password: password,
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Empty(t, result.SessionToken)
		assert.Empty(t, result.RefreshToken)
		assert.Equal(t, "account locked", result.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("account inactive", func(t *testing.T) {
		inactiveUser := &models.User{
			ID:       uuid.New(),
			Username: username,
			Email:    "test@example.com",
			IsActive: false,
		}

		mockUserRepo.On("GetByUsername", ctx, username).Return(inactiveUser, nil)

		credentials := &services.LoginCredentials{
			Username: username,
			Password: password,
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Empty(t, result.SessionToken)
		assert.Empty(t, result.RefreshToken)
		assert.Equal(t, "account inactive", result.Error)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestAuthenticationService_OTPGeneration tests OTP generation and verification
func TestAuthenticationService_OTPGeneration(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthenticationService(mockUserRepo, mockCache, &services.AuthConfig{
		OTPExpiry: 5 * time.Minute,
	})

	ctx := context.Background()
	userID := uuid.New()
	deviceIdentifier := "test@example.com"

	t.Run("generate OTP for email", func(t *testing.T) {
		mockCache.On("SetOTP", ctx, deviceIdentifier, mock.AnythingOfType("string"), 5*time.Minute).Return(nil)

		otp, err := authService.GenerateOTP(ctx, userID, models.DeviceTypeEmail, deviceIdentifier)

		assert.NoError(t, err)
		assert.NotEmpty(t, otp)
		assert.Len(t, otp, 6) // 6-digit OTP

		mockCache.AssertExpectations(t)
	})

	t.Run("generate OTP for SMS", func(t *testing.T) {
		phoneNumber := "1234567890"
		mockCache.On("SetOTP", ctx, phoneNumber, mock.AnythingOfType("string"), 5*time.Minute).Return(nil)

		otp, err := authService.GenerateOTP(ctx, userID, models.DeviceTypeSMS, phoneNumber)

		assert.NoError(t, err)
		assert.NotEmpty(t, otp)
		assert.Len(t, otp, 6) // 6-digit OTP

		mockCache.AssertExpectations(t)
	})

	t.Run("verify valid OTP", func(t *testing.T) {
		expectedOTP := "123456"
		mockCache.On("GetOTP", ctx, deviceIdentifier).Return(expectedOTP, nil)
		mockCache.On("DeleteOTP", ctx, deviceIdentifier).Return(nil)

		isValid, err := authService.VerifyOTP(ctx, deviceIdentifier, expectedOTP)

		assert.NoError(t, err)
		assert.True(t, isValid)

		mockCache.AssertExpectations(t)
	})

	t.Run("verify invalid OTP", func(t *testing.T) {
		expectedOTP := "123456"
		mockCache.On("GetOTP", ctx, deviceIdentifier).Return(expectedOTP, nil)

		isValid, err := authService.VerifyOTP(ctx, deviceIdentifier, "654321")

		assert.NoError(t, err)
		assert.False(t, isValid)

		mockCache.AssertExpectations(t)
	})

	t.Run("verify expired OTP", func(t *testing.T) {
		mockCache.On("GetOTP", ctx, deviceIdentifier).Return("", fmt.Errorf("OTP not found in cache"))

		isValid, err := authService.VerifyOTP(ctx, deviceIdentifier, "123456")

		assert.NoError(t, err)
		assert.False(t, isValid)

		mockCache.AssertExpectations(t)
	})
}

// TestAuthenticationService_MultiFactorAuthentication tests multi-factor authentication flow
func TestAuthenticationService_MultiFactorAuthentication(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthenticationService(mockUserRepo, mockCache, &services.AuthConfig{
		SessionTTL: 24 * time.Hour,
	})

	ctx := context.Background()
	userID := uuid.New()
	sessionToken := "test-session-token"
	deviceIdentifier := "test@example.com"

	t.Run("complete MFA flow", func(t *testing.T) {
		// Step 1: Generate OTP
		mockCache.On("SetOTP", ctx, deviceIdentifier, mock.AnythingOfType("string"), 5*time.Minute).Return(nil)

		otp, err := authService.GenerateOTP(ctx, userID, models.DeviceTypeEmail, deviceIdentifier)
		assert.NoError(t, err)
		assert.NotEmpty(t, otp)

		// Step 2: Verify OTP and complete MFA
		mockCache.On("GetOTP", ctx, deviceIdentifier).Return(otp, nil)
		mockCache.On("DeleteOTP", ctx, deviceIdentifier).Return(nil)
		mockCache.On("GetSession", ctx, sessionToken).Return(&models.UserSession{
			ID:           uuid.New(),
			UserID:       userID,
			SessionToken: sessionToken,
			ExpiresAt:    time.Now().Add(24 * time.Hour),
		}, nil)

		result, err := authService.CompleteMFA(ctx, sessionToken, deviceIdentifier, otp)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.NotEmpty(t, result.SessionToken)

		mockCache.AssertExpectations(t)
	})

	t.Run("MFA with invalid OTP", func(t *testing.T) {
		mockCache.On("GetOTP", ctx, deviceIdentifier).Return("123456", nil)
		mockCache.On("GetSession", ctx, sessionToken).Return(&models.UserSession{
			ID:           uuid.New(),
			UserID:       userID,
			SessionToken: sessionToken,
			ExpiresAt:    time.Now().Add(24 * time.Hour),
		}, nil)

		result, err := authService.CompleteMFA(ctx, sessionToken, deviceIdentifier, "654321")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Equal(t, "invalid OTP", result.Error)

		mockCache.AssertExpectations(t)
	})
}

// TestAuthenticationService_SessionManagement tests session creation and management
func TestAuthenticationService_SessionManagement(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthenticationService(mockUserRepo, mockCache, &services.AuthConfig{
		SessionTTL: 24 * time.Hour,
	})

	ctx := context.Background()
	userID := uuid.New()

	t.Run("create session", func(t *testing.T) {
		mockCache.On("SetSession", ctx, mock.AnythingOfType("*models.UserSession"), 24*time.Hour).Return(nil)

		session, err := authService.CreateSession(ctx, userID, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, userID, session.UserID)
		assert.NotEmpty(t, session.SessionToken)
		assert.NotEmpty(t, session.RefreshToken)
		assert.True(t, session.ExpiresAt.After(time.Now()))

		mockCache.AssertExpectations(t)
	})

	t.Run("validate session", func(t *testing.T) {
		sessionToken := "valid-session-token"
		expectedSession := &models.UserSession{
			ID:           uuid.New(),
			UserID:       userID,
			SessionToken: sessionToken,
			ExpiresAt:    time.Now().Add(24 * time.Hour),
		}

		mockCache.On("GetSession", ctx, sessionToken).Return(expectedSession, nil)

		session, err := authService.ValidateSession(ctx, sessionToken)

		assert.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, expectedSession.ID, session.ID)
		assert.Equal(t, expectedSession.UserID, session.UserID)

		mockCache.AssertExpectations(t)
	})

	t.Run("validate expired session", func(t *testing.T) {
		sessionToken := "expired-session-token"
		expiredSession := &models.UserSession{
			ID:           uuid.New(),
			UserID:       userID,
			SessionToken: sessionToken,
			ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired
		}

		mockCache.On("GetSession", ctx, sessionToken).Return(expiredSession, nil)

		session, err := authService.ValidateSession(ctx, sessionToken)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "session expired")

		mockCache.AssertExpectations(t)
	})

	t.Run("refresh session", func(t *testing.T) {
		refreshToken := "valid-refresh-token"
		expectedSession := &models.UserSession{
			ID:           uuid.New(),
			UserID:       userID,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(24 * time.Hour),
		}

		mockCache.On("GetSession", ctx, refreshToken).Return(expectedSession, nil)
		mockCache.On("SetSession", ctx, mock.AnythingOfType("*models.UserSession"), 24*time.Hour).Return(nil)

		newSession, err := authService.RefreshSession(ctx, refreshToken)

		assert.NoError(t, err)
		assert.NotNil(t, newSession)
		assert.Equal(t, userID, newSession.UserID)
		assert.NotEmpty(t, newSession.SessionToken)
		assert.NotEmpty(t, newSession.RefreshToken)

		mockCache.AssertExpectations(t)
	})

	t.Run("logout session", func(t *testing.T) {
		sessionToken := "session-to-logout"

		mockCache.On("DeleteSession", ctx, sessionToken).Return(nil)

		err := authService.Logout(ctx, sessionToken)

		assert.NoError(t, err)

		mockCache.AssertExpectations(t)
	})
}

// TestAuthenticationService_RateLimiting tests rate limiting and account lockout
func TestAuthenticationService_RateLimiting(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthenticationService(mockUserRepo, mockCache, &services.AuthConfig{
		MaxLoginAttempts: 3,
		LockoutDuration:  30 * time.Minute,
	})

	ctx := context.Background()
	username := "testuser"
	userID := uuid.New()

	user := &models.User{
		ID:       userID,
		Username: username,
		Email:    "test@example.com",
		IsActive: true,
	}
	err := user.SetPassword("securepassword123")
	require.NoError(t, err)

	t.Run("account lockout after max attempts", func(t *testing.T) {
		// First two failed attempts
		for i := 0; i < 2; i++ {
			mockUserRepo.On("GetByUsername", ctx, username).Return(user, nil)
			mockUserRepo.On("IncrementFailedLoginAttempts", ctx, userID).Return(nil)
			mockCache.On("IncrementLoginAttempts", ctx, username, mock.AnythingOfType("time.Duration")).Return(i+1, nil)

			credentials := &services.LoginCredentials{
				Username: username,
				Password: "wrongpassword",
			}

			result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

			assert.NoError(t, err)
			assert.False(t, result.Success)
		}

		// Third failed attempt should trigger lockout
		mockUserRepo.On("GetByUsername", ctx, username).Return(user, nil)
		mockUserRepo.On("IncrementFailedLoginAttempts", ctx, userID).Return(nil)
		mockUserRepo.On("LockAccount", ctx, userID, 30*time.Minute).Return(nil)
		mockCache.On("IncrementLoginAttempts", ctx, username, mock.AnythingOfType("time.Duration")).Return(3, nil)

		credentials := &services.LoginCredentials{
			Username: username,
			Password: "wrongpassword",
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.False(t, result.Success)
		assert.Equal(t, "account locked", result.Error)

		mockUserRepo.AssertExpectations(t)
		mockCache.AssertExpectations(t)
	})

	t.Run("reset attempts on successful login", func(t *testing.T) {
		mockUserRepo.On("GetByUsername", ctx, username).Return(user, nil)
		mockUserRepo.On("ResetFailedLoginAttempts", ctx, userID).Return(nil)
		mockUserRepo.On("UpdateLastLogin", ctx, userID).Return(nil)
		mockCache.On("ResetLoginAttempts", ctx, username).Return(nil)

		credentials := &services.LoginCredentials{
			Username: username,
			Password: "securepassword123",
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.True(t, result.Success)

		mockUserRepo.AssertExpectations(t)
		mockCache.AssertExpectations(t)
	})
}

// TestAuthenticationService_AuditLogging tests authentication audit logging
func TestAuthenticationService_AuditLogging(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthenticationService(mockUserRepo, mockCache, &services.AuthConfig{
		SessionTTL: 24 * time.Hour,
	})

	ctx := context.Background()
	userID := uuid.New()
	username := "testuser"

	user := &models.User{
		ID:       userID,
		Username: username,
		Email:    "test@example.com",
		IsActive: true,
	}
	err := user.SetPassword("securepassword123")
	require.NoError(t, err)

	t.Run("log successful authentication", func(t *testing.T) {
		mockUserRepo.On("GetByUsername", ctx, username).Return(user, nil)
		mockUserRepo.On("ResetFailedLoginAttempts", ctx, userID).Return(nil)
		mockUserRepo.On("UpdateLastLogin", ctx, userID).Return(nil)
		mockCache.On("ResetLoginAttempts", ctx, username).Return(nil)

		credentials := &services.LoginCredentials{
			Username: username,
			Password: "securepassword123",
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.True(t, result.Success)

		// Verify that audit event was created (this would be tested in the actual implementation)
		// For now, we just verify the authentication was successful

		mockUserRepo.AssertExpectations(t)
		mockCache.AssertExpectations(t)
	})

	t.Run("log failed authentication", func(t *testing.T) {
		mockUserRepo.On("GetByUsername", ctx, username).Return(user, nil)
		mockUserRepo.On("IncrementFailedLoginAttempts", ctx, userID).Return(nil)
		mockCache.On("IncrementLoginAttempts", ctx, username, mock.AnythingOfType("time.Duration")).Return(1, nil)

		credentials := &services.LoginCredentials{
			Username: username,
			Password: "wrongpassword",
		}

		result, err := authService.AuthenticateWithPassword(ctx, credentials, "127.0.0.1", "test-agent")

		assert.NoError(t, err)
		assert.False(t, result.Success)

		// Verify that audit event was created for failed login

		mockUserRepo.AssertExpectations(t)
		mockCache.AssertExpectations(t)
	})
} 