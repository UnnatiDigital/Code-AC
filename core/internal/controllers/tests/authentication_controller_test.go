package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"
)

// MockAuthenticationService is a mock implementation of AuthenticationService
type MockAuthenticationService struct {
	mock.Mock
}

func (m *MockAuthenticationService) AuthenticateWithPassword(ctx context.Context, credentials *services.LoginCredentials, ipAddress, userAgent string) (*services.AuthenticationResult, error) {
	args := m.Called(ctx, credentials, ipAddress, userAgent)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticationService) AuthenticateWithBiometric(ctx context.Context, biometricData *services.BiometricData, ipAddress, userAgent string) (*services.AuthenticationResult, error) {
	args := m.Called(ctx, biometricData, ipAddress, userAgent)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticationService) GenerateOTP(ctx context.Context, userID uuid.UUID, deviceType models.DeviceType, deviceIdentifier string) (string, error) {
	args := m.Called(ctx, userID, deviceType, deviceIdentifier)
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticationService) VerifyOTP(ctx context.Context, deviceIdentifier, otp string) (bool, error) {
	args := m.Called(ctx, deviceIdentifier, otp)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthenticationService) CompleteMFA(ctx context.Context, sessionToken, deviceIdentifier, otp string) (*services.AuthenticationResult, error) {
	args := m.Called(ctx, sessionToken, deviceIdentifier, otp)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticationService) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*models.UserSession, error) {
	args := m.Called(ctx, userID, ipAddress, userAgent)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserSession), args.Error(1)
}

func (m *MockAuthenticationService) ValidateSession(ctx context.Context, sessionToken string) (*models.UserSession, error) {
	args := m.Called(ctx, sessionToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserSession), args.Error(1)
}

func (m *MockAuthenticationService) RefreshSession(ctx context.Context, refreshToken string) (*models.UserSession, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserSession), args.Error(1)
}

func (m *MockAuthenticationService) Logout(ctx context.Context, sessionToken string) error {
	args := m.Called(ctx, sessionToken)
	return args.Error(0)
}

func (m *MockAuthenticationService) LockAccount(ctx context.Context, userID uuid.UUID, duration time.Duration) error {
	args := m.Called(ctx, userID, duration)
	return args.Error(0)
}

func (m *MockAuthenticationService) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthenticationService) ResetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	args := m.Called(ctx, userID, newPassword)
	return args.Error(0)
}

func (m *MockAuthenticationService) LogAuthenticationEvent(ctx context.Context, event *models.AuthenticationEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

// TestAuthenticationController_Login tests the login endpoint
func TestAuthenticationController_Login(t *testing.T) {
	mockAuthService := new(MockAuthenticationService)
	controller := NewAuthenticationController(mockAuthService)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	t.Run("successful login", func(t *testing.T) {
		// Setup test data
		userID := uuid.New()
		sessionToken := "test-session-token"
		refreshToken := "test-refresh-token"
		expiresAt := time.Now().Add(24 * time.Hour)

		loginRequest := map[string]interface{}{
			"username": "testuser",
			"password": "securepassword123",
		}

		expectedResult := &services.AuthenticationResult{
			Success:      true,
			UserID:       userID,
			SessionToken: sessionToken,
			RefreshToken: refreshToken,
			ExpiresAt:    expiresAt,
			RequiresMFA:  false,
		}

		// Setup mock expectations
		mockAuthService.On("AuthenticateWithPassword", mock.Anything, mock.AnythingOfType("*services.LoginCredentials"), "127.0.0.1", "test-agent").Return(expectedResult, nil)

		// Create request
		jsonData, _ := json.Marshal(loginRequest)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Login(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["success"])
		assert.Equal(t, userID.String(), response["user_id"])
		assert.Equal(t, sessionToken, response["session_token"])
		assert.Equal(t, refreshToken, response["refresh_token"])
		assert.Equal(t, false, response["requires_mfa"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		loginRequest := map[string]interface{}{
			"username": "testuser",
			"password": "wrongpassword",
		}

		expectedResult := &services.AuthenticationResult{
			Success:   false,
			Error:     "invalid credentials",
			ErrorCode: "INVALID_CREDENTIALS",
		}

		// Setup mock expectations
		mockAuthService.On("AuthenticateWithPassword", mock.Anything, mock.AnythingOfType("*services.LoginCredentials"), "127.0.0.1", "test-agent").Return(expectedResult, nil)

		// Create request
		jsonData, _ := json.Marshal(loginRequest)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Login(c)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Equal(t, "invalid credentials", response["error"])
		assert.Equal(t, "INVALID_CREDENTIALS", response["error_code"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("account locked", func(t *testing.T) {
		loginRequest := map[string]interface{}{
			"username": "lockeduser",
			"password": "securepassword123",
		}

		expectedResult := &services.AuthenticationResult{
			Success:   false,
			Error:     "account locked",
			ErrorCode: "ACCOUNT_LOCKED",
		}

		// Setup mock expectations
		mockAuthService.On("AuthenticateWithPassword", mock.Anything, mock.AnythingOfType("*services.LoginCredentials"), "127.0.0.1", "test-agent").Return(expectedResult, nil)

		// Create request
		jsonData, _ := json.Marshal(loginRequest)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Login(c)

		// Assertions
		assert.Equal(t, http.StatusForbidden, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Equal(t, "account locked", response["error"])
		assert.Equal(t, "ACCOUNT_LOCKED", response["error_code"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("requires MFA", func(t *testing.T) {
		userID := uuid.New()
		sessionToken := "test-session-token"
		refreshToken := "test-refresh-token"
		expiresAt := time.Now().Add(24 * time.Hour)

		loginRequest := map[string]interface{}{
			"username": "mfauser",
			"password": "securepassword123",
		}

		expectedResult := &services.AuthenticationResult{
			Success:      true,
			UserID:       userID,
			SessionToken: sessionToken,
			RefreshToken: refreshToken,
			ExpiresAt:    expiresAt,
			RequiresMFA:  true,
		}

		// Setup mock expectations
		mockAuthService.On("AuthenticateWithPassword", mock.Anything, mock.AnythingOfType("*services.LoginCredentials"), "127.0.0.1", "test-agent").Return(expectedResult, nil)

		// Create request
		jsonData, _ := json.Marshal(loginRequest)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Login(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["success"])
		assert.Equal(t, true, response["requires_mfa"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("invalid request body", func(t *testing.T) {
		// Create request with invalid JSON
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Login(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "invalid request body")
	})

	t.Run("missing required fields", func(t *testing.T) {
		loginRequest := map[string]interface{}{
			"username": "testuser",
			// password missing
		}

		// Create request
		jsonData, _ := json.Marshal(loginRequest)
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Login(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "password is required")
	})
}

// TestAuthenticationController_Logout tests the logout endpoint
func TestAuthenticationController_Logout(t *testing.T) {
	mockAuthService := new(MockAuthenticationService)
	controller := NewAuthenticationController(mockAuthService)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	t.Run("successful logout", func(t *testing.T) {
		sessionToken := "test-session-token"

		// Setup mock expectations
		mockAuthService.On("Logout", mock.Anything, sessionToken).Return(nil)

		// Create request
		req, _ := http.NewRequest("POST", "/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+sessionToken)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Logout(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["success"])
		assert.Equal(t, "logged out successfully", response["message"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("missing authorization header", func(t *testing.T) {
		// Create request without authorization header
		req, _ := http.NewRequest("POST", "/auth/logout", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Logout(c)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Equal(t, "missing authorization header", response["error"])
	})

	t.Run("invalid authorization format", func(t *testing.T) {
		// Create request with invalid authorization format
		req, _ := http.NewRequest("POST", "/auth/logout", nil)
		req.Header.Set("Authorization", "InvalidFormat token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.Logout(c)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Equal(t, "invalid authorization format", response["error"])
	})
}

// TestAuthenticationController_GenerateOTP tests the OTP generation endpoint
func TestAuthenticationController_GenerateOTP(t *testing.T) {
	mockAuthService := new(MockAuthenticationService)
	controller := NewAuthenticationController(mockAuthService)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	t.Run("successful OTP generation", func(t *testing.T) {
		userID := uuid.New()
		deviceType := models.DeviceTypeEmail
		deviceIdentifier := "test@example.com"
		otp := "123456"

		otpRequest := map[string]interface{}{
			"device_type":      string(deviceType),
			"device_identifier": deviceIdentifier,
		}

		// Setup mock expectations
		mockAuthService.On("GenerateOTP", mock.Anything, userID, deviceType, deviceIdentifier).Return(otp, nil)

		// Create request
		jsonData, _ := json.Marshal(otpRequest)
		req, _ := http.NewRequest("POST", "/auth/otp/generate", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-session-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Mock user ID in context (would be set by auth middleware)
		c.Set("user_id", userID)

		// Call controller method
		controller.GenerateOTP(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["success"])
		assert.Equal(t, otp, response["otp"])
		assert.Equal(t, string(deviceType), response["device_type"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("invalid device type", func(t *testing.T) {
		otpRequest := map[string]interface{}{
			"device_type":      "invalid_type",
			"device_identifier": "test@example.com",
		}

		// Create request
		jsonData, _ := json.Marshal(otpRequest)
		req, _ := http.NewRequest("POST", "/auth/otp/generate", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-session-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.GenerateOTP(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "invalid device type")
	})

	t.Run("missing device identifier", func(t *testing.T) {
		otpRequest := map[string]interface{}{
			"device_type": string(models.DeviceTypeEmail),
			// device_identifier missing
		}

		// Create request
		jsonData, _ := json.Marshal(otpRequest)
		req, _ := http.NewRequest("POST", "/auth/otp/generate", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-session-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.GenerateOTP(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "device identifier is required")
	})
}

// TestAuthenticationController_CompleteMFA tests the MFA completion endpoint
func TestAuthenticationController_CompleteMFA(t *testing.T) {
	mockAuthService := new(MockAuthenticationService)
	controller := NewAuthenticationController(mockAuthService)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	t.Run("successful MFA completion", func(t *testing.T) {
		userID := uuid.New()
		sessionToken := "test-session-token"
		refreshToken := "test-refresh-token"
		expiresAt := time.Now().Add(24 * time.Hour)

		mfaRequest := map[string]interface{}{
			"device_identifier": "test@example.com",
			"otp":              "123456",
		}

		expectedResult := &services.AuthenticationResult{
			Success:      true,
			UserID:       userID,
			SessionToken: sessionToken,
			RefreshToken: refreshToken,
			ExpiresAt:    expiresAt,
			RequiresMFA:  false,
		}

		// Setup mock expectations
		mockAuthService.On("CompleteMFA", mock.Anything, sessionToken, "test@example.com", "123456").Return(expectedResult, nil)

		// Create request
		jsonData, _ := json.Marshal(mfaRequest)
		req, _ := http.NewRequest("POST", "/auth/mfa/complete", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sessionToken)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.CompleteMFA(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["success"])
		assert.Equal(t, userID.String(), response["user_id"])
		assert.Equal(t, sessionToken, response["session_token"])
		assert.Equal(t, refreshToken, response["refresh_token"])
		assert.Equal(t, false, response["requires_mfa"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("invalid OTP", func(t *testing.T) {
		sessionToken := "test-session-token"

		mfaRequest := map[string]interface{}{
			"device_identifier": "test@example.com",
			"otp":              "wrong-otp",
		}

		expectedResult := &services.AuthenticationResult{
			Success:   false,
			Error:     "invalid OTP",
			ErrorCode: "INVALID_OTP",
		}

		// Setup mock expectations
		mockAuthService.On("CompleteMFA", mock.Anything, sessionToken, "test@example.com", "wrong-otp").Return(expectedResult, nil)

		// Create request
		jsonData, _ := json.Marshal(mfaRequest)
		req, _ := http.NewRequest("POST", "/auth/mfa/complete", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sessionToken)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.CompleteMFA(c)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Equal(t, "invalid OTP", response["error"])
		assert.Equal(t, "INVALID_OTP", response["error_code"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("missing OTP", func(t *testing.T) {
		mfaRequest := map[string]interface{}{
			"device_identifier": "test@example.com",
			// otp missing
		}

		// Create request
		jsonData, _ := json.Marshal(mfaRequest)
		req, _ := http.NewRequest("POST", "/auth/mfa/complete", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-session-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.CompleteMFA(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "OTP is required")
	})
}

// TestAuthenticationController_RefreshSession tests the session refresh endpoint
func TestAuthenticationController_RefreshSession(t *testing.T) {
	mockAuthService := new(MockAuthenticationService)
	controller := NewAuthenticationController(mockAuthService)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	t.Run("successful session refresh", func(t *testing.T) {
		userID := uuid.New()
		refreshToken := "test-refresh-token"
		newSessionToken := "new-session-token"
		newRefreshToken := "new-refresh-token"
		expiresAt := time.Now().Add(24 * time.Hour)

		refreshRequest := map[string]interface{}{
			"refresh_token": refreshToken,
		}

		newSession := &models.UserSession{
			UserID:       userID,
			SessionToken: newSessionToken,
			RefreshToken: newRefreshToken,
			ExpiresAt:    expiresAt,
		}

		// Setup mock expectations
		mockAuthService.On("RefreshSession", mock.Anything, refreshToken).Return(newSession, nil)

		// Create request
		jsonData, _ := json.Marshal(refreshRequest)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.RefreshSession(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["success"])
		assert.Equal(t, newSessionToken, response["session_token"])
		assert.Equal(t, newRefreshToken, response["refresh_token"])
		assert.Equal(t, userID.String(), response["user_id"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		refreshToken := "invalid-refresh-token"

		refreshRequest := map[string]interface{}{
			"refresh_token": refreshToken,
		}

		// Setup mock expectations
		mockAuthService.On("RefreshSession", mock.Anything, refreshToken).Return(nil, fmt.Errorf("invalid refresh token"))

		// Create request
		jsonData, _ := json.Marshal(refreshRequest)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.RefreshSession(c)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "invalid refresh token")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("missing refresh token", func(t *testing.T) {
		refreshRequest := map[string]interface{}{
			// refresh_token missing
		}

		// Create request
		jsonData, _ := json.Marshal(refreshRequest)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.RefreshSession(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "refresh token is required")
	})
}

// TestAuthenticationController_ValidateSession tests the session validation endpoint
func TestAuthenticationController_ValidateSession(t *testing.T) {
	mockAuthService := new(MockAuthenticationService)
	controller := NewAuthenticationController(mockAuthService)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	t.Run("valid session", func(t *testing.T) {
		userID := uuid.New()
		sessionToken := "test-session-token"

		session := &models.UserSession{
			UserID:       userID,
			SessionToken: sessionToken,
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}

		// Setup mock expectations
		mockAuthService.On("ValidateSession", mock.Anything, sessionToken).Return(session, nil)

		// Create request
		req, _ := http.NewRequest("GET", "/auth/validate", nil)
		req.Header.Set("Authorization", "Bearer "+sessionToken)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.ValidateSession(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["success"])
		assert.Equal(t, userID.String(), response["user_id"])
		assert.Equal(t, sessionToken, response["session_token"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("expired session", func(t *testing.T) {
		sessionToken := "expired-session-token"

		// Setup mock expectations
		mockAuthService.On("ValidateSession", mock.Anything, sessionToken).Return(nil, fmt.Errorf("session expired"))

		// Create request
		req, _ := http.NewRequest("GET", "/auth/validate", nil)
		req.Header.Set("Authorization", "Bearer "+sessionToken)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.ValidateSession(c)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "session expired")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("missing authorization header", func(t *testing.T) {
		// Create request without authorization header
		req, _ := http.NewRequest("GET", "/auth/validate", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.ValidateSession(c)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Equal(t, "missing authorization header", response["error"])
	})
}

// TestAuthenticationController_BiometricLogin tests the biometric login endpoint
func TestAuthenticationController_BiometricLogin(t *testing.T) {
	mockAuthService := new(MockAuthenticationService)
	controller := NewAuthenticationController(mockAuthService)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	t.Run("successful biometric login", func(t *testing.T) {
		userID := uuid.New()
		sessionToken := "test-session-token"
		refreshToken := "test-refresh-token"
		expiresAt := time.Now().Add(24 * time.Hour)

		biometricRequest := map[string]interface{}{
			"user_id":         userID.String(),
			"biometric_type":  "fingerprint",
			"data":            "base64-encoded-biometric-data",
			"device_id":       "device-123",
			"quality":         0.95,
		}

		expectedResult := &services.AuthenticationResult{
			Success:      true,
			UserID:       userID,
			SessionToken: sessionToken,
			RefreshToken: refreshToken,
			ExpiresAt:    expiresAt,
			RequiresMFA:  false,
		}

		// Setup mock expectations
		mockAuthService.On("AuthenticateWithBiometric", mock.Anything, mock.AnythingOfType("*services.BiometricData"), "127.0.0.1", "test-agent").Return(expectedResult, nil)

		// Create request
		jsonData, _ := json.Marshal(biometricRequest)
		req, _ := http.NewRequest("POST", "/auth/biometric", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.BiometricLogin(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["success"])
		assert.Equal(t, userID.String(), response["user_id"])
		assert.Equal(t, sessionToken, response["session_token"])
		assert.Equal(t, refreshToken, response["refresh_token"])
		assert.Equal(t, false, response["requires_mfa"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("invalid biometric data", func(t *testing.T) {
		biometricRequest := map[string]interface{}{
			"user_id":        uuid.New().String(),
			"biometric_type": "invalid_type",
			"data":           "base64-encoded-biometric-data",
		}

		expectedResult := &services.AuthenticationResult{
			Success:   false,
			Error:     "invalid biometric data",
			ErrorCode: "INVALID_BIOMETRIC_DATA",
		}

		// Setup mock expectations
		mockAuthService.On("AuthenticateWithBiometric", mock.Anything, mock.AnythingOfType("*services.BiometricData"), "127.0.0.1", "test-agent").Return(expectedResult, nil)

		// Create request
		jsonData, _ := json.Marshal(biometricRequest)
		req, _ := http.NewRequest("POST", "/auth/biometric", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.BiometricLogin(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Equal(t, "invalid biometric data", response["error"])
		assert.Equal(t, "INVALID_BIOMETRIC_DATA", response["error_code"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("missing required fields", func(t *testing.T) {
		biometricRequest := map[string]interface{}{
			"biometric_type": "fingerprint",
			// user_id and data missing
		}

		// Create request
		jsonData, _ := json.Marshal(biometricRequest)
		req, _ := http.NewRequest("POST", "/auth/biometric", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call controller method
		controller.BiometricLogin(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["success"])
		assert.Contains(t, response["error"], "user ID is required")
	})
}

// Helper function to create authentication controller (this would be implemented in the actual controller)
func NewAuthenticationController(authService services.AuthenticationService) *AuthenticationController {
	return &AuthenticationController{
		authService: authService,
	}
}

// AuthenticationController is a placeholder for the actual controller implementation
type AuthenticationController struct {
	authService services.AuthenticationService
}

// These methods are placeholders for the actual controller implementation
// In a real implementation, these would be the actual HTTP handlers

func (c *AuthenticationController) Login(ctx *gin.Context) {
	// Placeholder implementation
	ctx.JSON(http.StatusOK, gin.H{"message": "login endpoint"})
}

func (c *AuthenticationController) Logout(ctx *gin.Context) {
	// Placeholder implementation
	ctx.JSON(http.StatusOK, gin.H{"message": "logout endpoint"})
}

func (c *AuthenticationController) GenerateOTP(ctx *gin.Context) {
	// Placeholder implementation
	ctx.JSON(http.StatusOK, gin.H{"message": "generate OTP endpoint"})
}

func (c *AuthenticationController) CompleteMFA(ctx *gin.Context) {
	// Placeholder implementation
	ctx.JSON(http.StatusOK, gin.H{"message": "complete MFA endpoint"})
}

func (c *AuthenticationController) RefreshSession(ctx *gin.Context) {
	// Placeholder implementation
	ctx.JSON(http.StatusOK, gin.H{"message": "refresh session endpoint"})
}

func (c *AuthenticationController) ValidateSession(ctx *gin.Context) {
	// Placeholder implementation
	ctx.JSON(http.StatusOK, gin.H{"message": "validate session endpoint"})
}

func (c *AuthenticationController) BiometricLogin(ctx *gin.Context) {
	// Placeholder implementation
	ctx.JSON(http.StatusOK, gin.H{"message": "biometric login endpoint"})
} 