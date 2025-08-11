package services

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/repositories"
	"github.com/google/uuid"
)

// AuthenticationService implements the authentication service
type AuthenticationService struct {
	userRepo    repositories.UserRepository
	cache       Cache
	config      *AuthConfig
	auditRepo   repositories.AuditRepository
	otpRepo     repositories.UserOTPDeviceRepository
	sessionRepo repositories.UserSessionRepository
}

// NewAuthenticationService creates a new authentication service instance
func NewAuthenticationService(
	userRepo repositories.UserRepository,
	cache Cache,
	config *AuthConfig,
	auditRepo repositories.AuditRepository,
	otpRepo repositories.UserOTPDeviceRepository,
	sessionRepo repositories.UserSessionRepository,
) *AuthenticationService {
	return &AuthenticationService{
		userRepo:    userRepo,
		cache:       cache,
		config:      config,
		auditRepo:   auditRepo,
		otpRepo:     otpRepo,
		sessionRepo: sessionRepo,
	}
}

// AuthenticateWithPassword authenticates a user with username and password
func (s *AuthenticationService) AuthenticateWithPassword(
	ctx context.Context,
	credentials *LoginCredentials,
	ipAddress, userAgent string,
) (*AuthenticationResult, error) {
	// Validate credentials
	if err := s.validateCredentials(credentials); err != nil {
		return s.createFailedResult("invalid credentials", "INVALID_CREDENTIALS"), nil
	}

	// Check rate limiting
	if err := s.checkRateLimit(ctx, credentials.Username); err != nil {
		return s.createFailedResult("rate limit exceeded", "RATE_LIMIT_EXCEEDED"), nil
	}

	// Get user by username
	user, err := s.userRepo.GetByUsername(ctx, credentials.Username)
	if err != nil {
		// Log failed attempt for non-existent user
		s.logAuthenticationEvent(ctx, nil, "failed_login", "password", ipAddress, userAgent, false, "user not found")
		return s.createFailedResult("invalid credentials", "INVALID_CREDENTIALS"), nil
	}

	// Check if account is locked
	if user.IsAccountLocked() {
		s.logAuthenticationEvent(ctx, &user.ID, "failed_login", "password", ipAddress, userAgent, false, "account locked")
		return s.createFailedResult("account locked", "ACCOUNT_LOCKED"), nil
	}

	// Check if account is active
	if !user.IsActive {
		s.logAuthenticationEvent(ctx, &user.ID, "failed_login", "password", ipAddress, userAgent, false, "account inactive")
		return s.createFailedResult("account inactive", "ACCOUNT_INACTIVE"), nil
	}

	// Verify password
	if !user.CheckPassword(credentials.Password) {
		// Increment failed login attempts
		s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID)
		s.cache.IncrementLoginAttempts(ctx, credentials.Username, s.config.RateLimitWindow)

		// Check if account should be locked
		if user.FailedLoginAttempts >= s.config.MaxLoginAttempts {
			s.userRepo.LockAccount(ctx, user.ID, s.config.LockoutDuration)
			s.logAuthenticationEvent(ctx, &user.ID, "account_locked", "password", ipAddress, userAgent, false, "max failed attempts")
			return s.createFailedResult("account locked", "ACCOUNT_LOCKED"), nil
		}

		s.logAuthenticationEvent(ctx, &user.ID, "failed_login", "password", ipAddress, userAgent, false, "invalid password")
		return s.createFailedResult("invalid credentials", "INVALID_CREDENTIALS"), nil
	}

	// Reset failed login attempts on successful login
	s.userRepo.ResetFailedLoginAttempts(ctx, user.ID)
	s.cache.ResetLoginAttempts(ctx, credentials.Username)

	// Update last login
	s.userRepo.UpdateLastLogin(ctx, user.ID)

	// Create session
	session, err := s.CreateSession(ctx, user.ID, ipAddress, userAgent)
	if err != nil {
		return s.createFailedResult("failed to create session", "SESSION_CREATION_FAILED"), err
	}

	// Log successful authentication
	s.logAuthenticationEvent(ctx, &user.ID, "login", "password", ipAddress, userAgent, true, "")

	// Check if MFA is required
	requiresMFA := s.checkMFARequirement(ctx, user.ID)

	return &AuthenticationResult{
		Success:      true,
		UserID:       user.ID,
		SessionToken: session.SessionToken,
		RefreshToken: session.RefreshToken,
		ExpiresAt:    session.ExpiresAt,
		RequiresMFA:  requiresMFA,
		Metadata: map[string]interface{}{
			"username": user.Username,
			"email":    user.Email,
		},
	}, nil
}

// AuthenticateWithBiometric authenticates a user with biometric data
func (s *AuthenticationService) AuthenticateWithBiometric(
	ctx context.Context,
	biometricData *BiometricData,
	ipAddress, userAgent string,
) (*AuthenticationResult, error) {
	// Validate biometric data
	if err := s.validateBiometricData(biometricData); err != nil {
		return s.createFailedResult("invalid biometric data", "INVALID_BIOMETRIC_DATA"), nil
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, biometricData.UserID)
	if err != nil {
		return s.createFailedResult("user not found", "USER_NOT_FOUND"), nil
	}

	// Check if account is locked or inactive
	if user.IsAccountLocked() || !user.IsActive {
		return s.createFailedResult("account not accessible", "ACCOUNT_NOT_ACCESSIBLE"), nil
	}

	// Verify biometric data (this would integrate with actual biometric verification service)
	verified, err := s.verifyBiometric(ctx, biometricData)
	if err != nil {
		return s.createFailedResult("biometric verification failed", "BIOMETRIC_VERIFICATION_FAILED"), err
	}

	if !verified {
		s.logAuthenticationEvent(ctx, &user.ID, "failed_login", "biometric", ipAddress, userAgent, false, "biometric verification failed")
		return s.createFailedResult("biometric verification failed", "BIOMETRIC_VERIFICATION_FAILED"), nil
	}

	// Update last login
	s.userRepo.UpdateLastLogin(ctx, user.ID)

	// Create session
	session, err := s.CreateSession(ctx, user.ID, ipAddress, userAgent)
	if err != nil {
		return s.createFailedResult("failed to create session", "SESSION_CREATION_FAILED"), err
	}

	// Log successful authentication
	s.logAuthenticationEvent(ctx, &user.ID, "login", "biometric", ipAddress, userAgent, true, "")

	return &AuthenticationResult{
		Success:      true,
		UserID:       user.ID,
		SessionToken: session.SessionToken,
		RefreshToken: session.RefreshToken,
		ExpiresAt:    session.ExpiresAt,
		RequiresMFA:  false, // Biometric is considered MFA
		Metadata: map[string]interface{}{
			"username":      user.Username,
			"biometric_type": biometricData.BiometricType,
			"device_id":     biometricData.DeviceID,
		},
	}, nil
}

// GenerateOTP generates an OTP for the specified device
func (s *AuthenticationService) GenerateOTP(
	ctx context.Context,
	userID uuid.UUID,
	deviceType models.DeviceType,
	deviceIdentifier string,
) (string, error) {
	// Validate device type and identifier
	if err := s.validateOTPDevice(deviceType, deviceIdentifier); err != nil {
		return "", fmt.Errorf("invalid OTP device: %w", err)
	}

	// Generate OTP
	otp := s.generateRandomOTP(s.config.OTPLength)

	// Store OTP in cache
	err := s.cache.SetOTP(ctx, deviceIdentifier, otp, s.config.OTPExpiry)
	if err != nil {
		return "", fmt.Errorf("failed to store OTP: %w", err)
	}

	// Log OTP generation
	s.logAuthenticationEvent(ctx, &userID, "otp_generated", string(deviceType), "", "", true, "")

	return otp, nil
}

// VerifyOTP verifies an OTP for the specified device
func (s *AuthenticationService) VerifyOTP(ctx context.Context, deviceIdentifier, otp string) (bool, error) {
	// Get OTP from cache
	storedOTP, err := s.cache.GetOTP(ctx, deviceIdentifier)
	if err != nil {
		return false, nil // OTP not found or expired
	}

	// Compare OTPs
	if storedOTP != otp {
		return false, nil
	}

	// Delete OTP from cache after successful verification
	s.cache.DeleteOTP(ctx, deviceIdentifier)

	return true, nil
}

// CompleteMFA completes multi-factor authentication
func (s *AuthenticationService) CompleteMFA(
	ctx context.Context,
	sessionToken, deviceIdentifier, otp string,
) (*AuthenticationResult, error) {
	// Get session from cache
	session, err := s.cache.GetSession(ctx, sessionToken)
	if err != nil {
		return s.createFailedResult("invalid session", "INVALID_SESSION"), nil
	}

	// Verify OTP
	verified, err := s.VerifyOTP(ctx, deviceIdentifier, otp)
	if err != nil {
		return s.createFailedResult("OTP verification failed", "OTP_VERIFICATION_FAILED"), err
	}

	if !verified {
		s.logAuthenticationEvent(ctx, &session.UserID, "failed_login", "mfa", "", "", false, "invalid OTP")
		return s.createFailedResult("invalid OTP", "INVALID_OTP"), nil
	}

	// Update session to mark MFA as completed
	session.UpdateLastAccessed()
	err = s.cache.SetSession(ctx, session, s.config.SessionTTL)
	if err != nil {
		return s.createFailedResult("failed to update session", "SESSION_UPDATE_FAILED"), err
	}

	// Log successful MFA
	s.logAuthenticationEvent(ctx, &session.UserID, "mfa_completed", "otp", "", "", true, "")

	return &AuthenticationResult{
		Success:      true,
		UserID:       session.UserID,
		SessionToken: session.SessionToken,
		RefreshToken: session.RefreshToken,
		ExpiresAt:    session.ExpiresAt,
		RequiresMFA:  false,
	}, nil
}

// CreateSession creates a new user session
func (s *AuthenticationService) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	ipAddress, userAgent string,
) (*models.UserSession, error) {
	// Generate session tokens
	sessionToken := s.generateSessionToken()
	refreshToken := s.generateRefreshToken()

	// Create session
	session := &models.UserSession{
		UserID:       userID,
		SessionToken: sessionToken,
		RefreshToken: refreshToken,
		IPAddress:    &ipAddress,
		UserAgent:    &userAgent,
		ExpiresAt:    time.Now().Add(s.config.SessionTTL),
	}

	// Store session in cache
	err := s.cache.SetSession(ctx, session, s.config.SessionTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Store session in database
	err = s.sessionRepo.Create(ctx, session)
	if err != nil {
		// Clean up cache if database storage fails
		s.cache.DeleteSession(ctx, sessionToken)
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// ValidateSession validates a session token
func (s *AuthenticationService) ValidateSession(ctx context.Context, sessionToken string) (*models.UserSession, error) {
	// Get session from cache
	session, err := s.cache.GetSession(ctx, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Check if session is expired
	if session.IsExpired() {
		// Clean up expired session
		s.cache.DeleteSession(ctx, sessionToken)
		return nil, fmt.Errorf("session expired")
	}

	// Update last accessed time
	session.UpdateLastAccessed()
	err = s.cache.SetSession(ctx, session, s.config.SessionTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return session, nil
}

// RefreshSession refreshes a session using a refresh token
func (s *AuthenticationService) RefreshSession(ctx context.Context, refreshToken string) (*models.UserSession, error) {
	// Get session from cache using refresh token
	session, err := s.cache.GetSession(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if session is expired
	if session.IsExpired() {
		s.cache.DeleteSession(ctx, refreshToken)
		return nil, fmt.Errorf("session expired")
	}

	// Generate new session tokens
	newSessionToken := s.generateSessionToken()
	newRefreshToken := s.generateRefreshToken()

	// Create new session
	newSession := &models.UserSession{
		UserID:       session.UserID,
		SessionToken: newSessionToken,
		RefreshToken: newRefreshToken,
		IPAddress:    session.IPAddress,
		UserAgent:    session.UserAgent,
		ExpiresAt:    time.Now().Add(s.config.SessionTTL),
	}

	// Store new session in cache
	err = s.cache.SetSession(ctx, newSession, s.config.SessionTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to store new session: %w", err)
	}

	// Delete old session
	s.cache.DeleteSession(ctx, refreshToken)

	// Store new session in database
	err = s.sessionRepo.Create(ctx, newSession)
	if err != nil {
		s.cache.DeleteSession(ctx, newSessionToken)
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	return newSession, nil
}

// Logout logs out a user by invalidating their session
func (s *AuthenticationService) Logout(ctx context.Context, sessionToken string) error {
	// Get session to get user ID for logging
	session, err := s.cache.GetSession(ctx, sessionToken)
	if err == nil && session != nil {
		s.logAuthenticationEvent(ctx, &session.UserID, "logout", "session", "", "", true, "")
	}

	// Delete session from cache
	err = s.cache.DeleteSession(ctx, sessionToken)
	if err != nil {
		return fmt.Errorf("failed to delete session from cache: %w", err)
	}

	return nil
}

// LockAccount locks a user account
func (s *AuthenticationService) LockAccount(ctx context.Context, userID uuid.UUID, duration time.Duration) error {
	err := s.userRepo.LockAccount(ctx, userID, duration)
	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	s.logAuthenticationEvent(ctx, &userID, "account_locked", "admin", "", "", false, "manual lock")
	return nil
}

// UnlockAccount unlocks a user account
func (s *AuthenticationService) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	err := s.userRepo.UnlockAccount(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	s.logAuthenticationEvent(ctx, &userID, "account_unlocked", "admin", "", "", true, "manual unlock")
	return nil
}

// ResetPassword resets a user's password
func (s *AuthenticationService) ResetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Set new password
	err = user.SetPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

	// Update user
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Invalidate all user sessions
	err = s.cache.DeleteUserSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate sessions: %w", err)
	}

	s.logAuthenticationEvent(ctx, &userID, "password_reset", "admin", "", "", true, "")
	return nil
}

// LogAuthenticationEvent logs an authentication event
func (s *AuthenticationService) LogAuthenticationEvent(ctx context.Context, event *models.AuthenticationEvent) error {
	if s.auditRepo != nil {
		return s.auditRepo.CreateAuthenticationEvent(ctx, event)
	}
	return nil
}

// Helper methods

func (s *AuthenticationService) validateCredentials(credentials *LoginCredentials) error {
	if credentials == nil {
		return fmt.Errorf("credentials cannot be nil")
	}
	if credentials.Username == "" {
		return fmt.Errorf("username is required")
	}
	if credentials.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(credentials.Username) < 3 || len(credentials.Username) > 50 {
		return fmt.Errorf("username must be between 3 and 50 characters")
	}
	if len(credentials.Password) < s.config.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", s.config.PasswordMinLength)
	}
	return nil
}

func (s *AuthenticationService) validateBiometricData(data *BiometricData) error {
	if data == nil {
		return fmt.Errorf("biometric data cannot be nil")
	}
	if data.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if data.BiometricType == "" {
		return fmt.Errorf("biometric type is required")
	}
	if len(data.Data) == 0 {
		return fmt.Errorf("biometric data is required")
	}
	return nil
}

func (s *AuthenticationService) validateOTPDevice(deviceType models.DeviceType, deviceIdentifier string) error {
	if deviceType == "" {
		return fmt.Errorf("device type is required")
	}
	if deviceIdentifier == "" {
		return fmt.Errorf("device identifier is required")
	}
	return nil
}

func (s *AuthenticationService) checkRateLimit(ctx context.Context, username string) error {
	attempts, err := s.cache.GetLoginAttempts(ctx, username)
	if err != nil {
		return nil // No attempts recorded yet
	}

	if attempts >= s.config.RateLimitMax {
		return fmt.Errorf("rate limit exceeded")
	}

	return nil
}

func (s *AuthenticationService) checkMFARequirement(ctx context.Context, userID uuid.UUID) bool {
	// Check if MFA is required for this user
	// This could be based on user role, facility, or other criteria
	return s.config.RequireMFA
}

func (s *AuthenticationService) verifyBiometric(ctx context.Context, data *BiometricData) (bool, error) {
	// This would integrate with actual biometric verification service
	// For now, return true for demonstration
	return true, nil
}

func (s *AuthenticationService) generateSessionToken() string {
	return s.generateRandomToken(32)
}

func (s *AuthenticationService) generateRefreshToken() string {
	return s.generateRandomToken(64)
}

func (s *AuthenticationService) generateRandomToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, length)
	for i := range token {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		token[i] = charset[randomIndex.Int64()]
	}
	return string(token)
}

func (s *AuthenticationService) generateRandomOTP(length int) string {
	const digits = "0123456789"
	otp := make([]byte, length)
	for i := range otp {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(10))
		otp[i] = digits[randomIndex.Int64()]
	}
	return string(otp)
}

func (s *AuthenticationService) createFailedResult(error, errorCode string) *AuthenticationResult {
	return &AuthenticationResult{
		Success:   false,
		Error:     error,
		ErrorCode: errorCode,
	}
}

func (s *AuthenticationService) logAuthenticationEvent(
	ctx context.Context,
	userID *uuid.UUID,
	eventType, authMethod, ipAddress, userAgent string,
	success bool,
	failureReason string,
) {
	if s.auditRepo == nil {
		return
	}

	event := &models.AuthenticationEvent{
		UserID:              userID,
		EventType:           eventType,
		AuthenticationMethod: &authMethod,
		IPAddress:           &ipAddress,
		UserAgent:           &userAgent,
		Success:             success,
		FailureReason:       &failureReason,
	}

	s.auditRepo.CreateAuthenticationEvent(ctx, event)
} 