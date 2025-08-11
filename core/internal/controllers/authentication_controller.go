package controllers

import (
	"net/http"
	"strings"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthenticationController handles authentication-related HTTP requests
type AuthenticationController struct {
	authService services.AuthenticationService
}

// NewAuthenticationController creates a new authentication controller
func NewAuthenticationController(authService services.AuthenticationService) *AuthenticationController {
	return &AuthenticationController{
		authService: authService,
	}
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=8"`
}

// LoginResponse represents the login response payload
type LoginResponse struct {
	Success      bool                   `json:"success"`
	UserID       string                 `json:"user_id,omitempty"`
	SessionToken string                 `json:"session_token,omitempty"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	ExpiresAt    string                 `json:"expires_at,omitempty"`
	RequiresMFA  bool                   `json:"requires_mfa,omitempty"`
	Error        string                 `json:"error,omitempty"`
	ErrorCode    string                 `json:"error_code,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// BiometricLoginRequest represents the biometric login request payload
type BiometricLoginRequest struct {
	UserID        string  `json:"user_id" binding:"required"`
	BiometricType string  `json:"biometric_type" binding:"required,oneof=fingerprint facial iris"`
	Data          []byte  `json:"data" binding:"required"`
	DeviceID      string  `json:"device_id"`
	Quality       float64 `json:"quality"`
}

// OTPGenerateRequest represents the OTP generation request payload
type OTPGenerateRequest struct {
	DeviceType      string `json:"device_type" binding:"required,oneof=email sms totp"`
	DeviceIdentifier string `json:"device_identifier" binding:"required"`
}

// OTPGenerateResponse represents the OTP generation response payload
type OTPGenerateResponse struct {
	Success        bool   `json:"success"`
	OTP            string `json:"otp,omitempty"`
	DeviceType     string `json:"device_type,omitempty"`
	ExpiresIn      int    `json:"expires_in,omitempty"`
	Error          string `json:"error,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
}

// MFACompleteRequest represents the MFA completion request payload
type MFACompleteRequest struct {
	DeviceIdentifier string `json:"device_identifier" binding:"required"`
	OTP              string `json:"otp" binding:"required,min=6,max=6"`
}

// RefreshSessionRequest represents the session refresh request payload
type RefreshSessionRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// SessionValidationResponse represents the session validation response payload
type SessionValidationResponse struct {
	Success     bool   `json:"success"`
	UserID      string `json:"user_id,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Error       string `json:"error,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
}

// LogoutResponse represents the logout response payload
type LogoutResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Login handles user login with username and password
func (c *AuthenticationController) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, LoginResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Get client IP and user agent
	ipAddress := getClientIPAddress(ctx)
	userAgent := ctx.GetHeader("User-Agent")

	// Create login credentials
	credentials := &services.LoginCredentials{
		Username: req.Username,
		Password: req.Password,
	}

	// Authenticate user
	result, err := c.authService.AuthenticateWithPassword(ctx, credentials, ipAddress, userAgent)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, LoginResponse{
			Success:   false,
			Error:     "authentication service error",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	// Map result to response
	response := LoginResponse{
		Success:      result.Success,
		RequiresMFA:  result.RequiresMFA,
		Error:        result.Error,
		ErrorCode:    result.ErrorCode,
		Metadata:     result.Metadata,
	}

	if result.Success {
		response.UserID = result.UserID.String()
		response.SessionToken = result.SessionToken
		response.RefreshToken = result.RefreshToken
		response.ExpiresAt = result.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	}

	// Set appropriate HTTP status code
	switch result.ErrorCode {
	case "INVALID_CREDENTIALS":
		ctx.JSON(http.StatusUnauthorized, response)
	case "ACCOUNT_LOCKED":
		ctx.JSON(http.StatusForbidden, response)
	case "ACCOUNT_INACTIVE":
		ctx.JSON(http.StatusForbidden, response)
	case "RATE_LIMIT_EXCEEDED":
		ctx.JSON(http.StatusTooManyRequests, response)
	default:
		ctx.JSON(http.StatusOK, response)
	}
}

// BiometricLogin handles user login with biometric data
func (c *AuthenticationController) BiometricLogin(ctx *gin.Context) {
	var req BiometricLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, LoginResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse user ID
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, LoginResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Get client IP and user agent
	ipAddress := getClientIPAddress(ctx)
	userAgent := ctx.GetHeader("User-Agent")

	// Create biometric data
	biometricData := &services.BiometricData{
		UserID:        userID,
		BiometricType: req.BiometricType,
		Data:          req.Data,
		DeviceID:      req.DeviceID,
		Quality:       req.Quality,
	}

	// Authenticate user with biometric
	result, err := c.authService.AuthenticateWithBiometric(ctx, biometricData, ipAddress, userAgent)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, LoginResponse{
			Success:   false,
			Error:     "biometric authentication service error",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	// Map result to response
	response := LoginResponse{
		Success:      result.Success,
		RequiresMFA:  result.RequiresMFA,
		Error:        result.Error,
		ErrorCode:    result.ErrorCode,
		Metadata:     result.Metadata,
	}

	if result.Success {
		response.UserID = result.UserID.String()
		response.SessionToken = result.SessionToken
		response.RefreshToken = result.RefreshToken
		response.ExpiresAt = result.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	}

	// Set appropriate HTTP status code
	switch result.ErrorCode {
	case "INVALID_BIOMETRIC_DATA":
		ctx.JSON(http.StatusBadRequest, response)
	case "BIOMETRIC_VERIFICATION_FAILED":
		ctx.JSON(http.StatusUnauthorized, response)
	case "USER_NOT_FOUND":
		ctx.JSON(http.StatusNotFound, response)
	case "ACCOUNT_NOT_ACCESSIBLE":
		ctx.JSON(http.StatusForbidden, response)
	default:
		ctx.JSON(http.StatusOK, response)
	}
}

// GenerateOTP generates an OTP for the specified device
func (c *AuthenticationController) GenerateOTP(ctx *gin.Context) {
	var req OTPGenerateRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, OTPGenerateResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userIDInterface, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, OTPGenerateResponse{
			Success:   false,
			Error:     "user not authenticated",
			ErrorCode: "UNAUTHORIZED",
		})
		return
	}

	userID, ok := userIDInterface.(uuid.UUID)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, OTPGenerateResponse{
			Success:   false,
			Error:     "invalid user ID in context",
			ErrorCode: "INTERNAL_ERROR",
		})
		return
	}

	// Map device type string to DeviceType enum
	var deviceType models.DeviceType
	switch req.DeviceType {
	case "email":
		deviceType = models.DeviceTypeEmail
	case "sms":
		deviceType = models.DeviceTypeSMS
	case "totp":
		deviceType = models.DeviceTypeTOTP
	default:
		ctx.JSON(http.StatusBadRequest, OTPGenerateResponse{
			Success:   false,
			Error:     "invalid device type",
			ErrorCode: "INVALID_DEVICE_TYPE",
		})
		return
	}

	// Generate OTP
	otp, err := c.authService.GenerateOTP(ctx, userID, deviceType, req.DeviceIdentifier)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, OTPGenerateResponse{
			Success:   false,
			Error:     "failed to generate OTP",
			ErrorCode: "OTP_GENERATION_FAILED",
		})
		return
	}

	ctx.JSON(http.StatusOK, OTPGenerateResponse{
		Success:    true,
		OTP:        otp,
		DeviceType: req.DeviceType,
		ExpiresIn:  300, // 5 minutes
	})
}

// CompleteMFA completes multi-factor authentication
func (c *AuthenticationController) CompleteMFA(ctx *gin.Context) {
	var req MFACompleteRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, LoginResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Get session token from authorization header
	sessionToken := getSessionTokenFromHeader(ctx)
	if sessionToken == "" {
		ctx.JSON(http.StatusUnauthorized, LoginResponse{
			Success:   false,
			Error:     "missing session token",
			ErrorCode: "MISSING_SESSION_TOKEN",
		})
		return
	}

	// Complete MFA
	result, err := c.authService.CompleteMFA(ctx, sessionToken, req.DeviceIdentifier, req.OTP)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, LoginResponse{
			Success:   false,
			Error:     "MFA completion service error",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	// Map result to response
	response := LoginResponse{
		Success:      result.Success,
		RequiresMFA:  result.RequiresMFA,
		Error:        result.Error,
		ErrorCode:    result.ErrorCode,
		Metadata:     result.Metadata,
	}

	if result.Success {
		response.UserID = result.UserID.String()
		response.SessionToken = result.SessionToken
		response.RefreshToken = result.RefreshToken
		response.ExpiresAt = result.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	}

	// Set appropriate HTTP status code
	switch result.ErrorCode {
	case "INVALID_SESSION":
		ctx.JSON(http.StatusUnauthorized, response)
	case "INVALID_OTP":
		ctx.JSON(http.StatusUnauthorized, response)
	case "OTP_VERIFICATION_FAILED":
		ctx.JSON(http.StatusUnauthorized, response)
	default:
		ctx.JSON(http.StatusOK, response)
	}
}

// RefreshSession refreshes a session using a refresh token
func (c *AuthenticationController) RefreshSession(ctx *gin.Context) {
	var req RefreshSessionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, LoginResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Refresh session
	session, err := c.authService.RefreshSession(ctx, req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, LoginResponse{
			Success:   false,
			Error:     "invalid refresh token",
			ErrorCode: "INVALID_REFRESH_TOKEN",
		})
		return
	}

	ctx.JSON(http.StatusOK, LoginResponse{
		Success:      true,
		UserID:       session.UserID.String(),
		SessionToken: session.SessionToken,
		RefreshToken: session.RefreshToken,
		ExpiresAt:    session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// ValidateSession validates a session token
func (c *AuthenticationController) ValidateSession(ctx *gin.Context) {
	// Get session token from authorization header
	sessionToken := getSessionTokenFromHeader(ctx)
	if sessionToken == "" {
		ctx.JSON(http.StatusUnauthorized, SessionValidationResponse{
			Success:   false,
			Error:     "missing authorization header",
			ErrorCode: "MISSING_AUTHORIZATION",
		})
		return
	}

	// Validate session
	session, err := c.authService.ValidateSession(ctx, sessionToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, SessionValidationResponse{
			Success:   false,
			Error:     "invalid session",
			ErrorCode: "INVALID_SESSION",
		})
		return
	}

	ctx.JSON(http.StatusOK, SessionValidationResponse{
		Success:      true,
		UserID:       session.UserID.String(),
		SessionToken: session.SessionToken,
		ExpiresAt:    session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// Logout logs out a user by invalidating their session
func (c *AuthenticationController) Logout(ctx *gin.Context) {
	// Get session token from authorization header
	sessionToken := getSessionTokenFromHeader(ctx)
	if sessionToken == "" {
		ctx.JSON(http.StatusUnauthorized, LogoutResponse{
			Success: false,
			Error:   "missing authorization header",
		})
		return
	}

	// Logout user
	err := c.authService.Logout(ctx, sessionToken)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, LogoutResponse{
			Success: false,
			Error:   "failed to logout",
		})
		return
	}

	ctx.JSON(http.StatusOK, LogoutResponse{
		Success: true,
		Message: "logged out successfully",
	})
}

// Helper functions

// getClientIPAddress extracts the client IP address from the request
func getClientIPAddress(ctx *gin.Context) string {
	// Check for X-Forwarded-For header (for proxy scenarios)
	if forwardedFor := ctx.GetHeader("X-Forwarded-For"); forwardedFor != "" {
		// Take the first IP in the list
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check for X-Real-IP header
	if realIP := ctx.GetHeader("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to remote address
	return ctx.ClientIP()
}

// getSessionTokenFromHeader extracts the session token from the Authorization header
func getSessionTokenFromHeader(ctx *gin.Context) string {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}

	// Check if it's a Bearer token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
} 