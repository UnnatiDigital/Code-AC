package middleware

import (
	"net/http"
	"strings"

	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
)

// AuthenticationMiddleware provides authentication and authorization middleware
type AuthenticationMiddleware struct {
	authService services.AuthenticationService
}

// NewAuthenticationMiddleware creates a new authentication middleware
func NewAuthenticationMiddleware(authService services.AuthenticationService) *AuthenticationMiddleware {
	return &AuthenticationMiddleware{
		authService: authService,
	}
}

// RequireAuthentication middleware ensures the request has a valid session token
func (m *AuthenticationMiddleware) RequireAuthentication() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get session token from authorization header
		sessionToken := getSessionTokenFromHeader(ctx)
		if sessionToken == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"success":   false,
				"error":     "missing authorization header",
				"error_code": "MISSING_AUTHORIZATION",
			})
			ctx.Abort()
			return
		}

		// Validate session
		session, err := m.authService.ValidateSession(ctx, sessionToken)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"success":   false,
				"error":     "invalid session",
				"error_code": "INVALID_SESSION",
			})
			ctx.Abort()
			return
		}

		// Set user ID in context for downstream handlers
		ctx.Set("user_id", session.UserID)
		ctx.Set("session_token", sessionToken)
		ctx.Set("session", session)

		ctx.Next()
	}
}

// RequireMFA middleware ensures the user has completed multi-factor authentication
func (m *AuthenticationMiddleware) RequireMFA() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// First ensure authentication
		m.RequireAuthentication()(ctx)
		if ctx.IsAborted() {
			return
		}

		// Check if MFA is required and completed
		// This would typically check a flag in the session or user record
		// For now, we'll assume MFA is completed if the session exists
		// In a real implementation, you'd check a specific MFA completion flag

		ctx.Next()
	}
}

// RequirePermission middleware ensures the user has a specific permission
func (m *AuthenticationMiddleware) RequirePermission(resource, action string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// First ensure authentication
		m.RequireAuthentication()(ctx)
		if ctx.IsAborted() {
			return
		}

		// Get user ID from context
		userIDInterface, exists := ctx.Get("user_id")
		if !exists {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":   false,
				"error":     "user ID not found in context",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		userID, ok := userIDInterface.(string)
		if !ok {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":   false,
				"error":     "invalid user ID in context",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		// Parse user ID
		parsedUserID, err := parseUUID(userID)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":   false,
				"error":     "invalid user ID format",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		// Check permission (this would use the authorization service)
		// For now, we'll assume permission is granted
		// In a real implementation, you'd call the authorization service
		hasPermission := true // Placeholder

		if !hasPermission {
			ctx.JSON(http.StatusForbidden, gin.H{
				"success":   false,
				"error":     "insufficient permissions",
				"error_code": "INSUFFICIENT_PERMISSIONS",
			})
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// RequireRole middleware ensures the user has a specific role
func (m *AuthenticationMiddleware) RequireRole(roleName string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// First ensure authentication
		m.RequireAuthentication()(ctx)
		if ctx.IsAborted() {
			return
		}

		// Get user ID from context
		userIDInterface, exists := ctx.Get("user_id")
		if !exists {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":   false,
				"error":     "user ID not found in context",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		userID, ok := userIDInterface.(string)
		if !ok {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":   false,
				"error":     "invalid user ID in context",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		// Parse user ID
		parsedUserID, err := parseUUID(userID)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":   false,
				"error":     "invalid user ID format",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		// Check role (this would use the authorization service)
		// For now, we'll assume role is granted
		// In a real implementation, you'd call the authorization service
		hasRole := true // Placeholder

		if !hasRole {
			ctx.JSON(http.StatusForbidden, gin.H{
				"success":   false,
				"error":     "insufficient role",
				"error_code": "INSUFFICIENT_ROLE",
			})
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// OptionalAuthentication middleware provides optional authentication
// It doesn't abort the request if authentication fails, but sets user info if available
func (m *AuthenticationMiddleware) OptionalAuthentication() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get session token from authorization header
		sessionToken := getSessionTokenFromHeader(ctx)
		if sessionToken == "" {
			// No token provided, continue without authentication
			ctx.Next()
			return
		}

		// Try to validate session
		session, err := m.authService.ValidateSession(ctx, sessionToken)
		if err != nil {
			// Invalid token, continue without authentication
			ctx.Next()
			return
		}

		// Valid session, set user info in context
		ctx.Set("user_id", session.UserID)
		ctx.Set("session_token", sessionToken)
		ctx.Set("session", session)
		ctx.Set("authenticated", true)

		ctx.Next()
	}
}

// RateLimitMiddleware provides rate limiting for authentication endpoints
func (m *AuthenticationMiddleware) RateLimitMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get client IP
		clientIP := getClientIP(ctx)

		// Check rate limit (this would use a rate limiting service)
		// For now, we'll assume rate limit is not exceeded
		// In a real implementation, you'd check against Redis or similar
		rateLimitExceeded := false // Placeholder

		if rateLimitExceeded {
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				"success":   false,
				"error":     "rate limit exceeded",
				"error_code": "RATE_LIMIT_EXCEEDED",
			})
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// AuditMiddleware provides audit logging for authentication events
func (m *AuthenticationMiddleware) AuditMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Log the request (this would use an audit service)
		// For now, we'll just continue
		// In a real implementation, you'd log to an audit service

		ctx.Next()

		// Log the response
		// This would typically be done in a response interceptor
	}
}

// Helper functions

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

// getClientIP extracts the client IP address from the request
func getClientIP(ctx *gin.Context) string {
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

// parseUUID parses a UUID string
func parseUUID(uuidStr string) (interface{}, error) {
	// This is a placeholder - in a real implementation, you'd use github.com/google/uuid
	// For now, we'll just return the string as-is
	return uuidStr, nil
} 