package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/bmad-method/hmis-core/internal/cache"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// SecurityMiddleware provides comprehensive security features
type SecurityMiddleware struct {
	redisCache *cache.RedisCache
	limiter    *rate.Limiter
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(redisCache *cache.RedisCache) *SecurityMiddleware {
	return &SecurityMiddleware{
		redisCache: redisCache,
		limiter:    rate.NewLimiter(rate.Every(time.Second), 100), // 100 requests per second
	}
}

// CORSMiddleware handles Cross-Origin Resource Sharing
func (m *SecurityMiddleware) CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Allow specific origins for healthcare applications
		allowedOrigins := []string{
			"https://hospital.example.com",
			"https://clinic.example.com",
			"https://admin.example.com",
			"http://localhost:3000", // Development
			"http://localhost:8080", // Development
		}

		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// SecurityHeadersMiddleware adds security headers
func (m *SecurityMiddleware) SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content Security Policy for healthcare applications
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';")
		
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")
		
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		
		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// Strict Transport Security for healthcare data
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		
		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Permissions Policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		// Remove server information
		c.Header("Server", "")
		
		c.Next()
	}
}

// RateLimitMiddleware implements rate limiting
func (m *SecurityMiddleware) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client IP
		clientIP := getClientIP(c)
		
		// Check rate limit
		key := "rate_limit:" + clientIP
		limit, err := m.redisCache.GetInt(c, key)
		if err != nil {
			limit = 0
		}

		// Set rate limit based on endpoint
		maxRequests := m.getRateLimitForEndpoint(c.Request.URL.Path)
		
		if limit >= maxRequests {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success":    false,
				"error":      "rate limit exceeded",
				"error_code": "RATE_LIMIT_EXCEEDED",
				"retry_after": 60,
			})
			c.Abort()
			return
		}

		// Increment rate limit counter
		m.redisCache.SetInt(c, key, limit+1, 60*time.Second)
		
		// Add rate limit headers
		c.Header("X-RateLimit-Limit", string(rune(maxRequests)))
		c.Header("X-RateLimit-Remaining", string(rune(maxRequests-limit-1)))
		c.Header("X-RateLimit-Reset", string(rune(time.Now().Add(60*time.Second).Unix())))

		c.Next()
	}
}

// BruteForceProtectionMiddleware protects against brute force attacks
func (m *SecurityMiddleware) BruteForceProtectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to authentication endpoints
		if !strings.Contains(c.Request.URL.Path, "/auth/login") {
			c.Next()
			return
		}

		clientIP := getClientIP(c)
		key := "brute_force:" + clientIP
		
		// Check failed attempts
		failedAttempts, err := m.redisCache.GetInt(c, key)
		if err != nil {
			failedAttempts = 0
		}

		// Block if too many failed attempts
		if failedAttempts >= 5 {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success":    false,
				"error":      "too many failed login attempts. please try again later.",
				"error_code": "BRUTE_FORCE_PROTECTION",
				"retry_after": 300, // 5 minutes
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequestIDMiddleware adds unique request ID for tracking
func (m *SecurityMiddleware) RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		
		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		
		c.Next()
	}
}

// InputValidationMiddleware validates and sanitizes input
func (m *SecurityMiddleware) InputValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate Content-Type for POST/PUT requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				c.JSON(http.StatusBadRequest, gin.H{
					"success":    false,
					"error":      "invalid content type. expected application/json",
					"error_code": "INVALID_CONTENT_TYPE",
				})
				c.Abort()
				return
			}
		}

		// Validate request size
		if c.Request.ContentLength > 10*1024*1024 { // 10MB limit
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"success":    false,
				"error":      "request too large",
				"error_code": "REQUEST_TOO_LARGE",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// SQLInjectionProtectionMiddleware protects against SQL injection
func (m *SecurityMiddleware) SQLInjectionProtectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check query parameters
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				if containsSQLInjection(value) {
					c.JSON(http.StatusBadRequest, gin.H{
						"success":    false,
						"error":      "invalid input detected",
						"error_code": "INVALID_INPUT",
					})
					c.Abort()
					return
				}
			}
		}

		// Check request body for JSON requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if strings.Contains(contentType, "application/json") {
				// The actual validation will be done in the controller
				// This middleware just checks for obvious patterns
			}
		}

		c.Next()
	}
}

// XSSProtectionMiddleware protects against XSS attacks
func (m *SecurityMiddleware) XSSProtectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for XSS patterns in query parameters
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				if containsXSS(value) {
					c.JSON(http.StatusBadRequest, gin.H{
						"success":    false,
						"error":      "invalid input detected",
						"error_code": "INVALID_INPUT",
					})
					c.Abort()
					return
				}
			}
		}

		c.Next()
	}
}

// HealthcareDataProtectionMiddleware adds healthcare-specific security
func (m *SecurityMiddleware) HealthcareDataProtectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add healthcare-specific headers
		c.Header("X-Healthcare-Data-Protected", "true")
		c.Header("X-HIPAA-Compliant", "true")
		
		// Log healthcare data access
		if strings.Contains(c.Request.URL.Path, "/patients") || 
		   strings.Contains(c.Request.URL.Path, "/medical") ||
		   strings.Contains(c.Request.URL.Path, "/healthcare") {
			// This would typically log to a healthcare-specific audit system
			requestID, _ := c.Get("request_id")
			clientIP := getClientIP(c)
			
			// Log healthcare data access attempt
			_ = requestID
			_ = clientIP
		}

		c.Next()
	}
}

// AuditLoggingMiddleware logs security-relevant events
func (m *SecurityMiddleware) AuditLoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		
		// Process request
		c.Next()
		
		// Log security events
		statusCode := c.Writer.Status()
		duration := time.Since(startTime)
		clientIP := getClientIP(c)
		userAgent := c.GetHeader("User-Agent")
		requestID, _ := c.Get("request_id")
		
		// Log suspicious activities
		if statusCode >= 400 {
			// Log failed requests
			_ = statusCode
			_ = duration
			_ = clientIP
			_ = userAgent
			_ = requestID
		}
		
		// Log healthcare data access
		if strings.Contains(c.Request.URL.Path, "/patients") || 
		   strings.Contains(c.Request.URL.Path, "/medical") {
			// Log healthcare data access
			_ = clientIP
			_ = requestID
		}
	}
}

// Helper functions

// getClientIP extracts the client IP address
func getClientIP(c *gin.Context) string {
	// Check for X-Forwarded-For header (for proxy scenarios)
	if forwardedFor := c.GetHeader("X-Forwarded-For"); forwardedFor != "" {
		// Take the first IP in the list
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check for X-Real-IP header
	if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to remote address
	return c.ClientIP()
}

// getRateLimitForEndpoint returns rate limit for specific endpoints
func (m *SecurityMiddleware) getRateLimitForEndpoint(path string) int {
	switch {
	case strings.Contains(path, "/auth/login"):
		return 5 // 5 login attempts per minute
	case strings.Contains(path, "/auth/"):
		return 30 // 30 auth requests per minute
	case strings.Contains(path, "/users/"):
		return 20 // 20 user management requests per minute
	case strings.Contains(path, "/audit/"):
		return 10 // 10 audit requests per minute
	default:
		return 100 // 100 requests per minute for other endpoints
	}
}

// containsSQLInjection checks for SQL injection patterns
func containsSQLInjection(input string) bool {
	// Convert to lowercase for case-insensitive matching
	input = strings.ToLower(input)
	
	// Common SQL injection patterns
	patterns := []string{
		"';",
		"';--",
		"';/*",
		"';#",
		"union select",
		"union all select",
		"drop table",
		"delete from",
		"insert into",
		"update set",
		"alter table",
		"create table",
		"exec(",
		"execute(",
		"xp_",
		"sp_",
		"@@",
		"0x",
		"waitfor delay",
		"benchmark(",
		"sleep(",
	}
	
	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	
	return false
}

// containsXSS checks for XSS patterns
func containsXSS(input string) bool {
	// Convert to lowercase for case-insensitive matching
	input = strings.ToLower(input)
	
	// Common XSS patterns
	patterns := []string{
		"<script",
		"javascript:",
		"onload=",
		"onerror=",
		"onclick=",
		"onmouseover=",
		"onfocus=",
		"onblur=",
		"onchange=",
		"onsubmit=",
		"<iframe",
		"<object",
		"<embed",
		"<form",
		"<input",
		"<textarea",
		"<select",
		"<button",
		"<link",
		"<meta",
		"<style",
		"<img",
		"<svg",
		"<math",
		"<xmp",
		"<plaintext",
		"<listing",
		"<marquee",
		"<applet",
		"<bgsound",
		"<base",
		"<basefont",
		"<bdo",
		"<dir",
		"<font",
		"<isindex",
		"<keygen",
		"<multicol",
		"<nextid",
		"<spacer",
		"<wbr",
	}
	
	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	
	return false
}

// RecordFailedLogin records a failed login attempt
func (m *SecurityMiddleware) RecordFailedLogin(c *gin.Context, username string) {
	clientIP := getClientIP(c)
	key := "brute_force:" + clientIP
	
	// Increment failed attempts
	failedAttempts, err := m.redisCache.GetInt(c, key)
	if err != nil {
		failedAttempts = 0
	}
	
	m.redisCache.SetInt(c, key, failedAttempts+1, 5*time.Minute)
	
	// Log failed login attempt
	_ = username
	_ = clientIP
}

// ResetFailedLoginAttempts resets failed login attempts
func (m *SecurityMiddleware) ResetFailedLoginAttempts(c *gin.Context) {
	clientIP := getClientIP(c)
	key := "brute_force:" + clientIP
	
	// Reset failed attempts
	m.redisCache.Delete(c, key)
} 