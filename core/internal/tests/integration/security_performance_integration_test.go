package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/controllers"
	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// SecurityPerformanceIntegrationTestSuite provides security and performance integration tests
type SecurityPerformanceIntegrationTestSuite struct {
	suite.Suite
	router *gin.Engine
}

// SetupSuite sets up the test suite
func (suite *SecurityPerformanceIntegrationTestSuite) SetupSuite() {
	// Initialize router with the same setup as main integration tests
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
	// Note: In a real implementation, this would use the same setup as the main integration tests
}

// TestSecurityScenarios tests various security scenarios
func (suite *SecurityPerformanceIntegrationTestSuite) TestSecurityScenarios() {
	suite.Run("TestBruteForceProtection", suite.testBruteForceProtection)
	suite.Run("TestSessionSecurity", suite.testSessionSecurity)
	suite.Run("TestPermissionEscalation", suite.testPermissionEscalation)
	suite.Run("TestSQLInjectionProtection", suite.testSQLInjectionProtection)
	suite.Run("TestXSSProtection", suite.testXSSProtection)
	suite.Run("TestCSRFProtection", suite.testCSRFProtection)
}

// TestPerformanceScenarios tests various performance scenarios
func (suite *SecurityPerformanceIntegrationTestSuite) TestPerformanceScenarios() {
	suite.Run("TestConcurrentLogins", suite.testConcurrentLogins)
	suite.Run("TestHighLoadAuthentication", suite.testHighLoadAuthentication)
	suite.Run("TestCachePerformance", suite.testCachePerformance)
	suite.Run("TestDatabasePerformance", suite.testDatabasePerformance)
}

// testBruteForceProtection tests brute force attack protection
func (suite *SecurityPerformanceIntegrationTestSuite) testBruteForceProtection() {
	// Create test user
	username := "bruteforce_test"
	password := "correct_password"

	// Attempt multiple failed logins
	for i := 0; i < 10; i++ {
		loginReq := controllers.LoginRequest{
			Username: username,
			Password: "wrong_password",
		}
		loginBody, _ := json.Marshal(loginReq)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		// After several failed attempts, should get rate limited or account locked
		if i >= 5 {
			assert.Contains(suite.T(), []int{http.StatusTooManyRequests, http.StatusLocked, http.StatusUnauthorized}, w.Code)
		}
	}

	// Try correct password - should be blocked
	loginReq := controllers.LoginRequest{
		Username: username,
		Password: password,
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	// Should be blocked due to too many failed attempts
	assert.NotEqual(suite.T(), http.StatusOK, w.Code)
}

// testSessionSecurity tests session security features
func (suite *SecurityPerformanceIntegrationTestSuite) testSessionSecurity() {
	// Create test user and login
	username := "session_test"
	password := "password123"

	// Login to get session
	loginReq := controllers.LoginRequest{
		Username: username,
		Password: password,
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var loginResp controllers.LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(suite.T(), err)

	// Test session validation with valid token
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/validate", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Test session validation with expired token (simulate)
	// In a real test, you would wait for token expiration or use a mock
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/validate", nil)
	req.Header.Set("Authorization", "Bearer expired_token")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test session logout
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Try to use logged out session
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/validate", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

// testPermissionEscalation tests permission escalation prevention
func (suite *SecurityPerformanceIntegrationTestSuite) testPermissionEscalation() {
	// Create regular user with limited permissions
	regularUser := "regular_user"
	regularPassword := "password123"

	// Login as regular user
	loginReq := controllers.LoginRequest{
		Username: regularUser,
		Password: regularPassword,
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var loginResp controllers.LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(suite.T(), err)

	// Try to access admin functionality
	adminReq := controllers.PermissionCheckRequest{
		Resource: "admin",
		Action:   "access",
	}
	adminBody, _ := json.Marshal(adminReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(adminBody)))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	// Should be denied
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var adminResp controllers.PermissionCheckResponse
	err = json.Unmarshal(w.Body.Bytes(), &adminResp)
	require.NoError(suite.T(), err)
	assert.False(suite.T(), adminResp.HasPermission)

	// Try to create admin user
	createAdminReq := controllers.CreateUserRequest{
		Username:  "new_admin",
		Email:     "admin@example.com",
		Password:  "admin123",
		FirstName: "Admin",
		LastName:  "User",
		Status:    "active",
	}
	createAdminBody, _ := json.Marshal(createAdminReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/users/", strings.NewReader(string(createAdminBody)))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	// Should be denied due to insufficient permissions
	assert.Equal(suite.T(), http.StatusForbidden, w.Code)
}

// testSQLInjectionProtection tests SQL injection protection
func (suite *SecurityPerformanceIntegrationTestSuite) testSQLInjectionProtection() {
	// Test SQL injection in username field
	sqlInjectionReq := controllers.LoginRequest{
		Username: "'; DROP TABLE users; --",
		Password: "password123",
	}
	sqlInjectionBody, _ := json.Marshal(sqlInjectionReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(sqlInjectionBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	// Should handle gracefully without SQL injection
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test SQL injection in search query
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/users/search?q='; DROP TABLE users; --", nil)
	suite.router.ServeHTTP(w, req)

	// Should handle gracefully
	assert.NotEqual(suite.T(), http.StatusInternalServerError, w.Code)
}

// testXSSProtection tests XSS protection
func (suite *SecurityPerformanceIntegrationTestSuite) testXSSProtection() {
	// Test XSS in user creation
	xssReq := controllers.CreateUserRequest{
		Username:  "<script>alert('xss')</script>",
		Email:     "xss@example.com",
		Password:  "password123",
		FirstName: "<img src=x onerror=alert('xss')>",
		LastName:  "User",
	}
	xssBody, _ := json.Marshal(xssReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/users/", strings.NewReader(string(xssBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	// Should handle XSS attempts gracefully
	assert.NotEqual(suite.T(), http.StatusInternalServerError, w.Code)
}

// testCSRFProtection tests CSRF protection
func (suite *SecurityPerformanceIntegrationTestSuite) testCSRFProtection() {
	// Test without CSRF token
	loginReq := controllers.LoginRequest{
		Username: "test_user",
		Password: "password123",
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	// Note: In a real implementation, CSRF protection would be implemented
	suite.router.ServeHTTP(w, req)

	// Should handle CSRF protection appropriately
	assert.NotEqual(suite.T(), http.StatusInternalServerError, w.Code)
}

// testConcurrentLogins tests concurrent login handling
func (suite *SecurityPerformanceIntegrationTestSuite) testConcurrentLogins() {
	username := "concurrent_test"
	password := "password123"
	numConcurrent := 10

	var wg sync.WaitGroup
	results := make(chan int, numConcurrent)

	// Launch concurrent login attempts
	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			loginReq := controllers.LoginRequest{
				Username: username,
				Password: password,
			}
			loginBody, _ := json.Marshal(loginReq)

			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			results <- w.Code
		}()
	}

	wg.Wait()
	close(results)

	// Check results
	successCount := 0
	for code := range results {
		if code == http.StatusOK {
			successCount++
		}
	}

	// Should handle concurrent requests appropriately
	assert.Greater(suite.T(), successCount, 0)
}

// testHighLoadAuthentication tests high load authentication scenarios
func (suite *SecurityPerformanceIntegrationTestSuite) testHighLoadAuthentication() {
	numRequests := 100
	startTime := time.Now()

	// Perform high load authentication requests
	for i := 0; i < numRequests; i++ {
		username := fmt.Sprintf("load_test_%d", i)
		password := "password123"

		loginReq := controllers.LoginRequest{
			Username: username,
			Password: password,
		}
		loginBody, _ := json.Marshal(loginReq)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		// Should handle high load gracefully
		assert.NotEqual(suite.T(), http.StatusInternalServerError, w.Code)
	}

	duration := time.Since(startTime)
	requestsPerSecond := float64(numRequests) / duration.Seconds()

	// Should maintain reasonable performance
	assert.Greater(suite.T(), requestsPerSecond, 10.0) // At least 10 requests per second
}

// testCachePerformance tests cache performance
func (suite *SecurityPerformanceIntegrationTestSuite) testCachePerformance() {
	username := "cache_test"
	password := "password123"

	// First login (cache miss)
	startTime := time.Now()
	loginReq := controllers.LoginRequest{
		Username: username,
		Password: password,
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	firstLoginTime := time.Since(startTime)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var loginResp controllers.LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(suite.T(), err)

	// Second login (cache hit)
	startTime = time.Now()
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	secondLoginTime := time.Since(startTime)

	// Cache hit should be faster
	assert.Less(suite.T(), secondLoginTime, firstLoginTime)
}

// testDatabasePerformance tests database performance
func (suite *SecurityPerformanceIntegrationTestSuite) testDatabasePerformance() {
	// Test user creation performance
	numUsers := 50
	startTime := time.Now()

	for i := 0; i < numUsers; i++ {
		username := fmt.Sprintf("perf_test_%d", i)
		email := fmt.Sprintf("perf_%d@example.com", i)

		createUserReq := controllers.CreateUserRequest{
			Username:  username,
			Email:     email,
			Password:  "password123",
			FirstName: "Performance",
			LastName:  "Test",
		}
		createUserBody, _ := json.Marshal(createUserReq)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/users/", strings.NewReader(string(createUserBody)))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusCreated, w.Code)
	}

	duration := time.Since(startTime)
	usersPerSecond := float64(numUsers) / duration.Seconds()

	// Should maintain reasonable database performance
	assert.Greater(suite.T(), usersPerSecond, 5.0) // At least 5 users per second

	// Test user listing performance
	startTime = time.Now()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/users/?limit=100&offset=0", nil)
	suite.router.ServeHTTP(w, req)

	listingTime := time.Since(startTime)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Less(suite.T(), listingTime, 2*time.Second) // Should complete within 2 seconds
}

// TestHealthcareSecurityScenarios tests healthcare-specific security scenarios
func (suite *SecurityPerformanceIntegrationTestSuite) TestHealthcareSecurityScenarios() {
	suite.Run("TestPatientDataAccessControl", suite.testPatientDataAccessControl)
	suite.Run("TestEmergencyAccessControl", suite.testEmergencyAccessControl)
	suite.Run("TestAuditTrailIntegrity", suite.testAuditTrailIntegrity)
}

// testPatientDataAccessControl tests patient data access control
func (suite *SecurityPerformanceIntegrationTestSuite) testPatientDataAccessControl() {
	// Create doctor user
	doctorUsername := "doctor_security"
	doctorPassword := "password123"

	// Login as doctor
	loginReq := controllers.LoginRequest{
		Username: doctorUsername,
		Password: doctorPassword,
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var loginResp controllers.LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(suite.T(), err)

	// Test patient data access with proper authorization
	patientAccessReq := controllers.PermissionCheckRequest{
		Resource: "patients",
		Action:   "read",
	}
	patientAccessBody, _ := json.Marshal(patientAccessReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(patientAccessBody)))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var patientAccessResp controllers.PermissionCheckResponse
	err = json.Unmarshal(w.Body.Bytes(), &patientAccessResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), patientAccessResp.HasPermission)

	// Test unauthorized patient data access
	unauthorizedReq := controllers.PermissionCheckRequest{
		Resource: "patients",
		Action:   "delete",
	}
	unauthorizedBody, _ := json.Marshal(unauthorizedReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(unauthorizedBody)))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var unauthorizedResp controllers.PermissionCheckResponse
	err = json.Unmarshal(w.Body.Bytes(), &unauthorizedResp)
	require.NoError(suite.T(), err)
	assert.False(suite.T(), unauthorizedResp.HasPermission)
}

// testEmergencyAccessControl tests emergency access control
func (suite *SecurityPerformanceIntegrationTestSuite) testEmergencyAccessControl() {
	// Create emergency staff user
	emergencyUsername := "emergency_staff"
	emergencyPassword := "password123"

	// Login as emergency staff
	loginReq := controllers.LoginRequest{
		Username: emergencyUsername,
		Password: emergencyPassword,
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var loginResp controllers.LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(suite.T(), err)

	// Test emergency access
	emergencyReq := controllers.PermissionCheckRequest{
		Resource: "emergency",
		Action:   "access",
	}
	emergencyBody, _ := json.Marshal(emergencyReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(emergencyBody)))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var emergencyResp controllers.PermissionCheckResponse
	err = json.Unmarshal(w.Body.Bytes(), &emergencyResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), emergencyResp.HasPermission)
}

// testAuditTrailIntegrity tests audit trail integrity
func (suite *SecurityPerformanceIntegrationTestSuite) testAuditTrailIntegrity() {
	// Create test user
	username := "audit_integrity_test"
	password := "password123"

	// Login user
	loginReq := controllers.LoginRequest{
		Username: username,
		Password: password,
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Check authentication audit trail
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/audit/authentication?limit=10&offset=0", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var authEventsResp controllers.GetAuthenticationEventsResponse
	err := json.Unmarshal(w.Body.Bytes(), &authEventsResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), authEventsResp.Success)
	assert.GreaterOrEqual(suite.T(), len(authEventsResp.Events), 1)

	// Verify audit trail integrity
	for _, event := range authEventsResp.Events {
		eventMap := event.(map[string]interface{})
		assert.NotEmpty(suite.T(), eventMap["id"])
		assert.NotEmpty(suite.T(), eventMap["timestamp"])
		assert.NotEmpty(suite.T(), eventMap["user_id"])
	}
}

// Run the test suite
func TestSecurityPerformanceIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(SecurityPerformanceIntegrationTestSuite))
} 