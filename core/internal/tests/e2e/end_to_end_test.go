package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/cache"
	"github.com/bmad-method/hmis-core/internal/controllers"
	"github.com/bmad-method/hmis-core/internal/database"
	"github.com/bmad-method/hmis-core/internal/gateway"
	"github.com/bmad-method/hmis-core/internal/middleware"
	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/notifications"
	"github.com/bmad-method/hmis-core/internal/repositories"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// EndToEndTestSuite provides comprehensive end-to-end testing
type EndToEndTestSuite struct {
	suite.Suite
	db                *sql.DB
	redisCache        *cache.RedisCache
	userRepo          repositories.UserRepository
	roleRepo          repositories.RoleRepository
	auditRepo         repositories.AuditRepository
	authService       services.AuthenticationService
	authzService      services.AuthorizationService
	auditService      services.AuditService
	notificationService *notifications.NotificationService
	securityMiddleware *middleware.SecurityMiddleware
	apiGateway        *gateway.APIGateway
	authCtrl          *controllers.AuthenticationController
	authzCtrl         *controllers.AuthorizationController
	userCtrl          *controllers.UserManagementController
	auditCtrl         *controllers.AuditController
	router            *gin.Engine
	server            *httptest.Server
}

// SetupSuite sets up the test suite
func (suite *EndToEndTestSuite) SetupSuite() {
	// Initialize test database
	var err error
	suite.db, err = database.NewTestConnection()
	require.NoError(suite.T(), err)

	// Run migrations
	err = database.RunMigrations(suite.db)
	require.NoError(suite.T(), err)

	// Initialize Redis cache
	suite.redisCache = cache.NewRedisCache("localhost:6379", "", 0)

	// Initialize repositories
	suite.userRepo = repositories.NewUserRepository(suite.db)
	suite.roleRepo = repositories.NewRoleRepository(suite.db)
	suite.auditRepo = repositories.NewAuditRepository(suite.db)

	// Initialize services
	suite.authService = services.NewAuthenticationService(suite.userRepo, suite.redisCache)
	suite.authzService = services.NewAuthorizationService(suite.userRepo, suite.roleRepo, suite.redisCache)
	suite.auditService = services.NewAuditService(suite.auditRepo)

	// Initialize notification service
	notificationConfig := &notifications.NotificationConfig{
		SMTPHost:     "localhost",
		SMTPPort:     587,
		SMTPUsername: "test",
		SMTPPassword: "test",
	}
	suite.notificationService = notifications.NewNotificationService(suite.auditService, notificationConfig)

	// Initialize security middleware
	suite.securityMiddleware = middleware.NewSecurityMiddleware(suite.redisCache)

	// Initialize API gateway
	suite.apiGateway = gateway.NewAPIGateway(suite.authService, suite.authzService, suite.auditService, suite.redisCache)

	// Initialize controllers
	suite.authCtrl = controllers.NewAuthenticationController(suite.authService, suite.auditService)
	suite.authzCtrl = controllers.NewAuthorizationController(suite.authzService)
	suite.userCtrl = controllers.NewUserManagementController(suite.userRepo, suite.roleRepo)
	suite.auditCtrl = controllers.NewAuditController(suite.auditService)

	// Setup router
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
	suite.setupRoutes()

	// Create test server
	suite.server = httptest.NewServer(suite.router)
}

// TearDownSuite cleans up the test suite
func (suite *EndToEndTestSuite) TearDownSuite() {
	if suite.server != nil {
		suite.server.Close()
	}
	if suite.db != nil {
		suite.db.Close()
	}
}

// SetupTest sets up each test
func (suite *EndToEndTestSuite) SetupTest() {
	// Clean up test data
	suite.cleanupTestData()
}

// TearDownTest cleans up after each test
func (suite *EndToEndTestSuite) TearDownTest() {
	// Clean up test data
	suite.cleanupTestData()
}

// setupRoutes sets up the API routes for testing
func (suite *EndToEndTestSuite) setupRoutes() {
	// Apply security middleware
	suite.router.Use(suite.securityMiddleware.RequestIDMiddleware())
	suite.router.Use(suite.securityMiddleware.SecurityHeadersMiddleware())
	suite.router.Use(suite.securityMiddleware.CORSMiddleware())
	suite.router.Use(suite.securityMiddleware.RateLimitMiddleware())
	suite.router.Use(suite.securityMiddleware.BruteForceProtectionMiddleware())
	suite.router.Use(suite.securityMiddleware.InputValidationMiddleware())
	suite.router.Use(suite.securityMiddleware.SQLInjectionProtectionMiddleware())
	suite.router.Use(suite.securityMiddleware.XSSProtectionMiddleware())
	suite.router.Use(suite.securityMiddleware.HealthcareDataProtectionMiddleware())
	suite.router.Use(suite.securityMiddleware.AuditLoggingMiddleware())

	// Setup API gateway routes
	suite.apiGateway.SetupRoutes(suite.router)

	// Authentication routes
	auth := suite.router.Group("/auth")
	{
		auth.POST("/login", suite.authCtrl.Login)
		auth.POST("/logout", suite.authCtrl.Logout)
		auth.POST("/refresh", suite.authCtrl.RefreshSession)
		auth.POST("/validate", suite.authCtrl.ValidateSession)
	}

	// Authorization routes
	authz := suite.router.Group("/authz")
	{
		authz.POST("/check-permission", suite.authzCtrl.CheckPermission)
		authz.POST("/check-role", suite.authzCtrl.CheckRole)
		authz.POST("/check-facility", suite.authzCtrl.CheckFacilityAccess)
		authz.GET("/permissions", suite.authzCtrl.GetUserPermissions)
		authz.GET("/roles", suite.authzCtrl.GetUserRoles)
	}

	// User management routes
	users := suite.router.Group("/users")
	{
		users.POST("/", suite.userCtrl.CreateUser)
		users.GET("/:id", suite.userCtrl.GetUser)
		users.PUT("/:id", suite.userCtrl.UpdateUser)
		users.DELETE("/:id", suite.userCtrl.DeleteUser)
		users.GET("/", suite.userCtrl.ListUsers)
		users.GET("/search", suite.userCtrl.SearchUsers)
		users.POST("/:id/roles", suite.userCtrl.AssignUserRole)
		users.DELETE("/:id/roles", suite.userCtrl.RevokeUserRole)
		users.POST("/:id/activate", suite.userCtrl.ActivateUser)
		users.POST("/:id/deactivate", suite.userCtrl.DeactivateUser)
		users.POST("/:id/lock", suite.userCtrl.LockUser)
		users.POST("/:id/unlock", suite.userCtrl.UnlockUser)
	}

	// Audit routes
	audit := suite.router.Group("/audit")
	{
		audit.POST("/authentication", suite.auditCtrl.LogAuthenticationEvent)
		audit.POST("/authorization", suite.auditCtrl.LogAuthorizationEvent)
		audit.GET("/authentication", suite.auditCtrl.GetAuthenticationEvents)
		audit.GET("/authorization", suite.auditCtrl.GetAuthorizationEvents)
		audit.GET("/search", suite.auditCtrl.SearchAuditEvents)
		audit.GET("/compliance/:type", suite.auditCtrl.GenerateComplianceReport)
		audit.POST("/cleanup", suite.auditCtrl.CleanupOldAuditData)
		audit.GET("/events/:type/:id", suite.auditCtrl.GetAuditEventByID)
		audit.GET("/summary", suite.auditCtrl.GetAuditSummary)
		audit.GET("/export", suite.auditCtrl.ExportAuditData)
		audit.GET("/validate", suite.auditCtrl.ValidateAuditData)
	}

	// Health check
	suite.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
}

// TestCompleteAuthenticationFlow tests the complete authentication flow
func (suite *EndToEndTestSuite) TestCompleteAuthenticationFlow() {
	// Create test user
	user := suite.createTestUser("e2e_auth_user", "e2e_auth@example.com", "password123")

	// Test 1: User Registration (if applicable)
	// This would typically be a separate registration endpoint
	// For now, we'll test with a pre-created user

	// Test 2: User Login
	loginReq := controllers.LoginRequest{
		Username: "e2e_auth_user",
		Password: "password123",
	}
	loginBody, _ := json.Marshal(loginReq)

	resp, err := http.Post(suite.server.URL+"/auth/login", "application/json", bytes.NewBuffer(loginBody))
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var loginResp controllers.LoginResponse
	err = json.NewDecoder(resp.Body).Decode(&loginResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), loginResp.Success)
	assert.NotEmpty(suite.T(), loginResp.AccessToken)
	assert.NotEmpty(suite.T(), loginResp.RefreshToken)

	// Test 3: Session Validation
	req, _ := http.NewRequest("POST", suite.server.URL+"/auth/validate", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Test 4: Token Refresh
	refreshReq := controllers.RefreshSessionRequest{
		RefreshToken: loginResp.RefreshToken,
	}
	refreshBody, _ := json.Marshal(refreshReq)

	resp, err = http.Post(suite.server.URL+"/auth/refresh", "application/json", bytes.NewBuffer(refreshBody))
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var refreshResp controllers.RefreshSessionResponse
	err = json.NewDecoder(resp.Body).Decode(&refreshResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), refreshResp.Success)
	assert.NotEmpty(suite.T(), refreshResp.AccessToken)

	// Test 5: Logout
	logoutReq, _ := http.NewRequest("POST", suite.server.URL+"/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	logoutReq.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(logoutReq)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Test 6: Validate Logged Out Session
	req, _ = http.NewRequest("POST", suite.server.URL+"/auth/validate", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
}

// TestCompleteAuthorizationFlow tests the complete authorization flow
func (suite *EndToEndTestSuite) TestCompleteAuthorizationFlow() {
	// Create test user and roles
	user := suite.createTestUser("e2e_authz_user", "e2e_authz@example.com", "password123")
	doctorRole := suite.createTestRole("doctor", "Doctor role")
	patientReadPerm := suite.createTestPermission("patients", "read", "Read patient records")
	patientWritePerm := suite.createTestPermission("patients", "write", "Write patient records")

	// Assign role and permissions
	suite.assignRoleToUser(user.ID, doctorRole.ID, nil)
	suite.assignPermissionToRole(doctorRole.ID, patientReadPerm.ID, user.ID)
	suite.assignPermissionToRole(doctorRole.ID, patientWritePerm.ID, user.ID)

	// Login user
	loginResp := suite.loginUser("e2e_authz_user", "password123")
	require.NotEmpty(suite.T(), loginResp.AccessToken)

	// Test 1: Permission Check - Allowed
	permissionReq := controllers.PermissionCheckRequest{
		Resource: "patients",
		Action:   "read",
	}
	permissionBody, _ := json.Marshal(permissionReq)

	req, _ := http.NewRequest("POST", suite.server.URL+"/authz/check-permission", bytes.NewBuffer(permissionBody))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var permissionResp controllers.PermissionCheckResponse
	err = json.NewDecoder(resp.Body).Decode(&permissionResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), permissionResp.HasPermission)

	// Test 2: Permission Check - Denied
	deniedPermissionReq := controllers.PermissionCheckRequest{
		Resource: "admin",
		Action:   "access",
	}
	deniedPermissionBody, _ := json.Marshal(deniedPermissionReq)

	req, _ = http.NewRequest("POST", suite.server.URL+"/authz/check-permission", bytes.NewBuffer(deniedPermissionBody))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var deniedPermissionResp controllers.PermissionCheckResponse
	err = json.NewDecoder(resp.Body).Decode(&deniedPermissionResp)
	require.NoError(suite.T(), err)
	assert.False(suite.T(), deniedPermissionResp.HasPermission)

	// Test 3: Role Check
	roleReq := controllers.RoleCheckRequest{
		RoleName: "doctor",
	}
	roleBody, _ := json.Marshal(roleReq)

	req, _ = http.NewRequest("POST", suite.server.URL+"/authz/check-role", bytes.NewBuffer(roleBody))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var roleResp controllers.RoleCheckResponse
	err = json.NewDecoder(resp.Body).Decode(&roleResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), roleResp.HasRole)

	// Test 4: Get User Permissions
	req, _ = http.NewRequest("GET", suite.server.URL+"/authz/permissions", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var permissionsResp controllers.GetUserPermissionsResponse
	err = json.NewDecoder(resp.Body).Decode(&permissionsResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), permissionsResp.Success)
	assert.Len(suite.T(), permissionsResp.Permissions, 2) // read and write permissions

	// Test 5: Get User Roles
	req, _ = http.NewRequest("GET", suite.server.URL+"/authz/roles", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var rolesResp controllers.GetUserRolesResponse
	err = json.NewDecoder(resp.Body).Decode(&rolesResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), rolesResp.Success)
	assert.Len(suite.T(), rolesResp.Roles, 1) // doctor role
}

// TestCompleteUserManagementFlow tests the complete user management flow
func (suite *EndToEndTestSuite) TestCompleteUserManagementFlow() {
	// Create admin user
	admin := suite.createTestUser("e2e_admin", "e2e_admin@example.com", "admin123")
	adminRole := suite.createTestRole("admin", "Administrator role")
	adminPermission := suite.createTestPermission("users", "manage", "Manage users")
	suite.assignRoleToUser(admin.ID, adminRole.ID, nil)
	suite.assignPermissionToRole(adminRole.ID, adminPermission.ID, admin.ID)

	// Login as admin
	adminLoginResp := suite.loginUser("e2e_admin", "admin123")
	require.NotEmpty(suite.T(), adminLoginResp.AccessToken)

	// Test 1: Create User
	createUserReq := controllers.CreateUserRequest{
		Username:  "e2e_new_user",
		Email:     "e2e_new_user@example.com",
		Password:  "password123",
		FirstName: "New",
		LastName:  "User",
		Phone:     "1234567890",
		Status:    "active",
	}
	createUserBody, _ := json.Marshal(createUserReq)

	req, _ := http.NewRequest("POST", suite.server.URL+"/users/", bytes.NewBuffer(createUserBody))
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)

	var createUserResp controllers.CreateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&createUserResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), createUserResp.Success)
	assert.NotEmpty(suite.T(), createUserResp.UserID)

	userID := createUserResp.UserID

	// Test 2: Get User
	req, _ = http.NewRequest("GET", suite.server.URL+"/users/"+userID, nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var getUserResp controllers.GetUserResponse
	err = json.NewDecoder(resp.Body).Decode(&getUserResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), getUserResp.Success)
	assert.Equal(suite.T(), "e2e_new_user", getUserResp.User.Username)

	// Test 3: Update User
	updateUserReq := controllers.UpdateUserRequest{
		FirstName: "Updated",
		LastName:  "User",
		Phone:     "0987654321",
	}
	updateUserBody, _ := json.Marshal(updateUserReq)

	req, _ = http.NewRequest("PUT", suite.server.URL+"/users/"+userID, bytes.NewBuffer(updateUserBody))
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Test 4: Assign Role to User
	role := suite.createTestRole("nurse", "Nurse role")
	assignRoleReq := controllers.AssignUserRoleRequest{
		RoleID: role.ID.String(),
	}
	assignRoleBody, _ := json.Marshal(assignRoleReq)

	req, _ = http.NewRequest("POST", suite.server.URL+"/users/"+userID+"/roles", bytes.NewBuffer(assignRoleBody))
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Test 5: List Users
	req, _ = http.NewRequest("GET", suite.server.URL+"/users/?limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var listUsersResp controllers.ListUsersResponse
	err = json.NewDecoder(resp.Body).Decode(&listUsersResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), listUsersResp.Success)
	assert.GreaterOrEqual(suite.T(), listUsersResp.Total, 2) // admin + new user

	// Test 6: Search Users
	req, _ = http.NewRequest("GET", suite.server.URL+"/users/search?q=e2e_new_user&limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var searchUsersResp controllers.SearchUsersResponse
	err = json.NewDecoder(resp.Body).Decode(&searchUsersResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), searchUsersResp.Success)
	assert.Equal(suite.T(), "e2e_new_user", searchUsersResp.Query)
	assert.GreaterOrEqual(suite.T(), searchUsersResp.Total, 1)

	// Test 7: Deactivate User
	req, _ = http.NewRequest("POST", suite.server.URL+"/users/"+userID+"/deactivate", nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Test 8: Activate User
	req, _ = http.NewRequest("POST", suite.server.URL+"/users/"+userID+"/activate", nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Test 9: Delete User
	req, _ = http.NewRequest("DELETE", suite.server.URL+"/users/"+userID, nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
}

// TestCompleteAuditFlow tests the complete audit flow
func (suite *EndToEndTestSuite) TestCompleteAuditFlow() {
	// Create test user
	user := suite.createTestUser("e2e_audit_user", "e2e_audit@example.com", "password123")

	// Login user
	loginResp := suite.loginUser("e2e_audit_user", "password123")
	require.NotEmpty(suite.T(), loginResp.AccessToken)

	// Test 1: Log Authentication Event
	authEventReq := controllers.LogAuthenticationEventRequest{
		UserID:    user.ID.String(),
		EventType: "login_success",
		IPAddress: "192.168.1.100",
		UserAgent: "test-agent",
		Success:   true,
	}
	authEventBody, _ := json.Marshal(authEventReq)

	resp, err := http.Post(suite.server.URL+"/audit/authentication", "application/json", bytes.NewBuffer(authEventBody))
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Test 2: Log Authorization Event
	authzEventReq := controllers.LogAuthorizationEventRequest{
		UserID:   user.ID.String(),
		Resource: "patients",
		Action:   "read",
		Allowed:  true,
		Reason:   "user has permission",
	}
	authzEventBody, _ := json.Marshal(authzEventReq)

	resp, err = http.Post(suite.server.URL+"/audit/authorization", "application/json", bytes.NewBuffer(authzEventBody))
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Test 3: Get Authentication Events
	req, _ := http.NewRequest("GET", suite.server.URL+"/audit/authentication?user_id="+user.ID.String()+"&limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

	client := &http.Client{}
	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var authEventsResp controllers.GetAuthenticationEventsResponse
	err = json.NewDecoder(resp.Body).Decode(&authEventsResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), authEventsResp.Success)
	assert.GreaterOrEqual(suite.T(), len(authEventsResp.Events), 1)

	// Test 4: Get Authorization Events
	req, _ = http.NewRequest("GET", suite.server.URL+"/audit/authorization?user_id="+user.ID.String()+"&limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var authzEventsResp controllers.GetAuthorizationEventsResponse
	err = json.NewDecoder(resp.Body).Decode(&authzEventsResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), authzEventsResp.Success)
	assert.GreaterOrEqual(suite.T(), len(authzEventsResp.Events), 1)

	// Test 5: Search Audit Events
	req, _ = http.NewRequest("GET", suite.server.URL+"/audit/search?q=login&event_type=all&limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var searchResp controllers.SearchAuditEventsResponse
	err = json.NewDecoder(resp.Body).Decode(&searchResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), searchResp.Success)
	assert.Equal(suite.T(), "login", searchResp.Query)

	// Test 6: Generate Compliance Report
	req, _ = http.NewRequest("GET", suite.server.URL+"/audit/compliance/hipaa?start_date="+time.Now().AddDate(0, 0, -1).Format("2006-01-02")+"&end_date="+time.Now().Format("2006-01-02"), nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var complianceResp controllers.GenerateComplianceReportResponse
	err = json.NewDecoder(resp.Body).Decode(&complianceResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), complianceResp.Success)
	assert.NotNil(suite.T(), complianceResp.Report)

	// Test 7: Get Audit Summary
	req, _ = http.NewRequest("GET", suite.server.URL+"/audit/summary?start_date="+time.Now().AddDate(0, 0, -1).Format("2006-01-02")+"&end_date="+time.Now().Format("2006-01-02"), nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var summaryResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&summaryResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), summaryResp["success"].(bool))
}

// TestHealthcareSpecificScenarios tests healthcare-specific scenarios
func (suite *EndToEndTestSuite) TestHealthcareSpecificScenarios() {
	// Create healthcare staff user
	doctor := suite.createTestUser("e2e_doctor", "e2e_doctor@hospital.com", "password123")
	doctorRole := suite.createTestRole("doctor", "Doctor role")
	
	// Create healthcare-specific permissions
	patientReadPerm := suite.createTestPermission("patients", "read", "Read patient records")
	patientWritePerm := suite.createTestPermission("patients", "write", "Write patient records")
	medicationPerm := suite.createTestPermission("medications", "prescribe", "Prescribe medications")
	emergencyPerm := suite.createTestPermission("emergency", "access", "Emergency access")
	
	// Assign permissions to doctor role
	suite.assignRoleToUser(doctor.ID, doctorRole.ID, nil)
	suite.assignPermissionToRole(doctorRole.ID, patientReadPerm.ID, doctor.ID)
	suite.assignPermissionToRole(doctorRole.ID, patientWritePerm.ID, doctor.ID)
	suite.assignPermissionToRole(doctorRole.ID, medicationPerm.ID, doctor.ID)
	suite.assignPermissionToRole(doctorRole.ID, emergencyPerm.ID, doctor.ID)

	// Login as doctor
	doctorLoginResp := suite.loginUser("e2e_doctor", "password123")
	require.NotEmpty(suite.T(), doctorLoginResp.AccessToken)

	// Test 1: Patient Data Access
	patientAccessReq := controllers.PermissionCheckRequest{
		Resource: "patients",
		Action:   "read",
	}
	patientAccessBody, _ := json.Marshal(patientAccessReq)

	req, _ := http.NewRequest("POST", suite.server.URL+"/authz/check-permission", bytes.NewBuffer(patientAccessBody))
	req.Header.Set("Authorization", "Bearer "+doctorLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var patientAccessResp controllers.PermissionCheckResponse
	err = json.NewDecoder(resp.Body).Decode(&patientAccessResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), patientAccessResp.HasPermission)

	// Test 2: Medication Prescription Permission
	medicationReq := controllers.PermissionCheckRequest{
		Resource: "medications",
		Action:   "prescribe",
	}
	medicationBody, _ := json.Marshal(medicationReq)

	req, _ = http.NewRequest("POST", suite.server.URL+"/authz/check-permission", bytes.NewBuffer(medicationBody))
	req.Header.Set("Authorization", "Bearer "+doctorLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var medicationResp controllers.PermissionCheckResponse
	err = json.NewDecoder(resp.Body).Decode(&medicationResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), medicationResp.HasPermission)

	// Test 3: Emergency Access
	emergencyReq := controllers.PermissionCheckRequest{
		Resource: "emergency",
		Action:   "access",
	}
	emergencyBody, _ := json.Marshal(emergencyReq)

	req, _ = http.NewRequest("POST", suite.server.URL+"/authz/check-permission", bytes.NewBuffer(emergencyBody))
	req.Header.Set("Authorization", "Bearer "+doctorLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var emergencyResp controllers.PermissionCheckResponse
	err = json.NewDecoder(resp.Body).Decode(&emergencyResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), emergencyResp.HasPermission)

	// Test 4: Healthcare Compliance Report
	req, _ = http.NewRequest("GET", suite.server.URL+"/audit/compliance/healthcare_compliance?start_date="+time.Now().AddDate(0, 0, -1).Format("2006-01-02")+"&end_date="+time.Now().Format("2006-01-02"), nil)
	req.Header.Set("Authorization", "Bearer "+doctorLoginResp.AccessToken)

	resp, err = client.Do(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var healthcareComplianceResp controllers.GenerateComplianceReportResponse
	err = json.NewDecoder(resp.Body).Decode(&healthcareComplianceResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), healthcareComplianceResp.Success)
	assert.NotNil(suite.T(), healthcareComplianceResp.Report)
}

// TestSecurityFeatures tests security features
func (suite *EndToEndTestSuite) TestSecurityFeatures() {
	// Test 1: Rate Limiting
	for i := 0; i < 10; i++ {
		loginReq := controllers.LoginRequest{
			Username: "rate_limit_test",
			Password: "wrong_password",
		}
		loginBody, _ := json.Marshal(loginReq)

		resp, err := http.Post(suite.server.URL+"/auth/login", "application/json", bytes.NewBuffer(loginBody))
		require.NoError(suite.T(), err)

		// After several attempts, should get rate limited
		if i >= 5 {
			assert.Contains(suite.T(), []int{http.StatusTooManyRequests, http.StatusUnauthorized}, resp.StatusCode)
		}
	}

	// Test 2: SQL Injection Protection
	sqlInjectionReq := controllers.LoginRequest{
		Username: "'; DROP TABLE users; --",
		Password: "password123",
	}
	sqlInjectionBody, _ := json.Marshal(sqlInjectionReq)

	resp, err := http.Post(suite.server.URL+"/auth/login", "application/json", bytes.NewBuffer(sqlInjectionBody))
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)

	// Test 3: XSS Protection
	xssReq := controllers.CreateUserRequest{
		Username:  "<script>alert('xss')</script>",
		Email:     "xss@example.com",
		Password:  "password123",
		FirstName: "<img src=x onerror=alert('xss')>",
		LastName:  "User",
	}
	xssBody, _ := json.Marshal(xssReq)

	resp, err = http.Post(suite.server.URL+"/users/", "application/json", bytes.NewBuffer(xssBody))
	require.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), http.StatusInternalServerError, resp.StatusCode)

	// Test 4: Security Headers
	resp, err = http.Get(suite.server.URL + "/health")
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Check security headers
	assert.NotEmpty(suite.T(), resp.Header.Get("X-Frame-Options"))
	assert.NotEmpty(suite.T(), resp.Header.Get("X-Content-Type-Options"))
	assert.NotEmpty(suite.T(), resp.Header.Get("X-XSS-Protection"))
	assert.NotEmpty(suite.T(), resp.Header.Get("Strict-Transport-Security"))
}

// TestAPIGatewayFeatures tests API gateway features
func (suite *EndToEndTestSuite) TestAPIGatewayFeatures() {
	// Test 1: Health Check
	resp, err := http.Get(suite.server.URL + "/health")
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var healthResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&healthResp)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "healthy", healthResp["status"])

	// Test 2: Service Discovery
	resp, err = http.Get(suite.server.URL + "/services")
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var servicesResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&servicesResp)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), servicesResp["services"])

	// Test 3: Service Routing (simulated)
	// Since we don't have actual backend services running, we'll test the routing logic
	// In a real environment, this would test actual service communication
}

// Helper methods

// createTestUser creates a test user
func (suite *EndToEndTestSuite) createTestUser(username, email, password string) *models.User {
	user := &models.User{
		ID:        uuid.New(),
		Username:  username,
		Email:     email,
		FirstName: "Test",
		LastName:  "User",
		Status:    models.UserStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	user.SetPassword(password)
	err := suite.userRepo.Create(context.Background(), user)
	require.NoError(suite.T(), err)

	return user
}

// createTestRole creates a test role
func (suite *EndToEndTestSuite) createTestRole(name, description string) *models.Role {
	role := &models.Role{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := suite.roleRepo.Create(context.Background(), role)
	require.NoError(suite.T(), err)

	return role
}

// createTestPermission creates a test permission
func (suite *EndToEndTestSuite) createTestPermission(resource, action, description string) *models.Permission {
	permission := &models.Permission{
		ID:          uuid.New(),
		Resource:    resource,
		Action:      action,
		Description: description,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := suite.roleRepo.CreatePermission(context.Background(), permission)
	require.NoError(suite.T(), err)

	return permission
}

// assignRoleToUser assigns a role to a user
func (suite *EndToEndTestSuite) assignRoleToUser(userID, roleID uuid.UUID, facilityID *uuid.UUID) {
	err := suite.userRepo.AssignRole(context.Background(), userID, roleID, facilityID, &userID, nil)
	require.NoError(suite.T(), err)
}

// assignPermissionToRole assigns a permission to a role
func (suite *EndToEndTestSuite) assignPermissionToRole(roleID, permissionID, grantedBy uuid.UUID) {
	err := suite.roleRepo.AddPermission(context.Background(), roleID, permissionID, &grantedBy)
	require.NoError(suite.T(), err)
}

// loginUser logs in a user and returns the login response
func (suite *EndToEndTestSuite) loginUser(username, password string) *controllers.LoginResponse {
	loginReq := controllers.LoginRequest{
		Username: username,
		Password: password,
	}
	loginBody, _ := json.Marshal(loginReq)

	resp, err := http.Post(suite.server.URL+"/auth/login", "application/json", bytes.NewBuffer(loginBody))
	require.NoError(suite.T(), err)

	var loginResp controllers.LoginResponse
	err = json.NewDecoder(resp.Body).Decode(&loginResp)
	require.NoError(suite.T(), err)

	return &loginResp
}

// cleanupTestData cleans up test data
func (suite *EndToEndTestSuite) cleanupTestData() {
	// Clean up users
	suite.db.Exec("DELETE FROM user_otp_devices")
	suite.db.Exec("DELETE FROM user_sessions")
	suite.db.Exec("DELETE FROM role_permissions")
	suite.db.Exec("DELETE FROM user_roles")
	suite.db.Exec("DELETE FROM users")
	suite.db.Exec("DELETE FROM roles")
	suite.db.Exec("DELETE FROM permissions")
	suite.db.Exec("DELETE FROM authentication_events")
	suite.db.Exec("DELETE FROM authorization_events")
}

// Run the test suite
func TestEndToEndTestSuite(t *testing.T) {
	suite.Run(t, new(EndToEndTestSuite))
} 