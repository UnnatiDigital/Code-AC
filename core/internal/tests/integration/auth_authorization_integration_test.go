package integration

import (
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
	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/repositories"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// AuthAuthorizationIntegrationTestSuite provides integration tests for authentication and authorization
type AuthAuthorizationIntegrationTestSuite struct {
	suite.Suite
	db           *sql.DB
	redisCache   *cache.RedisCache
	userRepo     repositories.UserRepository
	roleRepo     repositories.RoleRepository
	auditRepo    repositories.AuditRepository
	authService  services.AuthenticationService
	authzService services.AuthorizationService
	auditService services.AuditService
	authCtrl     *controllers.AuthenticationController
	authzCtrl    *controllers.AuthorizationController
	userCtrl     *controllers.UserManagementController
	auditCtrl    *controllers.AuditController
	router       *gin.Engine
}

// SetupSuite sets up the test suite
func (suite *AuthAuthorizationIntegrationTestSuite) SetupSuite() {
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

	// Initialize controllers
	suite.authCtrl = controllers.NewAuthenticationController(suite.authService, suite.auditService)
	suite.authzCtrl = controllers.NewAuthorizationController(suite.authzService)
	suite.userCtrl = controllers.NewUserManagementController(suite.userRepo, suite.roleRepo)
	suite.auditCtrl = controllers.NewAuditController(suite.auditService)

	// Setup router
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
	suite.setupRoutes()
}

// TearDownSuite cleans up the test suite
func (suite *AuthAuthorizationIntegrationTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
}

// SetupTest sets up each test
func (suite *AuthAuthorizationIntegrationTestSuite) SetupTest() {
	// Clean up test data
	suite.cleanupTestData()
}

// TearDownTest cleans up after each test
func (suite *AuthAuthorizationIntegrationTestSuite) TearDownTest() {
	// Clean up test data
	suite.cleanupTestData()
}

// setupRoutes sets up the API routes for testing
func (suite *AuthAuthorizationIntegrationTestSuite) setupRoutes() {
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
}

// cleanupTestData cleans up test data
func (suite *AuthAuthorizationIntegrationTestSuite) cleanupTestData() {
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

// TestEndToEndAuthenticationFlow tests the complete authentication flow
func (suite *AuthAuthorizationIntegrationTestSuite) TestEndToEndAuthenticationFlow() {
	// Create test user
	user := suite.createTestUser("testuser", "test@example.com", "password123")

	// Test login
	loginReq := controllers.LoginRequest{
		Username: "testuser",
		Password: "password123",
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
	assert.True(suite.T(), loginResp.Success)
	assert.NotEmpty(suite.T(), loginResp.AccessToken)
	assert.NotEmpty(suite.T(), loginResp.RefreshToken)

	// Test session validation
	validateReq := httptest.NewRequest("POST", "/auth/validate", nil)
	validateReq.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	w = httptest.NewRecorder()
	suite.router.ServeHTTP(w, validateReq)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Test logout
	logoutReq := httptest.NewRequest("POST", "/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	w = httptest.NewRecorder()
	suite.router.ServeHTTP(w, logoutReq)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
}

// TestEndToEndAuthorizationFlow tests the complete authorization flow
func (suite *AuthAuthorizationIntegrationTestSuite) TestEndToEndAuthorizationFlow() {
	// Create test user and role
	user := suite.createTestUser("authuser", "auth@example.com", "password123")
	role := suite.createTestRole("doctor", "Doctor role")
	permission := suite.createTestPermission("patients", "read", "Read patient records")

	// Assign role and permission
	suite.assignRoleToUser(user.ID, role.ID, nil)
	suite.assignPermissionToRole(role.ID, permission.ID, user.ID)

	// Login user
	loginResp := suite.loginUser("authuser", "password123")
	require.NotEmpty(suite.T(), loginResp.AccessToken)

	// Test permission check
	permissionReq := controllers.PermissionCheckRequest{
		Resource: "patients",
		Action:   "read",
	}
	permissionBody, _ := json.Marshal(permissionReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(permissionBody)))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var permissionResp controllers.PermissionCheckResponse
	err := json.Unmarshal(w.Body.Bytes(), &permissionResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), permissionResp.HasPermission)

	// Test role check
	roleReq := controllers.RoleCheckRequest{
		RoleName: "doctor",
	}
	roleBody, _ := json.Marshal(roleReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-role", strings.NewReader(string(roleBody)))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var roleResp controllers.RoleCheckResponse
	err = json.Unmarshal(w.Body.Bytes(), &roleResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), roleResp.HasRole)
}

// TestUserManagementWorkflow tests the complete user management workflow
func (suite *AuthAuthorizationIntegrationTestSuite) TestUserManagementWorkflow() {
	// Create admin user
	admin := suite.createTestUser("admin", "admin@example.com", "admin123")
	adminRole := suite.createTestRole("admin", "Administrator role")
	adminPermission := suite.createTestPermission("users", "manage", "Manage users")
	suite.assignRoleToUser(admin.ID, adminRole.ID, nil)
	suite.assignPermissionToRole(adminRole.ID, adminPermission.ID, admin.ID)

	// Login as admin
	adminLoginResp := suite.loginUser("admin", "admin123")
	require.NotEmpty(suite.T(), adminLoginResp.AccessToken)

	// Create new user
	createUserReq := controllers.CreateUserRequest{
		Username:  "newuser",
		Email:     "newuser@example.com",
		Password:  "password123",
		FirstName: "New",
		LastName:  "User",
		Phone:     "1234567890",
		Status:    "active",
	}
	createUserBody, _ := json.Marshal(createUserReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/users/", strings.NewReader(string(createUserBody)))
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	var createUserResp controllers.CreateUserResponse
	err := json.Unmarshal(w.Body.Bytes(), &createUserResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), createUserResp.Success)
	assert.NotEmpty(suite.T(), createUserResp.UserID)

	// Get user
	userID := createUserResp.UserID
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/users/"+userID, nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var getUserResp controllers.GetUserResponse
	err = json.Unmarshal(w.Body.Bytes(), &getUserResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), getUserResp.Success)
	assert.Equal(suite.T(), "newuser", getUserResp.User.Username)

	// Update user
	updateUserReq := controllers.UpdateUserRequest{
		FirstName: "Updated",
		LastName:  "User",
		Phone:     "0987654321",
	}
	updateUserBody, _ := json.Marshal(updateUserReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/users/"+userID, strings.NewReader(string(updateUserBody)))
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// List users
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/users/?limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var listUsersResp controllers.ListUsersResponse
	err = json.Unmarshal(w.Body.Bytes(), &listUsersResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), listUsersResp.Success)
	assert.GreaterOrEqual(suite.T(), listUsersResp.Total, 2) // admin + newuser

	// Search users
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/users/search?q=newuser&limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var searchUsersResp controllers.SearchUsersResponse
	err = json.Unmarshal(w.Body.Bytes(), &searchUsersResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), searchUsersResp.Success)
	assert.Equal(suite.T(), "newuser", searchUsersResp.Query)
	assert.GreaterOrEqual(suite.T(), searchUsersResp.Total, 1)
}

// TestAuditTrailValidation tests the complete audit trail validation
func (suite *AuthAuthorizationIntegrationTestSuite) TestAuditTrailValidation() {
	// Create test user
	user := suite.createTestUser("audituser", "audit@example.com", "password123")

	// Login user (should create authentication event)
	loginResp := suite.loginUser("audituser", "password123")
	require.NotEmpty(suite.T(), loginResp.AccessToken)

	// Check authentication events
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/audit/authentication?user_id="+user.ID.String()+"&limit=10&offset=0", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var authEventsResp controllers.GetAuthenticationEventsResponse
	err := json.Unmarshal(w.Body.Bytes(), &authEventsResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), authEventsResp.Success)
	assert.GreaterOrEqual(suite.T(), len(authEventsResp.Events), 1)

	// Create role and permission for authorization testing
	role := suite.createTestRole("nurse", "Nurse role")
	permission := suite.createTestPermission("patients", "read", "Read patient records")
	suite.assignRoleToUser(user.ID, role.ID, nil)
	suite.assignPermissionToRole(role.ID, permission.ID, user.ID)

	// Test permission check (should create authorization event)
	permissionReq := controllers.PermissionCheckRequest{
		Resource: "patients",
		Action:   "read",
	}
	permissionBody, _ := json.Marshal(permissionReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(permissionBody)))
	req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Check authorization events
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/audit/authorization?user_id="+user.ID.String()+"&limit=10&offset=0", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var authzEventsResp controllers.GetAuthorizationEventsResponse
	err = json.Unmarshal(w.Body.Bytes(), &authzEventsResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), authzEventsResp.Success)
	assert.GreaterOrEqual(suite.T(), len(authzEventsResp.Events), 1)

	// Test audit summary
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/audit/summary?start_date="+time.Now().AddDate(0, 0, -1).Format("2006-01-02")+"&end_date="+time.Now().Format("2006-01-02"), nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var summaryResp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &summaryResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), summaryResp["success"].(bool))

	// Test compliance report
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/audit/compliance/hipaa?start_date="+time.Now().AddDate(0, 0, -1).Format("2006-01-02")+"&end_date="+time.Now().Format("2006-01-02"), nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var complianceResp controllers.GenerateComplianceReportResponse
	err = json.Unmarshal(w.Body.Bytes(), &complianceResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), complianceResp.Success)
	assert.NotNil(suite.T(), complianceResp.Report)
}

// TestHealthcareSpecificScenarios tests healthcare-specific scenarios
func (suite *AuthAuthorizationIntegrationTestSuite) TestHealthcareSpecificScenarios() {
	// Create healthcare staff user
	doctor := suite.createTestUser("doctor", "doctor@hospital.com", "password123")
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
	doctorLoginResp := suite.loginUser("doctor", "password123")
	require.NotEmpty(suite.T(), doctorLoginResp.AccessToken)

	// Test patient data access
	patientAccessReq := controllers.PermissionCheckRequest{
		Resource: "patients",
		Action:   "read",
	}
	patientAccessBody, _ := json.Marshal(patientAccessReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(patientAccessBody)))
	req.Header.Set("Authorization", "Bearer "+doctorLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var patientAccessResp controllers.PermissionCheckResponse
	err := json.Unmarshal(w.Body.Bytes(), &patientAccessResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), patientAccessResp.HasPermission)

	// Test medication prescription permission
	medicationReq := controllers.PermissionCheckRequest{
		Resource: "medications",
		Action:   "prescribe",
	}
	medicationBody, _ := json.Marshal(medicationReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(medicationBody)))
	req.Header.Set("Authorization", "Bearer "+doctorLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var medicationResp controllers.PermissionCheckResponse
	err = json.Unmarshal(w.Body.Bytes(), &medicationResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), medicationResp.HasPermission)

	// Test emergency access
	emergencyReq := controllers.PermissionCheckRequest{
		Resource: "emergency",
		Action:   "access",
	}
	emergencyBody, _ := json.Marshal(emergencyReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(emergencyBody)))
	req.Header.Set("Authorization", "Bearer "+doctorLoginResp.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var emergencyResp controllers.PermissionCheckResponse
	err = json.Unmarshal(w.Body.Bytes(), &emergencyResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), emergencyResp.HasPermission)

	// Test healthcare compliance report
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/audit/compliance/healthcare_compliance?start_date="+time.Now().AddDate(0, 0, -1).Format("2006-01-02")+"&end_date="+time.Now().Format("2006-01-02"), nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var healthcareComplianceResp controllers.GenerateComplianceReportResponse
	err = json.Unmarshal(w.Body.Bytes(), &healthcareComplianceResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), healthcareComplianceResp.Success)
	assert.NotNil(suite.T(), healthcareComplianceResp.Report)
}

// TestErrorScenarios tests various error scenarios
func (suite *AuthAuthorizationIntegrationTestSuite) TestErrorScenarios() {
	// Test invalid login
	invalidLoginReq := controllers.LoginRequest{
		Username: "nonexistent",
		Password: "wrongpassword",
	}
	invalidLoginBody, _ := json.Marshal(invalidLoginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(invalidLoginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test invalid token
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/auth/validate", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test permission check without authentication
	permissionReq := controllers.PermissionCheckRequest{
		Resource: "patients",
		Action:   "read",
	}
	permissionBody, _ := json.Marshal(permissionReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/authz/check-permission", strings.NewReader(string(permissionBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test user creation with duplicate username
	user := suite.createTestUser("duplicate", "duplicate@example.com", "password123")

	duplicateUserReq := controllers.CreateUserRequest{
		Username:  "duplicate",
		Email:     "another@example.com",
		Password:  "password123",
		FirstName: "Another",
		LastName:  "User",
	}
	duplicateUserBody, _ := json.Marshal(duplicateUserReq)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/users/", strings.NewReader(string(duplicateUserBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusConflict, w.Code)
}

// Helper methods

// createTestUser creates a test user
func (suite *AuthAuthorizationIntegrationTestSuite) createTestUser(username, email, password string) *models.User {
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
func (suite *AuthAuthorizationIntegrationTestSuite) createTestRole(name, description string) *models.Role {
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
func (suite *AuthAuthorizationIntegrationTestSuite) createTestPermission(resource, action, description string) *models.Permission {
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
func (suite *AuthAuthorizationIntegrationTestSuite) assignRoleToUser(userID, roleID uuid.UUID, facilityID *uuid.UUID) {
	err := suite.userRepo.AssignRole(context.Background(), userID, roleID, facilityID, &userID, nil)
	require.NoError(suite.T(), err)
}

// assignPermissionToRole assigns a permission to a role
func (suite *AuthAuthorizationIntegrationTestSuite) assignPermissionToRole(roleID, permissionID, grantedBy uuid.UUID) {
	err := suite.roleRepo.AddPermission(context.Background(), roleID, permissionID, &grantedBy)
	require.NoError(suite.T(), err)
}

// loginUser logs in a user and returns the login response
func (suite *AuthAuthorizationIntegrationTestSuite) loginUser(username, password string) *controllers.LoginResponse {
	loginReq := controllers.LoginRequest{
		Username: username,
		Password: password,
	}
	loginBody, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(loginBody)))
	req.Header.Set("Content-Type", "application/json")
	suite.router.ServeHTTP(w, req)

	var loginResp controllers.LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(suite.T(), err)

	return &loginResp
}

// Run the test suite
func TestAuthAuthorizationIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(AuthAuthorizationIntegrationTestSuite))
} 