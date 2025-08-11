package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/controllers"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"
)

// MockAuthorizationService is a mock implementation of AuthorizationService
type MockAuthorizationService struct {
	mock.Mock
}

func (m *MockAuthorizationService) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	args := m.Called(ctx, userID, roleName)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthorizationService) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	args := m.Called(ctx, userID, resource, action)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthorizationService) HasPermissionWithContext(ctx context.Context, userID uuid.UUID, resource, action string, context map[string]interface{}) (bool, error) {
	args := m.Called(ctx, userID, resource, action, context)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthorizationService) HasFacilityAccess(ctx context.Context, userID uuid.UUID, facilityID uuid.UUID) (bool, error) {
	args := m.Called(ctx, userID, facilityID)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthorizationService) HasPermissionWithAudit(ctx context.Context, userID uuid.UUID, resource, action string, context map[string]interface{}) (bool, error) {
	args := m.Called(ctx, userID, resource, action, context)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthorizationService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthorizationService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthorizationService) CheckPermission(ctx context.Context, userID uuid.UUID, resource, action string) (*services.AuthorizationResult, error) {
	args := m.Called(ctx, userID, resource, action)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.AuthorizationResult), args.Error(1)
}

func (m *MockAuthorizationService) CheckPermissionWithContext(ctx context.Context, userID uuid.UUID, resource, action string, context map[string]interface{}) (*services.AuthorizationResult, error) {
	args := m.Called(ctx, userID, resource, action, context)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.AuthorizationResult), args.Error(1)
}

func (m *MockAuthorizationService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthorizationService) GrantPermission(ctx context.Context, roleID, permissionID uuid.UUID, grantedBy *uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID, grantedBy)
	return args.Error(0)
}

func (m *MockAuthorizationService) RevokePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID)
	return args.Error(0)
}

func (m *MockAuthorizationService) AssignRole(ctx context.Context, userID, roleID uuid.UUID, facilityID *uuid.UUID, assignedBy *uuid.UUID, expiresAt *time.Time) error {
	args := m.Called(ctx, userID, roleID, facilityID, assignedBy, expiresAt)
	return args.Error(0)
}

func (m *MockAuthorizationService) RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockAuthorizationService) InvalidateUserPermissions(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthorizationService) InvalidateRolePermissions(ctx context.Context, roleID uuid.UUID) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

// TestAuthorizationController_PermissionCheck tests permission checking endpoints
func TestAuthorizationController_PermissionCheck(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("check permission success", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"

		// Setup mock expectations
		mockAuthService.On("HasPermission", mock.Anything, userID, resource, action).Return(true, nil)

		// Create request
		reqBody := controllers.PermissionCheckRequest{
			Resource: resource,
			Action:   action,
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-permission", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckPermission(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.PermissionCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.True(t, response.HasPermission)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("check permission denied", func(t *testing.T) {
		userID := uuid.New()
		resource := "admin_panel"
		action := "access"

		// Setup mock expectations
		mockAuthService.On("HasPermission", mock.Anything, userID, resource, action).Return(false, nil)

		// Create request
		reqBody := controllers.PermissionCheckRequest{
			Resource: resource,
			Action:   action,
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-permission", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckPermission(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.PermissionCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.False(t, response.HasPermission)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("check permission with invalid request", func(t *testing.T) {
		userID := uuid.New()

		// Create invalid request (missing required fields)
		reqBody := map[string]interface{}{
			"resource": "patients",
			// missing action field
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-permission", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckPermission(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response controllers.PermissionCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "INVALID_REQUEST", response.ErrorCode)
	})

	t.Run("check permission service error", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"

		// Setup mock expectations
		mockAuthService.On("HasPermission", mock.Anything, userID, resource, action).Return(false, assert.AnError)

		// Create request
		reqBody := controllers.PermissionCheckRequest{
			Resource: resource,
			Action:   action,
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-permission", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckPermission(c)

		// Assertions
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response controllers.PermissionCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "SERVICE_ERROR", response.ErrorCode)

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationController_PermissionCheckWithContext tests permission checking with context
func TestAuthorizationController_PermissionCheckWithContext(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("check permission with context success", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"
		context := map[string]interface{}{
			"patient_id":  uuid.New().String(),
			"facility_id": uuid.New().String(),
			"time_of_day": "business_hours",
		}

		// Setup mock expectations
		mockAuthService.On("HasPermissionWithContext", mock.Anything, userID, resource, action, context).Return(true, nil)

		// Create request
		reqBody := controllers.PermissionCheckWithContextRequest{
			Resource: resource,
			Action:   action,
			Context:  context,
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-permission-context", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckPermissionWithContext(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.PermissionCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.True(t, response.HasPermission)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("check permission with context denied", func(t *testing.T) {
		userID := uuid.New()
		resource := "emergency_room"
		action := "access"
		context := map[string]interface{}{
			"time_of_day": "after_hours",
			"location":    "remote",
		}

		// Setup mock expectations
		mockAuthService.On("HasPermissionWithContext", mock.Anything, userID, resource, action, context).Return(false, nil)

		// Create request
		reqBody := controllers.PermissionCheckWithContextRequest{
			Resource: resource,
			Action:   action,
			Context:  context,
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-permission-context", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckPermissionWithContext(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.PermissionCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.False(t, response.HasPermission)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationController_RoleCheck tests role checking endpoints
func TestAuthorizationController_RoleCheck(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("check role success", func(t *testing.T) {
		userID := uuid.New()
		roleName := "doctor"

		// Setup mock expectations
		mockAuthService.On("HasRole", mock.Anything, userID, roleName).Return(true, nil)

		// Create request
		reqBody := controllers.RoleCheckRequest{
			RoleName: roleName,
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-role", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckRole(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.RoleCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.True(t, response.HasRole)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("check role denied", func(t *testing.T) {
		userID := uuid.New()
		roleName := "admin"

		// Setup mock expectations
		mockAuthService.On("HasRole", mock.Anything, userID, roleName).Return(false, nil)

		// Create request
		reqBody := controllers.RoleCheckRequest{
			RoleName: roleName,
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-role", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckRole(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.RoleCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.False(t, response.HasRole)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationController_FacilityAccess tests facility access checking
func TestAuthorizationController_FacilityAccess(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("check facility access success", func(t *testing.T) {
		userID := uuid.New()
		facilityID := uuid.New()

		// Setup mock expectations
		mockAuthService.On("HasFacilityAccess", mock.Anything, userID, facilityID).Return(true, nil)

		// Create request
		reqBody := controllers.FacilityAccessRequest{
			FacilityID: facilityID.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-facility-access", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckFacilityAccess(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.FacilityAccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.True(t, response.HasAccess)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("check facility access denied", func(t *testing.T) {
		userID := uuid.New()
		facilityID := uuid.New()

		// Setup mock expectations
		mockAuthService.On("HasFacilityAccess", mock.Anything, userID, facilityID).Return(false, nil)

		// Create request
		reqBody := controllers.FacilityAccessRequest{
			FacilityID: facilityID.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-facility-access", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckFacilityAccess(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.FacilityAccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.False(t, response.HasAccess)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("check facility access with invalid facility ID", func(t *testing.T) {
		userID := uuid.New()

		// Create request with invalid facility ID
		reqBody := controllers.FacilityAccessRequest{
			FacilityID: "invalid-uuid",
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-facility-access", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckFacilityAccess(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response controllers.FacilityAccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "INVALID_FACILITY_ID", response.ErrorCode)
	})
}

// TestAuthorizationController_GetUserPermissions tests getting user permissions
func TestAuthorizationController_GetUserPermissions(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("get user permissions success", func(t *testing.T) {
		userID := uuid.New()
		expectedPermissions := []string{"patients:read", "patients:write", "appointments:create"}

		// Setup mock expectations
		mockAuthService.On("GetUserPermissions", mock.Anything, userID).Return(expectedPermissions, nil)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/auth/user/permissions", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.GetUserPermissions(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.UserPermissionsResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, expectedPermissions, response.Permissions)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("get user permissions service error", func(t *testing.T) {
		userID := uuid.New()

		// Setup mock expectations
		mockAuthService.On("GetUserPermissions", mock.Anything, userID).Return(nil, assert.AnError)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/auth/user/permissions", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.GetUserPermissions(c)

		// Assertions
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response controllers.UserPermissionsResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "SERVICE_ERROR", response.ErrorCode)

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationController_GetUserRoles tests getting user roles
func TestAuthorizationController_GetUserRoles(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("get user roles success", func(t *testing.T) {
		userID := uuid.New()
		expectedRoles := []string{"doctor", "consultant"}

		// Setup mock expectations
		mockAuthService.On("GetUserRoles", mock.Anything, userID).Return(expectedRoles, nil)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/auth/user/roles", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.GetUserRoles(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.UserRolesResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, expectedRoles, response.Roles)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationController_RoleManagement tests role management endpoints
func TestAuthorizationController_RoleManagement(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("assign role success", func(t *testing.T) {
		userID := uuid.New()
		roleID := uuid.New()
		facilityID := uuid.New()
		assignedBy := uuid.New()

		// Setup mock expectations
		mockAuthService.On("AssignRole", mock.Anything, userID, roleID, &facilityID, &assignedBy, (*time.Time)(nil)).Return(nil)

		// Create request
		reqBody := controllers.AssignRoleRequest{
			UserID:     userID.String(),
			RoleID:     roleID.String(),
			FacilityID: facilityID.String(),
			AssignedBy: assignedBy.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/assign-role", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		authController.AssignRole(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.AssignRoleResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("revoke role success", func(t *testing.T) {
		userID := uuid.New()
		roleID := uuid.New()

		// Setup mock expectations
		mockAuthService.On("RevokeRole", mock.Anything, userID, roleID).Return(nil)

		// Create request
		reqBody := controllers.RevokeRoleRequest{
			UserID: userID.String(),
			RoleID: roleID.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/revoke-role", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		authController.RevokeRole(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.RevokeRoleResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationController_PermissionManagement tests permission management endpoints
func TestAuthorizationController_PermissionManagement(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("grant permission success", func(t *testing.T) {
		roleID := uuid.New()
		permissionID := uuid.New()
		grantedBy := uuid.New()

		// Setup mock expectations
		mockAuthService.On("GrantPermission", mock.Anything, roleID, permissionID, &grantedBy).Return(nil)

		// Create request
		reqBody := controllers.GrantPermissionRequest{
			RoleID:       roleID.String(),
			PermissionID: permissionID.String(),
			GrantedBy:    grantedBy.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/grant-permission", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		authController.GrantPermission(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.GrantPermissionResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("revoke permission success", func(t *testing.T) {
		roleID := uuid.New()
		permissionID := uuid.New()

		// Setup mock expectations
		mockAuthService.On("RevokePermission", mock.Anything, roleID, permissionID).Return(nil)

		// Create request
		reqBody := controllers.RevokePermissionRequest{
			RoleID:       roleID.String(),
			PermissionID: permissionID.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/auth/revoke-permission", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		authController.RevokePermission(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.RevokePermissionResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationController_ErrorHandling tests error handling scenarios
func TestAuthorizationController_ErrorHandling(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	authController := controllers.NewAuthorizationController(mockAuthService)

	gin.SetMode(gin.TestMode)

	t.Run("unauthorized access", func(t *testing.T) {
		// Create HTTP request without user_id in context
		req, _ := http.NewRequest("GET", "/api/v1/auth/user/permissions", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context without user_id
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		authController.GetUserPermissions(c)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response controllers.UserPermissionsResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "UNAUTHORIZED", response.ErrorCode)
	})

	t.Run("invalid JSON request", func(t *testing.T) {
		userID := uuid.New()

		// Create request with invalid JSON
		reqBody := []byte(`{"resource": "patients", "action": "read",}`) // Invalid JSON
		req, _ := http.NewRequest("POST", "/api/v1/auth/check-permission", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("user_id", userID)

		// Call the handler
		authController.CheckPermission(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response controllers.PermissionCheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "INVALID_REQUEST", response.ErrorCode)
	})
} 