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
	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/gin-gonic/gin"
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
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.User), args.Int(1), args.Error(2)
}

func (m *MockUserRepository) GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID, lastLogin time.Time) error {
	args := m.Called(ctx, id, lastLogin)
	return args.Error(0)
}

func (m *MockUserRepository) LockAccount(ctx context.Context, id uuid.UUID, reason string) error {
	args := m.Called(ctx, id, reason)
	return args.Error(0)
}

func (m *MockUserRepository) UnlockAccount(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) IncrementLoginAttempts(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) ResetLoginAttempts(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) Search(ctx context.Context, query string, offset, limit int) ([]*models.User, int, error) {
	args := m.Called(ctx, query, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.User), args.Int(1), args.Error(2)
}

// MockRoleRepository is a mock implementation of RoleRepository
type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) Create(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockRoleRepository) GetByName(ctx context.Context, name string) (*models.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockRoleRepository) Update(ctx context.Context, role *models.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRoleRepository) List(ctx context.Context, offset, limit int) ([]*models.Role, int, error) {
	args := m.Called(ctx, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.Role), args.Int(1), args.Error(2)
}

func (m *MockRoleRepository) GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockRoleRepository) AddPermission(ctx context.Context, roleID, permissionID uuid.UUID, grantedBy *uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID, grantedBy)
	return args.Error(0)
}

func (m *MockRoleRepository) RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID)
	return args.Error(0)
}

// TestUserManagementController_CRUDOperations tests user CRUD operations
func TestUserManagementController_CRUDOperations(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	userController := controllers.NewUserManagementController(mockUserRepo, mockRoleRepo)

	gin.SetMode(gin.TestMode)

	t.Run("create user success", func(t *testing.T) {
		userID := uuid.New()
		username := "testuser"
		email := "test@example.com"

		// Create test user
		user := &models.User{
			ID:       userID,
			Username: username,
			Email:    email,
			Status:   models.UserStatusActive,
		}

		// Setup mock expectations
		mockUserRepo.On("GetByUsername", mock.Anything, username).Return(nil, assert.AnError) // Username not exists
		mockUserRepo.On("GetByEmail", mock.Anything, email).Return(nil, assert.AnError)       // Email not exists
		mockUserRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

		// Create request
		reqBody := controllers.CreateUserRequest{
			Username: username,
			Email:    email,
			Password: "securepassword123",
			FirstName: "Test",
			LastName:  "User",
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		userController.CreateUser(c)

		// Assertions
		assert.Equal(t, http.StatusCreated, w.Code)

		var response controllers.CreateUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.NotEmpty(t, response.UserID)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("create user with existing username", func(t *testing.T) {
		username := "existinguser"
		email := "new@example.com"

		// Setup mock expectations - username already exists
		existingUser := &models.User{Username: username}
		mockUserRepo.On("GetByUsername", mock.Anything, username).Return(existingUser, nil)

		// Create request
		reqBody := controllers.CreateUserRequest{
			Username: username,
			Email:    email,
			Password: "securepassword123",
			FirstName: "New",
			LastName:  "User",
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		userController.CreateUser(c)

		// Assertions
		assert.Equal(t, http.StatusConflict, w.Code)

		var response controllers.CreateUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "USERNAME_EXISTS", response.ErrorCode)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("get user by ID success", func(t *testing.T) {
		userID := uuid.New()
		username := "testuser"
		email := "test@example.com"

		// Create test user
		user := &models.User{
			ID:       userID,
			Username: username,
			Email:    email,
			Status:   models.UserStatusActive,
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/users/"+userID.String(), nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.GetUser(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.GetUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, userID.String(), response.User.ID)
		assert.Equal(t, username, response.User.Username)
		assert.Equal(t, email, response.User.Email)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("get user by ID not found", func(t *testing.T) {
		userID := uuid.New()

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(nil, assert.AnError)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/users/"+userID.String(), nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.GetUser(c)

		// Assertions
		assert.Equal(t, http.StatusNotFound, w.Code)

		var response controllers.GetUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "USER_NOT_FOUND", response.ErrorCode)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("update user success", func(t *testing.T) {
		userID := uuid.New()
		username := "testuser"
		email := "updated@example.com"

		// Create test user
		user := &models.User{
			ID:       userID,
			Username: username,
			Email:    email,
			Status:   models.UserStatusActive,
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
		mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

		// Create request
		reqBody := controllers.UpdateUserRequest{
			Email:     email,
			FirstName: "Updated",
			LastName:  "User",
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("PUT", "/api/v1/users/"+userID.String(), bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.UpdateUser(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.UpdateUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("delete user success", func(t *testing.T) {
		userID := uuid.New()

		// Setup mock expectations
		mockUserRepo.On("Delete", mock.Anything, userID).Return(nil)

		// Create HTTP request
		req, _ := http.NewRequest("DELETE", "/api/v1/users/"+userID.String(), nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.DeleteUser(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.DeleteUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestUserManagementController_UserRoleAssignment tests user role assignment
func TestUserManagementController_UserRoleAssignment(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	userController := controllers.NewUserManagementController(mockUserRepo, mockRoleRepo)

	gin.SetMode(gin.TestMode)

	t.Run("assign role to user success", func(t *testing.T) {
		userID := uuid.New()
		roleID := uuid.New()
		facilityID := uuid.New()
		assignedBy := uuid.New()

		// Create test user and role
		user := &models.User{
			ID:       userID,
			Username: "testuser",
			Status:   models.UserStatusActive,
		}
		role := &models.Role{
			ID:   roleID,
			Name: "doctor",
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
		mockRoleRepo.On("GetByID", mock.Anything, roleID).Return(role, nil)
		mockUserRepo.On("AssignRole", mock.Anything, userID, roleID, &facilityID, &assignedBy, (*time.Time)(nil)).Return(nil)

		// Create request
		reqBody := controllers.AssignUserRoleRequest{
			UserID:     userID.String(),
			RoleID:     roleID.String(),
			FacilityID: facilityID.String(),
			AssignedBy: assignedBy.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users/"+userID.String()+"/roles", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.AssignUserRole(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.AssignUserRoleResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("revoke role from user success", func(t *testing.T) {
		userID := uuid.New()
		roleID := uuid.New()

		// Create test user
		user := &models.User{
			ID:       userID,
			Username: "testuser",
			Status:   models.UserStatusActive,
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
		mockUserRepo.On("RevokeRole", mock.Anything, userID, roleID).Return(nil)

		// Create request
		reqBody := controllers.RevokeUserRoleRequest{
			RoleID: roleID.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("DELETE", "/api/v1/users/"+userID.String()+"/roles", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.RevokeUserRole(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.RevokeUserRoleResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestUserManagementController_UserStatusManagement tests user status management
func TestUserManagementController_UserStatusManagement(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	userController := controllers.NewUserManagementController(mockUserRepo, mockRoleRepo)

	gin.SetMode(gin.TestMode)

	t.Run("activate user success", func(t *testing.T) {
		userID := uuid.New()

		// Create test user
		user := &models.User{
			ID:       userID,
			Username: "testuser",
			Status:   models.UserStatusInactive,
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
		mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users/"+userID.String()+"/activate", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.ActivateUser(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.ActivateUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("deactivate user success", func(t *testing.T) {
		userID := uuid.New()

		// Create test user
		user := &models.User{
			ID:       userID,
			Username: "testuser",
			Status:   models.UserStatusActive,
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
		mockUserRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users/"+userID.String()+"/deactivate", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.DeactivateUser(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.DeactivateUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("lock user account success", func(t *testing.T) {
		userID := uuid.New()
		reason := "Suspicious activity detected"

		// Create test user
		user := &models.User{
			ID:       userID,
			Username: "testuser",
			Status:   models.UserStatusActive,
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
		mockUserRepo.On("LockAccount", mock.Anything, userID, reason).Return(nil)

		// Create request
		reqBody := controllers.LockUserRequest{
			Reason: reason,
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users/"+userID.String()+"/lock", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.LockUser(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.LockUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("unlock user account success", func(t *testing.T) {
		userID := uuid.New()

		// Create test user
		user := &models.User{
			ID:       userID,
			Username: "testuser",
			Status:   models.UserStatusLocked,
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
		mockUserRepo.On("UnlockAccount", mock.Anything, userID).Return(nil)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users/"+userID.String()+"/unlock", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.UnlockUser(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.UnlockUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestUserManagementController_UserSearchAndFiltering tests user search and filtering
func TestUserManagementController_UserSearchAndFiltering(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	userController := controllers.NewUserManagementController(mockUserRepo, mockRoleRepo)

	gin.SetMode(gin.TestMode)

	t.Run("list users success", func(t *testing.T) {
		// Create test users
		users := []*models.User{
			{
				ID:       uuid.New(),
				Username: "user1",
				Email:    "user1@example.com",
				Status:   models.UserStatusActive,
			},
			{
				ID:       uuid.New(),
				Username: "user2",
				Email:    "user2@example.com",
				Status:   models.UserStatusActive,
			},
		}

		// Setup mock expectations
		mockUserRepo.On("List", mock.Anything, 0, 10, mock.AnythingOfType("map[string]interface {}")).Return(users, 2, nil)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/users?limit=10&offset=0", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		userController.ListUsers(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.ListUsersResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Len(t, response.Users, 2)
		assert.Equal(t, 2, response.Total)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("search users success", func(t *testing.T) {
		query := "doctor"
		
		// Create test users
		users := []*models.User{
			{
				ID:       uuid.New(),
				Username: "doctor1",
				Email:    "doctor1@example.com",
				Status:   models.UserStatusActive,
			},
		}

		// Setup mock expectations
		mockUserRepo.On("Search", mock.Anything, query, 0, 10).Return(users, 1, nil)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/users/search?q="+query+"&limit=10&offset=0", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		userController.SearchUsers(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.SearchUsersResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Len(t, response.Users, 1)
		assert.Equal(t, 1, response.Total)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("filter users by status", func(t *testing.T) {
		// Create test users
		users := []*models.User{
			{
				ID:       uuid.New(),
				Username: "activeuser",
				Email:    "active@example.com",
				Status:   models.UserStatusActive,
			},
		}

		// Setup mock expectations
		mockUserRepo.On("List", mock.Anything, 0, 10, mock.MatchedBy(func(filters map[string]interface{}) bool {
			return filters["status"] == "active"
		})).Return(users, 1, nil)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/users?status=active&limit=10&offset=0", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		userController.ListUsers(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.ListUsersResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Len(t, response.Users, 1)
		assert.Equal(t, 1, response.Total)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestUserManagementController_ErrorHandling tests error handling scenarios
func TestUserManagementController_ErrorHandling(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	userController := controllers.NewUserManagementController(mockUserRepo, mockRoleRepo)

	gin.SetMode(gin.TestMode)

	t.Run("create user with invalid request", func(t *testing.T) {
		// Create invalid request (missing required fields)
		reqBody := map[string]interface{}{
			"email": "test@example.com",
			// missing username and password
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		userController.CreateUser(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response controllers.CreateUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "INVALID_REQUEST", response.ErrorCode)
	})

	t.Run("get user with invalid ID", func(t *testing.T) {
		// Create HTTP request with invalid UUID
		req, _ := http.NewRequest("GET", "/api/v1/users/invalid-uuid", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: "invalid-uuid"}}

		// Call the handler
		userController.GetUser(c)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response controllers.GetUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "INVALID_USER_ID", response.ErrorCode)
	})

	t.Run("update non-existent user", func(t *testing.T) {
		userID := uuid.New()

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(nil, assert.AnError)

		// Create request
		reqBody := controllers.UpdateUserRequest{
			Email:     "updated@example.com",
			FirstName: "Updated",
			LastName:  "User",
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("PUT", "/api/v1/users/"+userID.String(), bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.UpdateUser(c)

		// Assertions
		assert.Equal(t, http.StatusNotFound, w.Code)

		var response controllers.UpdateUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "USER_NOT_FOUND", response.ErrorCode)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("service error handling", func(t *testing.T) {
		userID := uuid.New()

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(nil, assert.AnError)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/users/"+userID.String(), nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.GetUser(c)

		// Assertions
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response controllers.GetUserResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.NotEmpty(t, response.Error)
		assert.Equal(t, "SERVICE_ERROR", response.ErrorCode)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestUserManagementController_HealthcareSpecificFeatures tests healthcare-specific features
func TestUserManagementController_HealthcareSpecificFeatures(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	userController := controllers.NewUserManagementController(mockUserRepo, mockRoleRepo)

	gin.SetMode(gin.TestMode)

	t.Run("assign healthcare role with facility", func(t *testing.T) {
		userID := uuid.New()
		roleID := uuid.New()
		facilityID := uuid.New()
		assignedBy := uuid.New()

		// Create test user and healthcare role
		user := &models.User{
			ID:       userID,
			Username: "doctor1",
			Status:   models.UserStatusActive,
		}
		role := &models.Role{
			ID:   roleID,
			Name: "doctor",
		}

		// Setup mock expectations
		mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
		mockRoleRepo.On("GetByID", mock.Anything, roleID).Return(role, nil)
		mockUserRepo.On("AssignRole", mock.Anything, userID, roleID, &facilityID, &assignedBy, (*time.Time)(nil)).Return(nil)

		// Create request
		reqBody := controllers.AssignUserRoleRequest{
			UserID:     userID.String(),
			RoleID:     roleID.String(),
			FacilityID: facilityID.String(),
			AssignedBy: assignedBy.String(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)

		// Create HTTP request
		req, _ := http.NewRequest("POST", "/api/v1/users/"+userID.String()+"/roles", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "id", Value: userID.String()}}

		// Call the handler
		userController.AssignUserRole(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.AssignUserRoleResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)

		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("search users by healthcare role", func(t *testing.T) {
		query := "nurse"
		
		// Create test healthcare users
		users := []*models.User{
			{
				ID:       uuid.New(),
				Username: "nurse1",
				Email:    "nurse1@hospital.com",
				Status:   models.UserStatusActive,
			},
			{
				ID:       uuid.New(),
				Username: "nurse2",
				Email:    "nurse2@hospital.com",
				Status:   models.UserStatusActive,
			},
		}

		// Setup mock expectations
		mockUserRepo.On("Search", mock.Anything, query, 0, 10).Return(users, 2, nil)

		// Create HTTP request
		req, _ := http.NewRequest("GET", "/api/v1/users/search?q="+query+"&limit=10&offset=0", nil)

		// Create response recorder
		w := httptest.NewRecorder()

		// Create Gin context
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Call the handler
		userController.SearchUsers(c)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		var response controllers.SearchUsersResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.Len(t, response.Users, 2)
		assert.Equal(t, 2, response.Total)

		mockUserRepo.AssertExpectations(t)
	})
} 