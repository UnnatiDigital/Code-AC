package tests

import (
	"context"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// MockRoleRepository is a mock implementation of RoleRepository
type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.Role, error) {
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

// MockCache is a mock implementation of cache interface
type MockCache struct {
	mock.Mock
}

func (m *MockCache) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockCache) SetUserPermissions(ctx context.Context, userID uuid.UUID, permissions []string, ttl time.Duration) error {
	args := m.Called(ctx, userID, permissions, ttl)
	return args.Error(0)
}

func (m *MockCache) DeleteUserPermissions(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockCache) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockCache) SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissions []string, ttl time.Duration) error {
	args := m.Called(ctx, roleID, permissions, ttl)
	return args.Error(0)
}

func (m *MockCache) DeleteRolePermissions(ctx context.Context, roleID uuid.UUID) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

// TestAuthorizationService_RBAC tests role-based access control functionality
func TestAuthorizationService_RBAC(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthorizationService(mockUserRepo, mockRoleRepo, mockCache)

	ctx := context.Background()

	t.Run("user has role", func(t *testing.T) {
		userID := uuid.New()
		roleName := "doctor"

		// Create test user with roles
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID:   uuid.New(),
						Name: roleName,
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test role checking
		hasRole, err := authService.HasRole(ctx, userID, roleName)
		
		require.NoError(t, err)
		assert.True(t, hasRole)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user does not have role", func(t *testing.T) {
		userID := uuid.New()
		roleName := "admin"

		// Create test user with different role
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID:   uuid.New(),
						Name: "doctor",
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test role checking
		hasRole, err := authService.HasRole(ctx, userID, roleName)
		
		require.NoError(t, err)
		assert.False(t, hasRole)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user has inactive role", func(t *testing.T) {
		userID := uuid.New()
		roleName := "doctor"

		// Create test user with inactive role
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID:   uuid.New(),
						Name: roleName,
					},
					IsActive: false, // Inactive role
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test role checking
		hasRole, err := authService.HasRole(ctx, userID, roleName)
		
		require.NoError(t, err)
		assert.False(t, hasRole) // Should return false for inactive role

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		userID := uuid.New()
		roleName := "doctor"

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(nil, assert.AnError)

		// Test role checking
		hasRole, err := authService.HasRole(ctx, userID, roleName)
		
		require.Error(t, err)
		assert.False(t, hasRole)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestAuthorizationService_PermissionChecking tests permission checking logic
func TestAuthorizationService_PermissionChecking(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthorizationService(mockUserRepo, mockRoleRepo, mockCache)

	ctx := context.Background()

	t.Run("user has permission", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"

		// Create test user with permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   action,
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test permission checking
		hasPermission, err := authService.HasPermission(ctx, userID, resource, action)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user does not have permission", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "delete"

		// Create test user with different permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "nurse",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   "read", // Different action
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test permission checking
		hasPermission, err := authService.HasPermission(ctx, userID, resource, action)
		
		require.NoError(t, err)
		assert.False(t, hasPermission)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user has permission through multiple roles", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"

		// Create test user with multiple roles
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "nurse",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: "appointments",
									Action:   "read",
								},
							},
						},
					},
					IsActive: true,
				},
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   action,
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test permission checking
		hasPermission, err := authService.HasPermission(ctx, userID, resource, action)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("permission check with caching", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"

		// Setup cache expectations
		cachedPermissions := []string{"patients:read", "appointments:create"}
		mockCache.On("GetUserPermissions", ctx, userID).Return(cachedPermissions, nil)

		// Test permission checking with cache
		hasPermission, err := authService.HasPermission(ctx, userID, resource, action)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockCache.AssertExpectations(t)
	})

	t.Run("cache miss - fallback to database", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"

		// Create test user with permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   action,
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup cache miss
		mockCache.On("GetUserPermissions", ctx, userID).Return(nil, assert.AnError)
		
		// Setup database fallback
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)
		
		// Setup cache update
		mockCache.On("SetUserPermissions", ctx, userID, mock.AnythingOfType("[]string"), mock.AnythingOfType("time.Duration")).Return(nil)

		// Test permission checking with cache miss
		hasPermission, err := authService.HasPermission(ctx, userID, resource, action)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockCache.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})
}

// TestAuthorizationService_FacilityBasedAccessControl tests facility-based access control
func TestAuthorizationService_FacilityBasedAccessControl(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthorizationService(mockUserRepo, mockRoleRepo, mockCache)

	ctx := context.Background()

	t.Run("user has access to facility", func(t *testing.T) {
		userID := uuid.New()
		facilityID := uuid.New()

		// Create test user with facility access
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					FacilityID: &facilityID,
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test facility access
		hasAccess, err := authService.HasFacilityAccess(ctx, userID, facilityID)
		
		require.NoError(t, err)
		assert.True(t, hasAccess)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user does not have access to facility", func(t *testing.T) {
		userID := uuid.New()
		facilityID := uuid.New()
		differentFacilityID := uuid.New()

		// Create test user with different facility access
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					FacilityID: &differentFacilityID, // Different facility
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test facility access
		hasAccess, err := authService.HasFacilityAccess(ctx, userID, facilityID)
		
		require.NoError(t, err)
		assert.False(t, hasAccess)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user has access to multiple facilities", func(t *testing.T) {
		userID := uuid.New()
		facilityID1 := uuid.New()
		facilityID2 := uuid.New()

		// Create test user with multiple facility access
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					FacilityID: &facilityID1,
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
					},
					IsActive: true,
				},
				{
					UserID: userID,
					RoleID: uuid.New(),
					FacilityID: &facilityID2,
					Role: &models.Role{
						ID: uuid.New(),
						Name: "consultant",
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test facility access for both facilities
		hasAccess1, err := authService.HasFacilityAccess(ctx, userID, facilityID1)
		require.NoError(t, err)
		assert.True(t, hasAccess1)

		hasAccess2, err := authService.HasFacilityAccess(ctx, userID, facilityID2)
		require.NoError(t, err)
		assert.True(t, hasAccess2)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user has system-wide access (no facility restriction)", func(t *testing.T) {
		userID := uuid.New()
		facilityID := uuid.New()

		// Create test user with system-wide access (no facility ID)
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					FacilityID: nil, // No facility restriction
					Role: &models.Role{
						ID: uuid.New(),
						Name: "admin",
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test facility access
		hasAccess, err := authService.HasFacilityAccess(ctx, userID, facilityID)
		
		require.NoError(t, err)
		assert.True(t, hasAccess) // Should have access to any facility

		mockUserRepo.AssertExpectations(t)
	})
}

// TestAuthorizationService_DynamicAuthorization tests dynamic authorization decisions
func TestAuthorizationService_DynamicAuthorization(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthorizationService(mockUserRepo, mockRoleRepo, mockCache)

	ctx := context.Background()

	t.Run("dynamic permission check with context", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"
		context := map[string]interface{}{
			"patient_id": uuid.New().String(),
			"facility_id": uuid.New().String(),
			"time_of_day": "business_hours",
		}

		// Create test user with permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   action,
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test dynamic permission checking
		hasPermission, err := authService.HasPermissionWithContext(ctx, userID, resource, action, context)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("time-based access control", func(t *testing.T) {
		userID := uuid.New()
		resource := "emergency_room"
		action := "access"

		// Test during business hours
		businessHoursContext := map[string]interface{}{
			"time_of_day": "business_hours",
			"facility_id": uuid.New().String(),
		}

		// Create test user with time-based permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "emergency_doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   action,
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test access during business hours
		hasPermission, err := authService.HasPermissionWithContext(ctx, userID, resource, action, businessHoursContext)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("location-based access control", func(t *testing.T) {
		userID := uuid.New()
		resource := "patient_records"
		action := "read"

		// Test access from authorized location
		authorizedLocationContext := map[string]interface{}{
			"location": "hospital_premises",
			"ip_address": "192.168.1.100",
			"patient_id": uuid.New().String(),
		}

		// Create test user with location-based permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   action,
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test access from authorized location
		hasPermission, err := authService.HasPermissionWithContext(ctx, userID, resource, action, authorizedLocationContext)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestAuthorizationService_PermissionCaching tests permission caching and invalidation
func TestAuthorizationService_PermissionCaching(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthorizationService(mockUserRepo, mockRoleRepo, mockCache)

	ctx := context.Background()

	t.Run("cache user permissions", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"

		// Create test user with permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   action,
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup cache miss
		mockCache.On("GetUserPermissions", ctx, userID).Return(nil, assert.AnError)
		
		// Setup database lookup
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)
		
		// Setup cache storage
		mockCache.On("SetUserPermissions", ctx, userID, mock.AnythingOfType("[]string"), mock.AnythingOfType("time.Duration")).Return(nil)

		// Test permission checking (should cache)
		hasPermission, err := authService.HasPermission(ctx, userID, resource, action)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockCache.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("invalidate user permissions cache", func(t *testing.T) {
		userID := uuid.New()

		// Setup cache invalidation
		mockCache.On("DeleteUserPermissions", ctx, userID).Return(nil)

		// Test cache invalidation
		err := authService.InvalidateUserPermissions(ctx, userID)
		
		require.NoError(t, err)

		mockCache.AssertExpectations(t)
	})

	t.Run("invalidate role permissions cache", func(t *testing.T) {
		roleID := uuid.New()

		// Setup cache invalidation
		mockCache.On("DeleteRolePermissions", ctx, roleID).Return(nil)

		// Test cache invalidation
		err := authService.InvalidateRolePermissions(ctx, roleID)
		
		require.NoError(t, err)

		mockCache.AssertExpectations(t)
	})

	t.Run("cache hit - no database lookup", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"

		// Setup cache hit
		cachedPermissions := []string{"patients:read", "appointments:create"}
		mockCache.On("GetUserPermissions", ctx, userID).Return(cachedPermissions, nil)

		// Test permission checking (should use cache)
		hasPermission, err := authService.HasPermission(ctx, userID, resource, action)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		// Should not call database
		mockUserRepo.AssertNotCalled(t, "GetWithPermissions")

		mockCache.AssertExpectations(t)
	})
}

// TestAuthorizationService_AuditLogging tests authorization audit logging
func TestAuthorizationService_AuditLogging(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthorizationService(mockUserRepo, mockRoleRepo, mockCache)

	ctx := context.Background()

	t.Run("log authorization decision", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"
		decision := true
		context := map[string]interface{}{
			"patient_id": uuid.New().String(),
			"ip_address": "192.168.1.100",
		}

		// Create test user with permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: resource,
									Action:   action,
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test authorization with audit logging
		hasPermission, err := authService.HasPermissionWithAudit(ctx, userID, resource, action, context)
		
		require.NoError(t, err)
		assert.True(t, hasPermission)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("log denied authorization", func(t *testing.T) {
		userID := uuid.New()
		resource := "admin_panel"
		action := "access"

		// Create test user without admin permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "nurse",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: "patients",
									Action:   "read",
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test authorization with audit logging
		hasPermission, err := authService.HasPermissionWithAudit(ctx, userID, resource, action, nil)
		
		require.NoError(t, err)
		assert.False(t, hasPermission)

		mockUserRepo.AssertExpectations(t)
	})
}

// TestAuthorizationService_GetUserPermissions tests getting all user permissions
func TestAuthorizationService_GetUserPermissions(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthorizationService(mockUserRepo, mockRoleRepo, mockCache)

	ctx := context.Background()

	t.Run("get user permissions", func(t *testing.T) {
		userID := uuid.New()

		// Create test user with multiple permissions
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "doctor",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: "patients",
									Action:   "read",
								},
							},
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: "patients",
									Action:   "write",
								},
							},
						},
					},
					IsActive: true,
				},
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID: uuid.New(),
						Name: "consultant",
						Permissions: []models.RolePermission{
							{
								RoleID: uuid.New(),
								PermissionID: uuid.New(),
								Permission: &models.Permission{
									ID:       uuid.New(),
									Resource: "appointments",
									Action:   "manage",
								},
							},
						},
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test getting user permissions
		permissions, err := authService.GetUserPermissions(ctx, userID)
		
		require.NoError(t, err)
		assert.Len(t, permissions, 3)
		
		// Check for specific permissions
		expectedPermissions := []string{"patients:read", "patients:write", "appointments:manage"}
		for _, expected := range expectedPermissions {
			assert.Contains(t, permissions, expected)
		}

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("get user permissions from cache", func(t *testing.T) {
		userID := uuid.New()

		// Setup cache hit
		cachedPermissions := []string{"patients:read", "appointments:create", "prescriptions:write"}
		mockCache.On("GetUserPermissions", ctx, userID).Return(cachedPermissions, nil)

		// Test getting user permissions from cache
		permissions, err := authService.GetUserPermissions(ctx, userID)
		
		require.NoError(t, err)
		assert.Equal(t, cachedPermissions, permissions)

		// Should not call database
		mockUserRepo.AssertNotCalled(t, "GetWithPermissions")

		mockCache.AssertExpectations(t)
	})
}

// TestAuthorizationService_GetUserRoles tests getting all user roles
func TestAuthorizationService_GetUserRoles(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockRoleRepo := new(MockRoleRepository)
	mockCache := new(MockCache)
	
	authService := services.NewAuthorizationService(mockUserRepo, mockRoleRepo, mockCache)

	ctx := context.Background()

	t.Run("get user roles", func(t *testing.T) {
		userID := uuid.New()

		// Create test user with multiple roles
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID:   uuid.New(),
						Name: "doctor",
					},
					IsActive: true,
				},
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID:   uuid.New(),
						Name: "consultant",
					},
					IsActive: true,
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test getting user roles
		roles, err := authService.GetUserRoles(ctx, userID)
		
		require.NoError(t, err)
		assert.Len(t, roles, 2)
		
		// Check for specific roles
		expectedRoles := []string{"doctor", "consultant"}
		for _, expected := range expectedRoles {
			assert.Contains(t, roles, expected)
		}

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("get user roles excluding inactive", func(t *testing.T) {
		userID := uuid.New()

		// Create test user with active and inactive roles
		user := &models.User{
			ID: userID,
			Roles: []models.UserRole{
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID:   uuid.New(),
						Name: "doctor",
					},
					IsActive: true,
				},
				{
					UserID: userID,
					RoleID: uuid.New(),
					Role: &models.Role{
						ID:   uuid.New(),
						Name: "admin",
					},
					IsActive: false, // Inactive role
				},
			},
		}

		// Setup mock expectations
		mockUserRepo.On("GetWithPermissions", ctx, userID).Return(user, nil)

		// Test getting user roles
		roles, err := authService.GetUserRoles(ctx, userID)
		
		require.NoError(t, err)
		assert.Len(t, roles, 1) // Only active roles
		assert.Contains(t, roles, "doctor")
		assert.NotContains(t, roles, "admin")

		mockUserRepo.AssertExpectations(t)
	})
} 