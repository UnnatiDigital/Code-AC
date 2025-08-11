package repositories

import (
	"context"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	
	// User management operations
	List(ctx context.Context, offset, limit int, filters map[string]interface{}) ([]*models.User, int, error)
	GetWithRoles(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.User, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error
	ResetFailedLoginAttempts(ctx context.Context, id uuid.UUID) error
	LockAccount(ctx context.Context, id uuid.UUID, duration time.Duration) error
	UnlockAccount(ctx context.Context, id uuid.UUID) error
	
	// Search and filtering
	Search(ctx context.Context, query string, offset, limit int) ([]*models.User, int, error)
	GetByFacility(ctx context.Context, facilityID uuid.UUID, offset, limit int) ([]*models.User, int, error)
	GetByRole(ctx context.Context, roleID uuid.UUID, offset, limit int) ([]*models.User, int, error)
}

// RoleRepository defines the interface for role data operations
type RoleRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, role *models.Role) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
	GetByName(ctx context.Context, name string) (*models.Role, error)
	Update(ctx context.Context, role *models.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Role management operations
	List(ctx context.Context, offset, limit int, filters map[string]interface{}) ([]*models.Role, int, error)
	GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.Role, error)
	GetSystemRoles(ctx context.Context) ([]*models.Role, error)
	GetCustomRoles(ctx context.Context) ([]*models.Role, error)
	
	// Permission management
	AddPermission(ctx context.Context, roleID, permissionID uuid.UUID, grantedBy *uuid.UUID) error
	RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetPermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error)
	HasPermission(ctx context.Context, roleID uuid.UUID, resource, action string) (bool, error)
}

// PermissionRepository defines the interface for permission data operations
type PermissionRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, permission *models.Permission) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error)
	GetByResourceAction(ctx context.Context, resource, action string) (*models.Permission, error)
	Update(ctx context.Context, permission *models.Permission) error
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Permission management operations
	List(ctx context.Context, offset, limit int, filters map[string]interface{}) ([]*models.Permission, int, error)
	GetSystemPermissions(ctx context.Context) ([]*models.Permission, error)
	GetCustomPermissions(ctx context.Context) ([]*models.Permission, error)
	GetByResource(ctx context.Context, resource string) ([]*models.Permission, error)
	GetByAction(ctx context.Context, action string) ([]*models.Permission, error)
}

// UserRoleRepository defines the interface for user-role assignment operations
type UserRoleRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, userRole *models.UserRole) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.UserRole, error)
	Update(ctx context.Context, userRole *models.UserRole) error
	Delete(ctx context.Context, id uuid.UUID) error
	
	// User-role management operations
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.UserRole, error)
	GetByRoleID(ctx context.Context, roleID uuid.UUID) ([]*models.UserRole, error)
	GetByUserAndRole(ctx context.Context, userID, roleID uuid.UUID) (*models.UserRole, error)
	GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*models.UserRole, error)
	GetByFacility(ctx context.Context, facilityID uuid.UUID, offset, limit int) ([]*models.UserRole, int, error)
	
	// Assignment operations
	AssignRole(ctx context.Context, userID, roleID uuid.UUID, facilityID *uuid.UUID, assignedBy *uuid.UUID, expiresAt *time.Time) error
	RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error
	ActivateRole(ctx context.Context, userID, roleID uuid.UUID) error
	DeactivateRole(ctx context.Context, userID, roleID uuid.UUID) error
	ExtendRole(ctx context.Context, userID, roleID uuid.UUID, duration time.Duration) error
}

// RolePermissionRepository defines the interface for role-permission assignment operations
type RolePermissionRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, rolePermission *models.RolePermission) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.RolePermission, error)
	Update(ctx context.Context, rolePermission *models.RolePermission) error
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Role-permission management operations
	GetByRoleID(ctx context.Context, roleID uuid.UUID) ([]*models.RolePermission, error)
	GetByPermissionID(ctx context.Context, permissionID uuid.UUID) ([]*models.RolePermission, error)
	GetByRoleAndPermission(ctx context.Context, roleID, permissionID uuid.UUID) (*models.RolePermission, error)
	
	// Assignment operations
	GrantPermission(ctx context.Context, roleID, permissionID uuid.UUID, grantedBy *uuid.UUID) error
	RevokePermission(ctx context.Context, roleID, permissionID uuid.UUID) error
	HasPermission(ctx context.Context, roleID uuid.UUID, resource, action string) (bool, error)
}

// UserSessionRepository defines the interface for user session operations
type UserSessionRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, session *models.UserSession) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.UserSession, error)
	Update(ctx context.Context, session *models.UserSession) error
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Session management operations
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.UserSession, error)
	GetBySessionToken(ctx context.Context, sessionToken string) (*models.UserSession, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*models.UserSession, error)
	GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*models.UserSession, error)
	GetExpiredSessions(ctx context.Context, before time.Time) ([]*models.UserSession, error)
	
	// Session operations
	UpdateLastAccessed(ctx context.Context, id uuid.UUID) error
	ExtendSession(ctx context.Context, id uuid.UUID, duration time.Duration) error
	RevokeSession(ctx context.Context, id uuid.UUID) error
	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error
	CleanupExpiredSessions(ctx context.Context, before time.Time) error
}

// UserOTPDeviceRepository defines the interface for OTP device operations
type UserOTPDeviceRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, device *models.UserOTPDevice) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.UserOTPDevice, error)
	Update(ctx context.Context, device *models.UserOTPDevice) error
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Device management operations
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.UserOTPDevice, error)
	GetByUserIDAndType(ctx context.Context, userID uuid.UUID, deviceType models.DeviceType) ([]*models.UserOTPDevice, error)
	GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*models.UserOTPDevice, error)
	GetByDeviceIdentifier(ctx context.Context, deviceIdentifier string) (*models.UserOTPDevice, error)
	
	// Device operations
	VerifyDevice(ctx context.Context, id uuid.UUID) error
	ActivateDevice(ctx context.Context, id uuid.UUID) error
	DeactivateDevice(ctx context.Context, id uuid.UUID) error
	DeactivateAllUserDevices(ctx context.Context, userID uuid.UUID) error
}

// AuditRepository defines the interface for audit event operations
type AuditRepository interface {
	// Authentication events
	CreateAuthenticationEvent(ctx context.Context, event *models.AuthenticationEvent) error
	GetAuthenticationEvents(ctx context.Context, userID *uuid.UUID, offset, limit int, filters map[string]interface{}) ([]*models.AuthenticationEvent, int, error)
	GetAuthenticationEventsByDateRange(ctx context.Context, startDate, endDate time.Time, offset, limit int) ([]*models.AuthenticationEvent, int, error)
	
	// Authorization events
	CreateAuthorizationEvent(ctx context.Context, event *models.AuthorizationEvent) error
	GetAuthorizationEvents(ctx context.Context, userID *uuid.UUID, offset, limit int, filters map[string]interface{}) ([]*models.AuthorizationEvent, int, error)
	GetAuthorizationEventsByDateRange(ctx context.Context, startDate, endDate time.Time, offset, limit int) ([]*models.AuthorizationEvent, int, error)
	
	// Audit operations
	GetAuditSummary(ctx context.Context, startDate, endDate time.Time) (map[string]interface{}, error)
	CleanupOldEvents(ctx context.Context, before time.Time) error
	ExportAuditData(ctx context.Context, startDate, endDate time.Time, format string) ([]byte, error)
} 