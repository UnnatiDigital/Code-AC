package services

import (
	"context"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
)

// Cache interface for caching operations
type Cache interface {
	// Session management
	SetSession(ctx context.Context, session *models.UserSession, ttl time.Duration) error
	GetSession(ctx context.Context, sessionToken string) (*models.UserSession, error)
	DeleteSession(ctx context.Context, sessionToken string) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
	RefreshSession(ctx context.Context, sessionToken string, ttl time.Duration) error

	// Permission caching
	SetUserPermissions(ctx context.Context, userID uuid.UUID, permissions []string, ttl time.Duration) error
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
	DeleteUserPermissions(ctx context.Context, userID uuid.UUID) error
	CheckUserPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)

	// Role permission caching
	SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissions []string, ttl time.Duration) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error)
	DeleteRolePermissions(ctx context.Context, roleID uuid.UUID) error

	// Rate limiting
	IncrementLoginAttempts(ctx context.Context, username string, ttl time.Duration) (int, error)
	GetLoginAttempts(ctx context.Context, username string) (int, error)
	ResetLoginAttempts(ctx context.Context, username string) error

	// OTP management
	SetOTP(ctx context.Context, identifier string, otp string, ttl time.Duration) error
	GetOTP(ctx context.Context, identifier string) (string, error)
	DeleteOTP(ctx context.Context, identifier string) error

	// Utility methods
	ClearAll(ctx context.Context) error
	GetStats(ctx context.Context) (map[string]interface{}, error)
	Close() error
}

// UserManagementService defines the interface for user management operations
type UserManagementService interface {
	// User CRUD operations
	CreateUser(ctx context.Context, user *models.User, createdBy *uuid.UUID) error
	GetUser(ctx context.Context, userID uuid.UUID) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User, updatedBy *uuid.UUID) error
	DeleteUser(ctx context.Context, userID uuid.UUID, deletedBy *uuid.UUID) error
	
	// User listing and search
	ListUsers(ctx context.Context, offset, limit int, filters map[string]interface{}) ([]*models.User, int, error)
	SearchUsers(ctx context.Context, query string, offset, limit int) ([]*models.User, int, error)
	
	// User status management
	ActivateUser(ctx context.Context, userID uuid.UUID, activatedBy *uuid.UUID) error
	DeactivateUser(ctx context.Context, userID uuid.UUID, deactivatedBy *uuid.UUID) error
	
	// User facility management
	AssignUserToFacility(ctx context.Context, userID, facilityID uuid.UUID, assignedBy *uuid.UUID) error
	RemoveUserFromFacility(ctx context.Context, userID, facilityID uuid.UUID, removedBy *uuid.UUID) error
	
	// Bulk operations
	BulkAssignRoles(ctx context.Context, userIDs []uuid.UUID, roleID uuid.UUID, facilityID *uuid.UUID, assignedBy *uuid.UUID) error
	BulkRevokeRoles(ctx context.Context, userIDs []uuid.UUID, roleID uuid.UUID, revokedBy *uuid.UUID) error
}

// NotificationService defines the interface for notification operations
type NotificationService interface {
	// OTP delivery
	SendOTP(ctx context.Context, deviceType models.DeviceType, deviceIdentifier, otp string) error
	
	// Security notifications
	SendSecurityAlert(ctx context.Context, userID uuid.UUID, alertType string, details map[string]interface{}) error
	SendLoginNotification(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) error
	
	// Account notifications
	SendAccountLockedNotification(ctx context.Context, userID uuid.UUID, reason string) error
	SendPasswordChangedNotification(ctx context.Context, userID uuid.UUID) error
	SendRoleAssignedNotification(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error
}

// BiometricService defines the interface for biometric operations
type BiometricService interface {
	// Biometric verification
	VerifyFingerprint(ctx context.Context, userID uuid.UUID, fingerprintData []byte) (bool, error)
	VerifyFacial(ctx context.Context, userID uuid.UUID, facialData []byte) (bool, error)
	VerifyIris(ctx context.Context, userID uuid.UUID, irisData []byte) (bool, error)
	
	// Biometric enrollment
	EnrollFingerprint(ctx context.Context, userID uuid.UUID, fingerprintData []byte) error
	EnrollFacial(ctx context.Context, userID uuid.UUID, facialData []byte) error
	EnrollIris(ctx context.Context, userID uuid.UUID, irisData []byte) error
	
	// Biometric management
	GetBiometricDevices(ctx context.Context, userID uuid.UUID) ([]*models.UserOTPDevice, error)
	RemoveBiometricDevice(ctx context.Context, deviceID uuid.UUID) error
} 