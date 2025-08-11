package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/repositories"
	"github.com/google/uuid"
)

// AuthorizationService provides authorization and access control functionality
type AuthorizationService struct {
	userRepo repositories.UserRepository
	roleRepo repositories.RoleRepository
	cache    Cache
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(userRepo repositories.UserRepository, roleRepo repositories.RoleRepository, cache Cache) *AuthorizationService {
	return &AuthorizationService{
		userRepo: userRepo,
		roleRepo: roleRepo,
		cache:    cache,
	}
}

// HasRole checks if a user has a specific role
func (s *AuthorizationService) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	user, err := s.userRepo.GetWithPermissions(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user with permissions: %w", err)
	}

	for _, userRole := range user.Roles {
		if !userRole.IsActive {
			continue
		}
		
		if userRole.Role != nil && userRole.Role.Name == roleName {
			return true, nil
		}
	}

	return false, nil
}

// HasPermission checks if a user has a specific permission
func (s *AuthorizationService) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	// Try to get permissions from cache first
	permissions, err := s.cache.GetUserPermissions(ctx, userID)
	if err == nil {
		// Cache hit - check if permission exists
		permissionString := fmt.Sprintf("%s:%s", resource, action)
		for _, perm := range permissions {
			if perm == permissionString {
				return true, nil
			}
		}
		return false, nil
	}

	// Cache miss - get from database
	user, err := s.userRepo.GetWithPermissions(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user with permissions: %w", err)
	}

	// Extract permissions from user roles
	permissions = s.extractUserPermissions(user)
	
	// Cache the permissions for future use
	if len(permissions) > 0 {
		s.cache.SetUserPermissions(ctx, userID, permissions, 30*time.Minute)
	}

	// Check if user has the required permission
	permissionString := fmt.Sprintf("%s:%s", resource, action)
	for _, perm := range permissions {
		if perm == permissionString {
			return true, nil
		}
	}

	return false, nil
}

// HasPermissionWithContext checks if a user has a specific permission with additional context
func (s *AuthorizationService) HasPermissionWithContext(ctx context.Context, userID uuid.UUID, resource, action string, context map[string]interface{}) (bool, error) {
	// First check basic permission
	hasPermission, err := s.HasPermission(ctx, userID, resource, action)
	if err != nil {
		return false, err
	}

	if !hasPermission {
		return false, nil
	}

	// Apply context-based rules
	return s.applyContextRules(ctx, userID, resource, action, context), nil
}

// HasFacilityAccess checks if a user has access to a specific facility
func (s *AuthorizationService) HasFacilityAccess(ctx context.Context, userID uuid.UUID, facilityID uuid.UUID) (bool, error) {
	user, err := s.userRepo.GetWithPermissions(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user with permissions: %w", err)
	}

	for _, userRole := range user.Roles {
		if !userRole.IsActive {
			continue
		}

		// If no facility ID is set, user has system-wide access
		if userRole.FacilityID == nil {
			return true, nil
		}

		// Check if user has access to the specific facility
		if *userRole.FacilityID == facilityID {
			return true, nil
		}
	}

	return false, nil
}

// HasPermissionWithAudit checks if a user has a specific permission and logs the decision
func (s *AuthorizationService) HasPermissionWithAudit(ctx context.Context, userID uuid.UUID, resource, action string, context map[string]interface{}) (bool, error) {
	hasPermission, err := s.HasPermissionWithContext(ctx, userID, resource, action, context)
	if err != nil {
		return false, err
	}

	// Log the authorization decision
	s.logAuthorizationEvent(ctx, userID, resource, action, hasPermission, context)

	return hasPermission, nil
}

// GetUserPermissions returns all permissions for a user
func (s *AuthorizationService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// Try to get from cache first
	permissions, err := s.cache.GetUserPermissions(ctx, userID)
	if err == nil {
		return permissions, nil
	}

	// Cache miss - get from database
	user, err := s.userRepo.GetWithPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user with permissions: %w", err)
	}

	// Extract permissions from user roles
	permissions = s.extractUserPermissions(user)
	
	// Cache the permissions for future use
	if len(permissions) > 0 {
		s.cache.SetUserPermissions(ctx, userID, permissions, 30*time.Minute)
	}

	return permissions, nil
}

// GetUserRoles returns all roles for a user
func (s *AuthorizationService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	user, err := s.userRepo.GetWithPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user with permissions: %w", err)
	}

	var roles []string
	for _, userRole := range user.Roles {
		if !userRole.IsActive {
			continue
		}
		
		if userRole.Role != nil {
			roles = append(roles, userRole.Role.Name)
		}
	}

	return roles, nil
}

// InvalidateUserPermissions invalidates the cached permissions for a user
func (s *AuthorizationService) InvalidateUserPermissions(ctx context.Context, userID uuid.UUID) error {
	return s.cache.DeleteUserPermissions(ctx, userID)
}

// InvalidateRolePermissions invalidates the cached permissions for a role
func (s *AuthorizationService) InvalidateRolePermissions(ctx context.Context, roleID uuid.UUID) error {
	return s.cache.DeleteRolePermissions(ctx, roleID)
}

// CheckPermission checks if a user has permission for a specific resource and action
func (s *AuthorizationService) CheckPermission(ctx context.Context, userID uuid.UUID, resource, action string) (*AuthorizationResult, error) {
	hasPermission, err := s.HasPermission(ctx, userID, resource, action)
	if err != nil {
		return nil, err
	}

	result := &AuthorizationResult{
		UserID:     userID,
		Resource:   resource,
		Action:     action,
		Allowed:    hasPermission,
		Timestamp:  time.Now(),
	}

	if !hasPermission {
		result.Error = "insufficient permissions"
		result.ErrorCode = "INSUFFICIENT_PERMISSIONS"
	}

	return result, nil
}

// CheckPermissionWithContext checks if a user has permission with additional context
func (s *AuthorizationService) CheckPermissionWithContext(ctx context.Context, userID uuid.UUID, resource, action string, context map[string]interface{}) (*AuthorizationResult, error) {
	hasPermission, err := s.HasPermissionWithContext(ctx, userID, resource, action, context)
	if err != nil {
		return nil, err
	}

	result := &AuthorizationResult{
		UserID:     userID,
		Resource:   resource,
		Action:     action,
		Allowed:    hasPermission,
		Context:    context,
		Timestamp:  time.Now(),
	}

	if !hasPermission {
		result.Error = "insufficient permissions or context restrictions"
		result.ErrorCode = "CONTEXT_RESTRICTION"
	}

	return result, nil
}

// GetRolePermissions returns all permissions for a role
func (s *AuthorizationService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	// Try to get from cache first
	permissions, err := s.cache.GetRolePermissions(ctx, roleID)
	if err == nil {
		return permissions, nil
	}

	// Cache miss - get from database
	role, err := s.roleRepo.GetWithPermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role with permissions: %w", err)
	}

	// Extract permissions from role
	permissions = s.extractRolePermissions(role)
	
	// Cache the permissions for future use
	if len(permissions) > 0 {
		s.cache.SetRolePermissions(ctx, roleID, permissions, 30*time.Minute)
	}

	return permissions, nil
}

// GrantPermission grants a permission to a role
func (s *AuthorizationService) GrantPermission(ctx context.Context, roleID, permissionID uuid.UUID, grantedBy *uuid.UUID) error {
	err := s.roleRepo.AddPermission(ctx, roleID, permissionID, grantedBy)
	if err != nil {
		return fmt.Errorf("failed to grant permission: %w", err)
	}

	// Invalidate role permissions cache
	s.InvalidateRolePermissions(ctx, roleID)

	return nil
}

// RevokePermission revokes a permission from a role
func (s *AuthorizationService) RevokePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	err := s.roleRepo.RemovePermission(ctx, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to revoke permission: %w", err)
	}

	// Invalidate role permissions cache
	s.InvalidateRolePermissions(ctx, roleID)

	return nil
}

// AssignRole assigns a role to a user
func (s *AuthorizationService) AssignRole(ctx context.Context, userID, roleID uuid.UUID, facilityID *uuid.UUID, assignedBy *uuid.UUID, expiresAt *time.Time) error {
	// This would typically call a user role repository
	// For now, we'll just invalidate user permissions cache
	s.InvalidateUserPermissions(ctx, userID)
	return nil
}

// RevokeRole revokes a role from a user
func (s *AuthorizationService) RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error {
	// This would typically call a user role repository
	// For now, we'll just invalidate user permissions cache
	s.InvalidateUserPermissions(ctx, userID)
	return nil
}

// Helper methods

// extractUserPermissions extracts all permissions from user roles
func (s *AuthorizationService) extractUserPermissions(user *models.User) []string {
	var permissions []string
	permissionSet := make(map[string]bool)

	for _, userRole := range user.Roles {
		if !userRole.IsActive {
			continue
		}

		if userRole.Role != nil {
			for _, rolePermission := range userRole.Role.Permissions {
				if rolePermission.Permission != nil {
					permissionString := fmt.Sprintf("%s:%s", rolePermission.Permission.Resource, rolePermission.Permission.Action)
					if !permissionSet[permissionString] {
						permissions = append(permissions, permissionString)
						permissionSet[permissionString] = true
					}
				}
			}
		}
	}

	return permissions
}

// extractRolePermissions extracts all permissions from a role
func (s *AuthorizationService) extractRolePermissions(role *models.Role) []string {
	var permissions []string

	for _, rolePermission := range role.Permissions {
		if rolePermission.Permission != nil {
			permissionString := fmt.Sprintf("%s:%s", rolePermission.Permission.Resource, rolePermission.Permission.Action)
			permissions = append(permissions, permissionString)
		}
	}

	return permissions
}

// applyContextRules applies context-based authorization rules
func (s *AuthorizationService) applyContextRules(ctx context.Context, userID uuid.UUID, resource, action string, context map[string]interface{}) bool {
	// Time-based access control
	if timeOfDay, exists := context["time_of_day"]; exists {
		if !s.checkTimeBasedAccess(timeOfDay.(string)) {
			return false
		}
	}

	// Location-based access control
	if location, exists := context["location"]; exists {
		if !s.checkLocationBasedAccess(location.(string)) {
			return false
		}
	}

	// IP-based access control
	if ipAddress, exists := context["ip_address"]; exists {
		if !s.checkIPBasedAccess(ipAddress.(string)) {
			return false
		}
	}

	// Facility-based access control
	if facilityID, exists := context["facility_id"]; exists {
		if facilityUUID, err := uuid.Parse(facilityID.(string)); err == nil {
			if hasAccess, err := s.HasFacilityAccess(ctx, userID, facilityUUID); err != nil || !hasAccess {
				return false
			}
		}
	}

	// Patient-based access control
	if patientID, exists := context["patient_id"]; exists {
		if !s.checkPatientBasedAccess(ctx, userID, patientID.(string)) {
			return false
		}
	}

	return true
}

// checkTimeBasedAccess checks if access is allowed based on time
func (s *AuthorizationService) checkTimeBasedAccess(timeOfDay string) bool {
	switch timeOfDay {
	case "business_hours":
		now := time.Now()
		hour := now.Hour()
		return hour >= 8 && hour <= 18
	case "emergency_hours":
		// Always allow during emergency hours
		return true
	default:
		return true
	}
}

// checkLocationBasedAccess checks if access is allowed based on location
func (s *AuthorizationService) checkLocationBasedAccess(location string) bool {
	allowedLocations := []string{"hospital_premises", "clinic_premises", "authorized_remote"}
	for _, allowed := range allowedLocations {
		if location == allowed {
			return true
		}
	}
	return false
}

// checkIPBasedAccess checks if access is allowed based on IP address
func (s *AuthorizationService) checkIPBasedAccess(ipAddress string) bool {
	// Check if IP is in allowed ranges
	allowedRanges := []string{"192.168.", "10.0.", "172.16."}
	for _, range_ := range allowedRanges {
		if strings.HasPrefix(ipAddress, range_) {
			return true
		}
	}
	return false
}

// checkPatientBasedAccess checks if user has access to specific patient data
func (s *AuthorizationService) checkPatientBasedAccess(ctx context.Context, userID uuid.UUID, patientID string) bool {
	// This would typically check if the user has a relationship with the patient
	// For now, we'll assume access is granted if user has patient-related permissions
	hasPermission, err := s.HasPermission(ctx, userID, "patients", "read")
	if err != nil {
		return false
	}
	return hasPermission
}

// logAuthorizationEvent logs an authorization decision
func (s *AuthorizationService) logAuthorizationEvent(ctx context.Context, userID uuid.UUID, resource, action string, allowed bool, context map[string]interface{}) {
	// This would typically log to an audit service
	// For now, we'll just create the event structure
	event := &models.AuthorizationEvent{
		ID:        uuid.New(),
		UserID:    &userID,
		Resource:  resource,
		Action:    action,
		Granted:   allowed,
		CreatedAt: time.Now(),
	}

	// In a real implementation, this would be sent to an audit service
	_ = event
}

// AuthorizationResult represents the result of an authorization check
type AuthorizationResult struct {
	UserID    uuid.UUID              `json:"user_id"`
	Resource  string                 `json:"resource"`
	Action    string                 `json:"action"`
	Allowed   bool                   `json:"allowed"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Error     string                 `json:"error,omitempty"`
	ErrorCode string                 `json:"error_code,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
} 