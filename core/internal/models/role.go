package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Role represents a role in the system
type Role struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Name         string    `json:"name" db:"name"`
	Description  *string   `json:"description" db:"description"`
	IsSystemRole bool      `json:"is_system_role" db:"is_system_role"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	
	// Relationships
	Permissions []RolePermission `json:"permissions,omitempty" db:"-"`
	UserRoles   []UserRole       `json:"user_roles,omitempty" db:"-"`
}

// TableName returns the table name for the Role model
func (Role) TableName() string {
	return "roles"
}

// BeforeCreate is called before creating a new role
func (r *Role) BeforeCreate() error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	r.CreatedAt = time.Now()
	r.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating a role
func (r *Role) BeforeUpdate() error {
	r.UpdatedAt = time.Now()
	return nil
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(resource, action string) bool {
	for _, permission := range r.Permissions {
		if permission.Permission != nil &&
			permission.Permission.Resource == resource &&
			permission.Permission.Action == action {
			return true
		}
	}
	return false
}

// AddPermission adds a permission to the role
func (r *Role) AddPermission(permission *Permission, grantedBy *uuid.UUID) {
	rolePermission := RolePermission{
		RoleID:       r.ID,
		PermissionID: permission.ID,
		GrantedBy:    grantedBy,
		GrantedAt:    time.Now(),
	}
	r.Permissions = append(r.Permissions, rolePermission)
}

// RemovePermission removes a permission from the role
func (r *Role) RemovePermission(permissionID uuid.UUID) {
	for i, permission := range r.Permissions {
		if permission.PermissionID == permissionID {
			// Remove from slice
			r.Permissions = append(r.Permissions[:i], r.Permissions[i+1:]...)
			break
		}
	}
}

// Validate validates the role data
func (r *Role) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("role name is required")
	}
	
	if len(r.Name) < 2 || len(r.Name) > 100 {
		return fmt.Errorf("role name must be between 2 and 100 characters")
	}
	
	// Check for valid characters in role name
	for _, char := range r.Name {
		if !isValidRoleNameChar(char) {
			return fmt.Errorf("role name contains invalid characters")
		}
	}
	
	return nil
}

// isValidRoleNameChar checks if a character is valid for role names
func isValidRoleNameChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '_' || char == '-'
}

// IsValidRoleNameChar is exported for testing
func IsValidRoleNameChar(char rune) bool {
	return isValidRoleNameChar(char)
}

// GetIsSystemRole checks if this is a system role
func (r *Role) GetIsSystemRole() bool {
	return r.IsSystemRole
}

// CanBeDeleted checks if the role can be deleted
func (r *Role) CanBeDeleted() bool {
	// System roles cannot be deleted
	if r.IsSystemRole {
		return false
	}
	
	// Check if any users are assigned to this role
	return len(r.UserRoles) == 0
} 