package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Permission represents a permission in the system
type Permission struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description *string   `json:"description" db:"description"`
	Resource    string    `json:"resource" db:"resource"`
	Action      string    `json:"action" db:"action"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	
	// Relationships
	RolePermissions []RolePermission `json:"role_permissions,omitempty" db:"-"`
}

// TableName returns the table name for the Permission model
func (Permission) TableName() string {
	return "permissions"
}

// BeforeCreate is called before creating a new permission
func (p *Permission) BeforeCreate() error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.CreatedAt = time.Now()
	return nil
}

// Validate validates the permission data
func (p *Permission) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("permission name is required")
	}
	
	if len(p.Name) < 2 || len(p.Name) > 100 {
		return fmt.Errorf("permission name must be between 2 and 100 characters")
	}
	
	if p.Resource == "" {
		return fmt.Errorf("permission resource is required")
	}
	
	if len(p.Resource) < 2 || len(p.Resource) > 100 {
		return fmt.Errorf("permission resource must be between 2 and 100 characters")
	}
	
	if p.Action == "" {
		return fmt.Errorf("permission action is required")
	}
	
	if len(p.Action) < 2 || len(p.Action) > 100 {
		return fmt.Errorf("permission action must be between 2 and 100 characters")
	}
	
	// Validate resource and action format
	if !isValidPermissionFormat(p.Resource) {
		return fmt.Errorf("invalid permission resource format")
	}
	
	if !isValidPermissionFormat(p.Action) {
		return fmt.Errorf("invalid permission action format")
	}
	
	return nil
}

// isValidPermissionFormat checks if the permission format is valid
func isValidPermissionFormat(value string) bool {
	if len(value) == 0 {
		return false
	}
	
	// Check for valid characters: lowercase letters, numbers, underscores
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '_') {
			return false
		}
	}
	
	return true
}

// IsValidPermissionFormat is exported for testing
func IsValidPermissionFormat(value string) bool {
	return isValidPermissionFormat(value)
}

// GetFullPermission returns the full permission string (resource:action)
func (p *Permission) GetFullPermission() string {
	return fmt.Sprintf("%s:%s", p.Resource, p.Action)
}

// Matches checks if this permission matches the given resource and action
func (p *Permission) Matches(resource, action string) bool {
	return p.Resource == resource && p.Action == action
}

// IsSystemPermission checks if this is a system permission
func (p *Permission) IsSystemPermission() bool {
	// System permissions are those that are created by default
	systemPermissions := []string{
		"patients:read", "patients:create", "patients:update", "patients:delete",
		"medical_records:read", "medical_records:create", "medical_records:update", "medical_records:delete",
		"appointments:read", "appointments:create", "appointments:update", "appointments:delete",
		"prescriptions:read", "prescriptions:create", "prescriptions:update", "prescriptions:delete",
		"users:read", "users:create", "users:update", "users:delete",
		"roles:read", "roles:create", "roles:update", "roles:delete",
		"permissions:read", "permissions:create", "permissions:update", "permissions:delete",
		"facilities:read", "facilities:create", "facilities:update", "facilities:delete",
		"reports:read", "reports:create", "reports:update", "reports:delete",
		"audit:read", "audit:create", "audit:update", "audit:delete",
		"system:read", "system:create", "system:update", "system:delete",
	}
	
	fullPermission := p.GetFullPermission()
	for _, sysPerm := range systemPermissions {
		if fullPermission == sysPerm {
			return true
		}
	}
	
	return false
}

// CanBeDeleted checks if the permission can be deleted
func (p *Permission) CanBeDeleted() bool {
	// System permissions cannot be deleted
	if p.IsSystemPermission() {
		return false
	}
	
	// Check if any roles are using this permission
	return len(p.RolePermissions) == 0
} 