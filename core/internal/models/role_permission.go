package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// RolePermission represents a role-permission assignment
type RolePermission struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	RoleID       uuid.UUID  `json:"role_id" db:"role_id"`
	PermissionID uuid.UUID  `json:"permission_id" db:"permission_id"`
	GrantedBy    *uuid.UUID `json:"granted_by" db:"granted_by"`
	GrantedAt    time.Time  `json:"granted_at" db:"granted_at"`
	
	// Relationships
	Role       *Role       `json:"role,omitempty" db:"-"`
	Permission *Permission `json:"permission,omitempty" db:"-"`
}

// TableName returns the table name for the RolePermission model
func (RolePermission) TableName() string {
	return "role_permissions"
}

// BeforeCreate is called before creating a new role permission assignment
func (rp *RolePermission) BeforeCreate() error {
	if rp.ID == uuid.Nil {
		rp.ID = uuid.New()
	}
	rp.GrantedAt = time.Now()
	return nil
}

// Validate validates the role permission assignment data
func (rp *RolePermission) Validate() error {
	if rp.RoleID == uuid.Nil {
		return fmt.Errorf("role ID is required")
	}
	
	if rp.PermissionID == uuid.Nil {
		return fmt.Errorf("permission ID is required")
	}
	
	return nil
}

// IsGrantedBySystem checks if this permission was granted by the system
func (rp *RolePermission) IsGrantedBySystem() bool {
	return rp.GrantedBy == nil
}

// IsGrantedByUser checks if this permission was granted by a specific user
func (rp *RolePermission) IsGrantedByUser(userID uuid.UUID) bool {
	return rp.GrantedBy != nil && *rp.GrantedBy == userID
} 