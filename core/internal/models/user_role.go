package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserRole represents a user-role assignment
type UserRole struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	RoleID     uuid.UUID  `json:"role_id" db:"role_id"`
	FacilityID *uuid.UUID `json:"facility_id" db:"facility_id"`
	AssignedBy *uuid.UUID `json:"assigned_by" db:"assigned_by"`
	AssignedAt time.Time  `json:"assigned_at" db:"assigned_at"`
	ExpiresAt  *time.Time `json:"expires_at" db:"expires_at"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	
	// Relationships
	User  *User  `json:"user,omitempty" db:"-"`
	Role  *Role  `json:"role,omitempty" db:"-"`
}

// TableName returns the table name for the UserRole model
func (UserRole) TableName() string {
	return "user_roles"
}

// BeforeCreate is called before creating a new user role assignment
func (ur *UserRole) BeforeCreate() error {
	if ur.ID == uuid.Nil {
		ur.ID = uuid.New()
	}
	ur.AssignedAt = time.Now()
	return nil
}

// Validate validates the user role assignment data
func (ur *UserRole) Validate() error {
	if ur.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	
	if ur.RoleID == uuid.Nil {
		return fmt.Errorf("role ID is required")
	}
	
	// Check if expiration date is in the future
	if ur.ExpiresAt != nil && ur.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("expiration date must be in the future")
	}
	
	return nil
}

// IsExpired checks if the role assignment has expired
func (ur *UserRole) IsExpired() bool {
	if ur.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*ur.ExpiresAt)
}

// IsValid checks if the role assignment is valid (active and not expired)
func (ur *UserRole) IsValid() bool {
	return ur.IsActive && !ur.IsExpired()
}

// Expire marks the role assignment as expired
func (ur *UserRole) Expire() {
	now := time.Now()
	ur.ExpiresAt = &now
	ur.IsActive = false
}

// Extend extends the expiration date
func (ur *UserRole) Extend(duration time.Duration) error {
	if ur.ExpiresAt == nil {
		return fmt.Errorf("cannot extend role assignment without expiration date")
	}
	
	newExpiry := ur.ExpiresAt.Add(duration)
	if newExpiry.Before(time.Now()) {
		return fmt.Errorf("new expiration date would be in the past")
	}
	
	ur.ExpiresAt = &newExpiry
	return nil
}

// SetExpiration sets the expiration date
func (ur *UserRole) SetExpiration(expiresAt time.Time) error {
	if expiresAt.Before(time.Now()) {
		return fmt.Errorf("expiration date must be in the future")
	}
	
	ur.ExpiresAt = &expiresAt
	return nil
}

// RemoveExpiration removes the expiration date (makes it permanent)
func (ur *UserRole) RemoveExpiration() {
	ur.ExpiresAt = nil
}

// Activate activates the role assignment
func (ur *UserRole) Activate() {
	ur.IsActive = true
}

// Deactivate deactivates the role assignment
func (ur *UserRole) Deactivate() {
	ur.IsActive = false
}

// GetRemainingTime returns the remaining time until expiration
func (ur *UserRole) GetRemainingTime() *time.Duration {
	if ur.ExpiresAt == nil {
		return nil
	}
	
	remaining := ur.ExpiresAt.Sub(time.Now())
	if remaining <= 0 {
		return nil
	}
	
	return &remaining
}

// IsPermanent checks if the role assignment is permanent (no expiration)
func (ur *UserRole) IsPermanent() bool {
	return ur.ExpiresAt == nil
} 