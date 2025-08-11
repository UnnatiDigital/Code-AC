package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID                  uuid.UUID       `json:"id" db:"id"`
	Username            string          `json:"username" db:"username"`
	Email               string          `json:"email" db:"email"`
	PasswordHash        *string         `json:"-" db:"password_hash"`
	PasswordSalt        *string         `json:"-" db:"password_salt"`
	IsActive            bool            `json:"is_active" db:"is_active"`
	IsLocked            bool            `json:"is_locked" db:"is_locked"`
	FailedLoginAttempts int             `json:"failed_login_attempts" db:"failed_login_attempts"`
	LastLoginAt         *time.Time      `json:"last_login_at" db:"last_login_at"`
	LockedUntil         *time.Time      `json:"locked_until" db:"locked_until"`
	CreatedAt           time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at" db:"updated_at"`
	CreatedBy           *uuid.UUID      `json:"created_by" db:"created_by"`
	UpdatedBy           *uuid.UUID      `json:"updated_by" db:"updated_by"`
	
	// Relationships
	Roles []UserRole `json:"roles,omitempty" db:"-"`
}

// TableName returns the table name for the User model
func (User) TableName() string {
	return "users"
}

// BeforeCreate is called before creating a new user
func (u *User) BeforeCreate() error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating a user
func (u *User) BeforeUpdate() error {
	u.UpdatedAt = time.Now()
	return nil
}

// SetPassword sets the user's password with bcrypt hashing
func (u *User) SetPassword(password string) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	
	// Generate salt and hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	
	hashStr := string(hash)
	u.PasswordHash = &hashStr
	return nil
}

// CheckPassword verifies if the provided password matches the stored hash
func (u *User) CheckPassword(password string) bool {
	if u.PasswordHash == nil || *u.PasswordHash == "" {
		return false
	}
	
	err := bcrypt.CompareHashAndPassword([]byte(*u.PasswordHash), []byte(password))
	return err == nil
}

// IncrementFailedLoginAttempts increments the failed login counter
func (u *User) IncrementFailedLoginAttempts() {
	u.FailedLoginAttempts++
	u.UpdatedAt = time.Now()
}

// ResetFailedLoginAttempts resets the failed login counter
func (u *User) ResetFailedLoginAttempts() {
	u.FailedLoginAttempts = 0
	u.IsLocked = false
	u.LockedUntil = nil
	u.UpdatedAt = time.Now()
}

// LockAccount locks the user account
func (u *User) LockAccount(duration time.Duration) {
	u.IsLocked = true
	lockTime := time.Now().Add(duration)
	u.LockedUntil = &lockTime
	u.UpdatedAt = time.Now()
}

// IsAccountLocked checks if the account is currently locked
func (u *User) IsAccountLocked() bool {
	if !u.IsLocked {
		return false
	}
	
	if u.LockedUntil == nil {
		return false
	}
	
	return time.Now().Before(*u.LockedUntil)
}

// UpdateLastLogin updates the last login timestamp
func (u *User) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
	u.UpdatedAt = now
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(roleName string) bool {
	for _, role := range u.Roles {
		if role.Role != nil && role.Role.Name == roleName {
			return role.IsActive
		}
	}
	return false
}

// HasPermission checks if the user has a specific permission
func (u *User) HasPermission(resource, action string) bool {
	for _, userRole := range u.Roles {
		if !userRole.IsActive {
			continue
		}
		
		if userRole.Role != nil {
			for _, permission := range userRole.Role.Permissions {
				if permission.Permission != nil &&
					permission.Permission.Resource == resource &&
					permission.Permission.Action == action {
					return true
				}
			}
		}
	}
	return false
}

// Validate validates the user data
func (u *User) Validate() error {
	if u.Username == "" {
		return fmt.Errorf("username is required")
	}
	
	if len(u.Username) < 3 || len(u.Username) > 50 {
		return fmt.Errorf("username must be between 3 and 50 characters")
	}
	
	if u.Email == "" {
		return fmt.Errorf("email is required")
	}
	
	// Basic email validation
	if !isValidEmail(u.Email) {
		return fmt.Errorf("invalid email format")
	}
	
	return nil
}

// isValidEmail performs basic email validation
func isValidEmail(email string) bool {
	// Simple email validation - in production, use a proper email validation library
	if len(email) < 5 || len(email) > 255 {
		return false
	}
	
	atIndex := -1
	dotIndex := -1
	
	for i, char := range email {
		if char == '@' {
			if atIndex != -1 {
				return false // Multiple @ symbols
			}
			atIndex = i
		} else if char == '.' {
			dotIndex = i
		}
	}
	
	return atIndex > 0 && dotIndex > atIndex+1 && dotIndex < len(email)-1
}

// IsValidEmail is exported for testing
func IsValidEmail(email string) bool {
	return isValidEmail(email)
} 