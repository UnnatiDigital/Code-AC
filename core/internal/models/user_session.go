package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserSession represents a user session
type UserSession struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	SessionToken    string     `json:"session_token" db:"session_token"`
	RefreshToken    string     `json:"refresh_token" db:"refresh_token"`
	IPAddress       *string    `json:"ip_address" db:"ip_address"`
	UserAgent       *string    `json:"user_agent" db:"user_agent"`
	ExpiresAt       time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	LastAccessedAt  time.Time  `json:"last_accessed_at" db:"last_accessed_at"`
	
	// Relationships
	User *User `json:"user,omitempty" db:"-"`
}

// TableName returns the table name for the UserSession model
func (UserSession) TableName() string {
	return "user_sessions"
}

// BeforeCreate is called before creating a new user session
func (us *UserSession) BeforeCreate() error {
	if us.ID == uuid.Nil {
		us.ID = uuid.New()
	}
	us.CreatedAt = time.Now()
	us.LastAccessedAt = time.Now()
	return nil
}

// Validate validates the user session data
func (us *UserSession) Validate() error {
	if us.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	
	if us.SessionToken == "" {
		return fmt.Errorf("session token is required")
	}
	
	if us.RefreshToken == "" {
		return fmt.Errorf("refresh token is required")
	}
	
	if us.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("expiration date must be in the future")
	}
	
	return nil
}

// IsExpired checks if the session has expired
func (us *UserSession) IsExpired() bool {
	return time.Now().After(us.ExpiresAt)
}

// IsValid checks if the session is valid (not expired)
func (us *UserSession) IsValid() bool {
	return !us.IsExpired()
}

// UpdateLastAccessed updates the last accessed timestamp
func (us *UserSession) UpdateLastAccessed() {
	us.LastAccessedAt = time.Now()
}

// GetRemainingTime returns the remaining time until expiration
func (us *UserSession) GetRemainingTime() time.Duration {
	remaining := us.ExpiresAt.Sub(time.Now())
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Extend extends the session expiration
func (us *UserSession) Extend(duration time.Duration) {
	us.ExpiresAt = us.ExpiresAt.Add(duration)
	us.UpdateLastAccessed()
}

// SetExpiration sets the session expiration
func (us *UserSession) SetExpiration(expiresAt time.Time) error {
	if expiresAt.Before(time.Now()) {
		return fmt.Errorf("expiration date must be in the future")
	}
	
	us.ExpiresAt = expiresAt
	return nil
}

// GetSessionInfo returns session information for logging
func (us *UserSession) GetSessionInfo() map[string]interface{} {
	return map[string]interface{}{
		"session_id":    us.ID,
		"user_id":       us.UserID,
		"ip_address":    us.IPAddress,
		"user_agent":    us.UserAgent,
		"created_at":    us.CreatedAt,
		"expires_at":    us.ExpiresAt,
		"is_expired":    us.IsExpired(),
		"remaining_time": us.GetRemainingTime().String(),
	}
} 