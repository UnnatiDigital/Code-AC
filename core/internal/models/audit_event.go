package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AuthenticationEvent represents an authentication event for audit logging
type AuthenticationEvent struct {
	ID                  uuid.UUID       `json:"id" db:"id"`
	UserID              *uuid.UUID      `json:"user_id" db:"user_id"`
	EventType           string          `json:"event_type" db:"event_type"`
	AuthenticationMethod *string        `json:"authentication_method" db:"authentication_method"`
	IPAddress           *string         `json:"ip_address" db:"ip_address"`
	UserAgent           *string         `json:"user_agent" db:"user_agent"`
	Success             bool            `json:"success" db:"success"`
	FailureReason       *string         `json:"failure_reason" db:"failure_reason"`
	Metadata            *JSONMap        `json:"metadata" db:"metadata"`
	CreatedAt           time.Time       `json:"created_at" db:"created_at"`
	
	// Relationships
	User *User `json:"user,omitempty" db:"-"`
}

// AuthorizationEvent represents an authorization event for audit logging
type AuthorizationEvent struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     *uuid.UUID `json:"user_id" db:"user_id"`
	Resource   string     `json:"resource" db:"resource"`
	Action     string     `json:"action" db:"action"`
	ResourceID *string    `json:"resource_id" db:"resource_id"`
	FacilityID *uuid.UUID `json:"facility_id" db:"facility_id"`
	Granted    bool       `json:"granted" db:"granted"`
	Reason     *string    `json:"reason" db:"reason"`
	IPAddress  *string    `json:"ip_address" db:"ip_address"`
	UserAgent  *string    `json:"user_agent" db:"user_agent"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	
	// Relationships
	User *User `json:"user,omitempty" db:"-"`
}

// JSONMap represents a JSON object stored in the database
type JSONMap map[string]interface{}

// Value implements the driver.Valuer interface
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into JSONMap", value)
	}
	
	return json.Unmarshal(bytes, j)
}

// TableName returns the table name for the AuthenticationEvent model
func (AuthenticationEvent) TableName() string {
	return "authentication_events"
}

// TableName returns the table name for the AuthorizationEvent model
func (AuthorizationEvent) TableName() string {
	return "authorization_events"
}

// BeforeCreate is called before creating a new authentication event
func (ae *AuthenticationEvent) BeforeCreate() error {
	if ae.ID == uuid.Nil {
		ae.ID = uuid.New()
	}
	ae.CreatedAt = time.Now()
	return nil
}

// BeforeCreate is called before creating a new authorization event
func (ae *AuthorizationEvent) BeforeCreate() error {
	if ae.ID == uuid.Nil {
		ae.ID = uuid.New()
	}
	ae.CreatedAt = time.Now()
	return nil
}

// Validate validates the authentication event data
func (ae *AuthenticationEvent) Validate() error {
	if ae.EventType == "" {
		return fmt.Errorf("event type is required")
	}
	
	if !ae.IsValidEventType() {
		return fmt.Errorf("invalid event type: %s", ae.EventType)
	}
	
	if ae.AuthenticationMethod != nil && !ae.IsValidAuthenticationMethod() {
		return fmt.Errorf("invalid authentication method: %s", *ae.AuthenticationMethod)
	}
	
	return nil
}

// Validate validates the authorization event data
func (ae *AuthorizationEvent) Validate() error {
	if ae.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	
	if ae.Action == "" {
		return fmt.Errorf("action is required")
	}
	
	if len(ae.Resource) > 100 {
		return fmt.Errorf("resource must be 100 characters or less")
	}
	
	if len(ae.Action) > 100 {
		return fmt.Errorf("action must be 100 characters or less")
	}
	
	return nil
}

// IsValidEventType checks if the event type is valid
func (ae *AuthenticationEvent) IsValidEventType() bool {
	validTypes := []string{
		"login", "logout", "failed_login", "password_change", "mfa_enabled",
		"mfa_disabled", "account_locked", "account_unlocked", "password_reset",
		"session_created", "session_expired", "session_revoked",
	}
	
	for _, validType := range validTypes {
		if ae.EventType == validType {
			return true
		}
	}
	return false
}

// IsValidAuthenticationMethod checks if the authentication method is valid
func (ae *AuthenticationEvent) IsValidAuthenticationMethod() bool {
	if ae.AuthenticationMethod == nil {
		return false
	}
	
	validMethods := []string{
		"password", "biometric", "otp", "totp", "sms", "email", "token",
	}
	
	for _, validMethod := range validMethods {
		if *ae.AuthenticationMethod == validMethod {
			return true
		}
	}
	return false
}

// GetEventSummary returns a summary of the event for logging
func (ae *AuthenticationEvent) GetEventSummary() string {
	summary := fmt.Sprintf("Authentication %s", ae.EventType)
	
	if ae.UserID != nil {
		summary += fmt.Sprintf(" for user %s", ae.UserID)
	}
	
	if ae.Success {
		summary += " - SUCCESS"
	} else {
		summary += " - FAILED"
		if ae.FailureReason != nil {
			summary += fmt.Sprintf(" (%s)", *ae.FailureReason)
		}
	}
	
	return summary
}

// GetEventSummary returns a summary of the event for logging
func (ae *AuthorizationEvent) GetEventSummary() string {
	summary := fmt.Sprintf("Authorization %s:%s", ae.Resource, ae.Action)
	
	if ae.UserID != nil {
		summary += fmt.Sprintf(" for user %s", ae.UserID)
	}
	
	if ae.ResourceID != nil {
		summary += fmt.Sprintf(" on resource %s", *ae.ResourceID)
	}
	
	if ae.Granted {
		summary += " - GRANTED"
	} else {
		summary += " - DENIED"
		if ae.Reason != nil {
			summary += fmt.Sprintf(" (%s)", *ae.Reason)
		}
	}
	
	return summary
}

// GetClientInfo returns client information for the event
func (ae *AuthenticationEvent) GetClientInfo() map[string]interface{} {
	info := make(map[string]interface{})
	
	if ae.IPAddress != nil {
		info["ip_address"] = *ae.IPAddress
	}
	
	if ae.UserAgent != nil {
		info["user_agent"] = *ae.UserAgent
	}
	
	return info
}

// GetClientInfo returns client information for the event
func (ae *AuthorizationEvent) GetClientInfo() map[string]interface{} {
	info := make(map[string]interface{})
	
	if ae.IPAddress != nil {
		info["ip_address"] = *ae.IPAddress
	}
	
	if ae.UserAgent != nil {
		info["user_agent"] = *ae.UserAgent
	}
	
	return info
} 