package services

import (
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
)

// AuthConfig holds configuration for authentication service
type AuthConfig struct {
	// Session configuration
	SessionTTL        time.Duration `json:"session_ttl"`
	RefreshTokenTTL   time.Duration `json:"refresh_token_ttl"`
	
	// Rate limiting configuration
	MaxLoginAttempts  int           `json:"max_login_attempts"`
	LockoutDuration   time.Duration `json:"lockout_duration"`
	RateLimitWindow   time.Duration `json:"rate_limit_window"`
	RateLimitMax      int           `json:"rate_limit_max"`
	
	// OTP configuration
	OTPExpiry         time.Duration `json:"otp_expiry"`
	OTPLength         int           `json:"otp_length"`
	
	// JWT configuration
	JWTSecret         string        `json:"jwt_secret"`
	JWTExpiry         time.Duration `json:"jwt_expiry"`
	
	// Cache configuration
	CacheTTL          time.Duration `json:"cache_ttl"`
	PermissionCacheTTL time.Duration `json:"permission_cache_ttl"`
	
	// Security configuration
	PasswordMinLength int           `json:"password_min_length"`
	PasswordMaxLength int           `json:"password_max_length"`
	RequireMFA        bool          `json:"require_mfa"`
	
	// Audit configuration
	AuditEnabled      bool          `json:"audit_enabled"`
	AuditRetention    time.Duration `json:"audit_retention"`
}

// LoginCredentials represents user login credentials
type LoginCredentials struct {
	Username string `json:"username" validate:"required,min=3,max=50"`
	Password string `json:"password" validate:"required,min=8"`
}

// BiometricData represents biometric authentication data
type BiometricData struct {
	UserID        uuid.UUID `json:"user_id" validate:"required"`
	BiometricType string    `json:"biometric_type" validate:"required,oneof=fingerprint facial iris"`
	Data          []byte    `json:"data" validate:"required"`
	DeviceID      string    `json:"device_id"`
	Quality       float64   `json:"quality"`
}

// AuthenticationResult represents the result of an authentication attempt
type AuthenticationResult struct {
	Success       bool                `json:"success"`
	UserID        uuid.UUID           `json:"user_id,omitempty"`
	SessionToken  string              `json:"session_token,omitempty"`
	RefreshToken  string              `json:"refresh_token,omitempty"`
	ExpiresAt     time.Time           `json:"expires_at,omitempty"`
	RequiresMFA   bool                `json:"requires_mfa,omitempty"`
	Error         string              `json:"error,omitempty"`
	ErrorCode     string              `json:"error_code,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// MFAResult represents the result of a multi-factor authentication attempt
type MFAResult struct {
	Success       bool                `json:"success"`
	UserID        uuid.UUID           `json:"user_id,omitempty"`
	SessionToken  string              `json:"session_token,omitempty"`
	RefreshToken  string              `json:"refresh_token,omitempty"`
	ExpiresAt     time.Time           `json:"expires_at,omitempty"`
	Error         string              `json:"error,omitempty"`
	ErrorCode     string              `json:"error_code,omitempty"`
}

// SessionInfo represents session information
type SessionInfo struct {
	SessionID     uuid.UUID           `json:"session_id"`
	UserID        uuid.UUID           `json:"user_id"`
	IPAddress     string              `json:"ip_address"`
	UserAgent     string              `json:"user_agent"`
	CreatedAt     time.Time           `json:"created_at"`
	ExpiresAt     time.Time           `json:"expires_at"`
	LastAccessed  time.Time           `json:"last_accessed"`
	IsActive      bool                `json:"is_active"`
	RemainingTime time.Duration       `json:"remaining_time"`
}

// UserPermissions represents user permissions information
type UserPermissions struct {
	UserID       uuid.UUID            `json:"user_id"`
	Permissions  []string             `json:"permissions"`
	Roles        []string             `json:"roles"`
	Facilities   []uuid.UUID          `json:"facilities"`
	ExpiresAt    time.Time            `json:"expires_at"`
	LastUpdated  time.Time            `json:"last_updated"`
}

// AuthorizationPolicy represents an authorization policy
type AuthorizationPolicy struct {
	ID          uuid.UUID             `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Rules       []PolicyRule          `json:"rules"`
	Priority    int                   `json:"priority"`
	Enabled     bool                  `json:"enabled"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
}

// PolicyRule represents a rule within an authorization policy
type PolicyRule struct {
	ID          uuid.UUID             `json:"id"`
	Resource    string                `json:"resource"`
	Action      string                `json:"action"`
	Conditions  []PolicyCondition     `json:"conditions"`
	Effect      string                `json:"effect"` // "allow" or "deny"
	Priority    int                   `json:"priority"`
}

// PolicyCondition represents a condition within a policy rule
type PolicyCondition struct {
	Type        string                `json:"type"` // "time", "location", "device", "custom"
	Operator    string                `json:"operator"` // "equals", "not_equals", "in", "not_in", "greater_than", "less_than"
	Field       string                `json:"field"`
	Value       interface{}           `json:"value"`
}

// PasswordPolicy represents password policy configuration
type PasswordPolicy struct {
	MinLength           int      `json:"min_length"`
	MaxLength           int      `json:"max_length"`
	RequireUppercase    bool     `json:"require_uppercase"`
	RequireLowercase    bool     `json:"require_lowercase"`
	RequireNumbers      bool     `json:"require_numbers"`
	RequireSpecialChars bool     `json:"require_special_chars"`
	PreventCommonPasswords bool   `json:"prevent_common_passwords"`
	MaxAge              time.Duration `json:"max_age"`
	HistoryCount        int      `json:"history_count"`
}

// AccountLockoutPolicy represents account lockout policy configuration
type AccountLockoutPolicy struct {
	MaxFailedAttempts   int           `json:"max_failed_attempts"`
	LockoutDuration     time.Duration `json:"lockout_duration"`
	ResetWindow         time.Duration `json:"reset_window"`
	NotifyOnLockout     bool          `json:"notify_on_lockout"`
	NotifyOnUnlock      bool          `json:"notify_on_unlock"`
}

// MFAPolicy represents multi-factor authentication policy
type MFAPolicy struct {
	Enabled             bool     `json:"enabled"`
	RequiredForAll      bool     `json:"required_for_all"`
	RequiredForRoles    []string `json:"required_for_roles"`
	RequiredForFacilities []uuid.UUID `json:"required_for_facilities"`
	AllowedMethods      []string `json:"allowed_methods"` // "sms", "email", "totp", "biometric"
	BackupCodesEnabled  bool     `json:"backup_codes_enabled"`
	BackupCodesCount    int      `json:"backup_codes_count"`
}

// SessionPolicy represents session policy configuration
type SessionPolicy struct {
	MaxSessionsPerUser  int           `json:"max_sessions_per_user"`
	SessionTimeout      time.Duration `json:"session_timeout"`
	IdleTimeout         time.Duration `json:"idle_timeout"`
	AbsoluteTimeout     time.Duration `json:"absolute_timeout"`
	ConcurrentSessions  bool          `json:"concurrent_sessions"`
	RememberMeEnabled   bool          `json:"remember_me_enabled"`
	RememberMeDuration  time.Duration `json:"remember_me_duration"`
}

// AuditPolicy represents audit policy configuration
type AuditPolicy struct {
	Enabled             bool     `json:"enabled"`
	LogAuthentication   bool     `json:"log_authentication"`
	LogAuthorization    bool     `json:"log_authorization"`
	LogUserManagement   bool     `json:"log_user_management"`
	LogDataAccess       bool     `json:"log_data_access"`
	LogSystemEvents     bool     `json:"log_system_events"`
	RetentionPeriod     time.Duration `json:"retention_period"`
	ArchiveEnabled      bool     `json:"archive_enabled"`
	ArchiveLocation     string   `json:"archive_location"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID          uuid.UUID             `json:"id"`
	UserID      *uuid.UUID            `json:"user_id,omitempty"`
	EventType   string                `json:"event_type"`
	Severity    string                `json:"severity"` // "low", "medium", "high", "critical"
	Description string                `json:"description"`
	IPAddress   string                `json:"ip_address"`
	UserAgent   string                `json:"user_agent"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time             `json:"created_at"`
}

// LoginAttempt represents a login attempt
type LoginAttempt struct {
	ID          uuid.UUID             `json:"id"`
	Username    string                `json:"username"`
	UserID      *uuid.UUID            `json:"user_id,omitempty"`
	IPAddress   string                `json:"ip_address"`
	UserAgent   string                `json:"user_agent"`
	Success     bool                  `json:"success"`
	FailureReason string              `json:"failure_reason,omitempty"`
	AttemptNumber int                 `json:"attempt_number"`
	CreatedAt   time.Time             `json:"created_at"`
}

// DeviceInfo represents device information
type DeviceInfo struct {
	DeviceID    string                `json:"device_id"`
	DeviceType  string                `json:"device_type"`
	DeviceName  string                `json:"device_name"`
	OS          string                `json:"os"`
	Browser     string                `json:"browser"`
	IPAddress   string                `json:"ip_address"`
	Location    string                `json:"location"`
	Trusted     bool                  `json:"trusted"`
	LastUsed    time.Time             `json:"last_used"`
}

// UserSessionSummary represents a summary of user sessions
type UserSessionSummary struct {
	UserID          uuid.UUID         `json:"user_id"`
	ActiveSessions  int               `json:"active_sessions"`
	TotalSessions   int               `json:"total_sessions"`
	LastLogin       time.Time         `json:"last_login"`
	LastLogout      time.Time         `json:"last_logout"`
	Devices         []DeviceInfo      `json:"devices"`
}

// PermissionCheck represents a permission check request
type PermissionCheck struct {
	UserID      uuid.UUID             `json:"user_id"`
	Resource    string                `json:"resource"`
	Action      string                `json:"action"`
	ResourceID  *string               `json:"resource_id,omitempty"`
	FacilityID  *uuid.UUID            `json:"facility_id,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// PermissionCheckResult represents the result of a permission check
type PermissionCheckResult struct {
	Granted     bool                  `json:"granted"`
	Reason      string                `json:"reason,omitempty"`
	PolicyID    *uuid.UUID            `json:"policy_id,omitempty"`
	RuleID      *uuid.UUID            `json:"rule_id,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// RoleAssignment represents a role assignment
type RoleAssignment struct {
	UserID      uuid.UUID             `json:"user_id"`
	RoleID      uuid.UUID             `json:"role_id"`
	FacilityID  *uuid.UUID            `json:"facility_id,omitempty"`
	AssignedBy  *uuid.UUID            `json:"assigned_by,omitempty"`
	ExpiresAt   *time.Time            `json:"expires_at,omitempty"`
	Reason      string                `json:"reason,omitempty"`
}

// PermissionGrant represents a permission grant
type PermissionGrant struct {
	RoleID      uuid.UUID             `json:"role_id"`
	PermissionID uuid.UUID            `json:"permission_id"`
	GrantedBy   *uuid.UUID            `json:"granted_by,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	ExpiresAt   *time.Time            `json:"expires_at,omitempty"`
}

// UserSearchCriteria represents criteria for user search
type UserSearchCriteria struct {
	Query       string                `json:"query,omitempty"`
	RoleID      *uuid.UUID            `json:"role_id,omitempty"`
	FacilityID  *uuid.UUID            `json:"facility_id,omitempty"`
	IsActive    *bool                 `json:"is_active,omitempty"`
	IsLocked    *bool                 `json:"is_locked,omitempty"`
	CreatedAfter *time.Time           `json:"created_after,omitempty"`
	CreatedBefore *time.Time          `json:"created_before,omitempty"`
	LastLoginAfter *time.Time         `json:"last_login_after,omitempty"`
	LastLoginBefore *time.Time        `json:"last_login_before,omitempty"`
}

// UserListResult represents the result of a user list operation
type UserListResult struct {
	Users       []*models.User        `json:"users"`
	Total       int                   `json:"total"`
	Page        int                   `json:"page"`
	PageSize    int                   `json:"page_size"`
	TotalPages  int                   `json:"total_pages"`
	HasNext     bool                  `json:"has_next"`
	HasPrev     bool                  `json:"has_prev"`
}

// AuditQuery represents an audit query
type AuditQuery struct {
	UserID      *uuid.UUID            `json:"user_id,omitempty"`
	EventType   string                `json:"event_type,omitempty"`
	StartDate   time.Time             `json:"start_date"`
	EndDate     time.Time             `json:"end_date"`
	IPAddress   string                `json:"ip_address,omitempty"`
	Resource    string                `json:"resource,omitempty"`
	Action      string                `json:"action,omitempty"`
	Success     *bool                 `json:"success,omitempty"`
	Page        int                   `json:"page"`
	PageSize    int                   `json:"page_size"`
}

// AuditResult represents the result of an audit query
type AuditResult struct {
	Events      []interface{}         `json:"events"`
	Total       int                   `json:"total"`
	Page        int                   `json:"page"`
	PageSize    int                   `json:"page_size"`
	TotalPages  int                   `json:"total_pages"`
	Summary     map[string]interface{} `json:"summary"`
} 