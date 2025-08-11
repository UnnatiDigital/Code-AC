package tests

import (
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationEvent_BeforeCreate(t *testing.T) {
	event := &models.AuthenticationEvent{
		UserID:    uuidPtr(uuid.New()),
		EventType: "login",
		Success:   true,
	}

	err := event.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, event.ID)
	assert.False(t, event.CreatedAt.IsZero())
}

func TestAuthorizationEvent_BeforeCreate(t *testing.T) {
	event := &models.AuthorizationEvent{
		UserID:   uuidPtr(uuid.New()),
		Resource: "patients",
		Action:   "read",
		Granted:  true,
	}

	err := event.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, event.ID)
	assert.False(t, event.CreatedAt.IsZero())
}

func TestAuthenticationEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   *models.AuthenticationEvent
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid event",
			event: &models.AuthenticationEvent{
				UserID:    uuidPtr(uuid.New()),
				EventType: "login",
				Success:   true,
			},
			wantErr: false,
		},
		{
			name: "missing event type",
			event: &models.AuthenticationEvent{
				UserID:  uuidPtr(uuid.New()),
				Success: true,
			},
			wantErr: true,
			errMsg:  "event type is required",
		},
		{
			name: "invalid event type",
			event: &models.AuthenticationEvent{
				UserID:    uuidPtr(uuid.New()),
				EventType: "invalid_event",
				Success:   true,
			},
			wantErr: true,
			errMsg:  "invalid event type",
		},
		{
			name: "invalid authentication method",
			event: &models.AuthenticationEvent{
				UserID:              uuidPtr(uuid.New()),
				EventType:           "login",
				AuthenticationMethod: stringPtr("invalid_method"),
				Success:             true,
			},
			wantErr: true,
			errMsg:  "invalid authentication method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthorizationEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   *models.AuthorizationEvent
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid event",
			event: &models.AuthorizationEvent{
				UserID:   uuidPtr(uuid.New()),
				Resource: "patients",
				Action:   "read",
				Granted:  true,
			},
			wantErr: false,
		},
		{
			name: "missing resource",
			event: &models.AuthorizationEvent{
				UserID:  uuidPtr(uuid.New()),
				Action:  "read",
				Granted: true,
			},
			wantErr: true,
			errMsg:  "resource is required",
		},
		{
			name: "missing action",
			event: &models.AuthorizationEvent{
				UserID:   uuidPtr(uuid.New()),
				Resource: "patients",
				Granted:  true,
			},
			wantErr: true,
			errMsg:  "action is required",
		},
		{
			name: "resource too long",
			event: &models.AuthorizationEvent{
				UserID:   uuidPtr(uuid.New()),
				Resource: string(make([]byte, 101)),
				Action:   "read",
				Granted:  true,
			},
			wantErr: true,
			errMsg:  "resource must be 100 characters or less",
		},
		{
			name: "action too long",
			event: &models.AuthorizationEvent{
				UserID:   uuidPtr(uuid.New()),
				Resource: "patients",
				Action:   string(make([]byte, 101)),
				Granted:  true,
			},
			wantErr: true,
			errMsg:  "action must be 100 characters or less",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthenticationEvent_IsValidEventType(t *testing.T) {
	tests := []struct {
		name     string
		eventType string
		expected bool
	}{
		{"login", "login", true},
		{"logout", "logout", true},
		{"failed_login", "failed_login", true},
		{"password_change", "password_change", true},
		{"mfa_enabled", "mfa_enabled", true},
		{"mfa_disabled", "mfa_disabled", true},
		{"account_locked", "account_locked", true},
		{"account_unlocked", "account_unlocked", true},
		{"password_reset", "password_reset", true},
		{"session_created", "session_created", true},
		{"session_expired", "session_expired", true},
		{"session_revoked", "session_revoked", true},
		{"invalid event", "invalid_event", false},
		{"empty event type", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &models.AuthenticationEvent{EventType: tt.eventType}
			result := event.IsValidEventType()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthenticationEvent_IsValidAuthenticationMethod(t *testing.T) {
	tests := []struct {
		name     string
		method   *string
		expected bool
	}{
		{"password", stringPtr("password"), true},
		{"biometric", stringPtr("biometric"), true},
		{"otp", stringPtr("otp"), true},
		{"totp", stringPtr("totp"), true},
		{"sms", stringPtr("sms"), true},
		{"email", stringPtr("email"), true},
		{"token", stringPtr("token"), true},
		{"invalid method", stringPtr("invalid_method"), false},
		{"nil method", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &models.AuthenticationEvent{AuthenticationMethod: tt.method}
			result := event.IsValidAuthenticationMethod()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthenticationEvent_GetEventSummary(t *testing.T) {
	userID := uuid.New()
	
	tests := []struct {
		name     string
		event    *models.AuthenticationEvent
		expected string
	}{
		{
			name: "successful login",
			event: &models.AuthenticationEvent{
				UserID:  &userID,
				EventType: "login",
				Success: true,
			},
			expected: "Authentication login for user " + userID.String() + " - SUCCESS",
		},
		{
			name: "failed login with reason",
			event: &models.AuthenticationEvent{
				UserID:        &userID,
				EventType:     "login",
				Success:       false,
				FailureReason: stringPtr("Invalid password"),
			},
			expected: "Authentication login for user " + userID.String() + " - FAILED (Invalid password)",
		},
		{
			name: "failed login without reason",
			event: &models.AuthenticationEvent{
				UserID:    &userID,
				EventType: "login",
				Success:   false,
			},
			expected: "Authentication login for user " + userID.String() + " - FAILED",
		},
		{
			name: "event without user",
			event: &models.AuthenticationEvent{
				EventType: "logout",
				Success:   true,
			},
			expected: "Authentication logout - SUCCESS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.GetEventSummary()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthorizationEvent_GetEventSummary(t *testing.T) {
	userID := uuid.New()
	resourceID := "patient_123"
	
	tests := []struct {
		name     string
		event    *models.AuthorizationEvent
		expected string
	}{
		{
			name: "granted access",
			event: &models.AuthorizationEvent{
				UserID:   &userID,
				Resource: "patients",
				Action:   "read",
				Granted:  true,
			},
			expected: "Authorization patients:read for user " + userID.String() + " - GRANTED",
		},
		{
			name: "denied access with reason",
			event: &models.AuthorizationEvent{
				UserID:   &userID,
				Resource: "patients",
				Action:   "write",
				Granted:  false,
				Reason:   stringPtr("Insufficient permissions"),
			},
			expected: "Authorization patients:write for user " + userID.String() + " - DENIED (Insufficient permissions)",
		},
		{
			name: "denied access without reason",
			event: &models.AuthorizationEvent{
				UserID:   &userID,
				Resource: "patients",
				Action:   "delete",
				Granted:  false,
			},
			expected: "Authorization patients:delete for user " + userID.String() + " - DENIED",
		},
		{
			name: "access with resource ID",
			event: &models.AuthorizationEvent{
				UserID:     &userID,
				Resource:   "patients",
				Action:     "read",
				ResourceID: &resourceID,
				Granted:    true,
			},
			expected: "Authorization patients:read for user " + userID.String() + " on resource " + resourceID + " - GRANTED",
		},
		{
			name: "event without user",
			event: &models.AuthorizationEvent{
				Resource: "system",
				Action:   "health_check",
				Granted:  true,
			},
			expected: "Authorization system:health_check - GRANTED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.GetEventSummary()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthenticationEvent_GetClientInfo(t *testing.T) {
	ipAddress := "192.168.1.1"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	
	event := &models.AuthenticationEvent{
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
	}

	info := event.GetClientInfo()

	assert.Equal(t, ipAddress, info["ip_address"])
	assert.Equal(t, userAgent, info["user_agent"])
}

func TestAuthorizationEvent_GetClientInfo(t *testing.T) {
	ipAddress := "192.168.1.1"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	
	event := &models.AuthorizationEvent{
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
	}

	info := event.GetClientInfo()

	assert.Equal(t, ipAddress, info["ip_address"])
	assert.Equal(t, userAgent, info["user_agent"])
}

func TestJSONMap_Value(t *testing.T) {
	tests := []struct {
		name     string
		jsonMap  models.JSONMap
		expected interface{}
	}{
		{
			name: "nil map",
			jsonMap: nil,
			expected: nil,
		},
		{
			name: "empty map",
			jsonMap: models.JSONMap{},
			expected: "{}",
		},
		{
			name: "simple map",
			jsonMap: models.JSONMap{
				"key": "value",
			},
			expected: `{"key":"value"}`,
		},
		{
			name: "complex map",
			jsonMap: models.JSONMap{
				"string": "test",
				"number": 123,
				"boolean": true,
				"array": []interface{}{1, 2, 3},
				"object": map[string]interface{}{
					"nested": "value",
				},
			},
			expected: `{"array":[1,2,3],"boolean":true,"number":123,"object":{"nested":"value"},"string":"test"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.jsonMap.Value()
			
			if tt.expected == nil {
				assert.NoError(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, string(result.([]byte)))
			}
		})
	}
}

func TestJSONMap_Scan(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected models.JSONMap
		wantErr  bool
	}{
		{
			name:     "nil value",
			value:    nil,
			expected: nil,
			wantErr:  false,
		},
		{
			name:     "empty JSON",
			value:    []byte("{}"),
			expected: models.JSONMap{},
			wantErr:  false,
		},
		{
			name:  "valid JSON",
			value: []byte(`{"key":"value","number":123}`),
			expected: models.JSONMap{
				"key":    "value",
				"number": float64(123), // JSON numbers are unmarshaled as float64
			},
			wantErr: false,
		},
		{
			name:     "string JSON",
			value:    `{"key":"value"}`,
			expected: models.JSONMap{"key": "value"},
			wantErr:  false,
		},
		{
			name:    "invalid JSON",
			value:   []byte(`{"key":`),
			wantErr: true,
		},
		{
			name:    "unsupported type",
			value:   123,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var jsonMap models.JSONMap
			err := jsonMap.Scan(tt.value)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, jsonMap)
			}
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

// Helper function to create UUID pointers
func uuidPtr(id uuid.UUID) *uuid.UUID {
	return &id
} 