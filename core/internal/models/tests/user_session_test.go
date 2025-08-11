package tests

import (
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserSession_BeforeCreate(t *testing.T) {
	userSession := &models.UserSession{
		UserID:       uuid.New(),
		SessionToken: "test_session_token",
		RefreshToken: "test_refresh_token",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	err := userSession.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, userSession.ID)
	assert.False(t, userSession.CreatedAt.IsZero())
	assert.False(t, userSession.LastAccessedAt.IsZero())
}

func TestUserSession_Validate(t *testing.T) {
	tests := []struct {
		name    string
		session *models.UserSession
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid session",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			wantErr: false,
		},
		{
			name: "missing user ID",
			session: &models.UserSession{
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			wantErr: true,
			errMsg:  "user ID is required",
		},
		{
			name: "missing session token",
			session: &models.UserSession{
				UserID:       uuid.New(),
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			wantErr: true,
			errMsg:  "session token is required",
		},
		{
			name: "missing refresh token",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			wantErr: true,
			errMsg:  "refresh token is required",
		},
		{
			name: "expiration date in past",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(-time.Hour),
			},
			wantErr: true,
			errMsg:  "expiration date must be in the future",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.session.Validate()
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

func TestUserSession_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		session  *models.UserSession
		expected bool
	}{
		{
			name: "not expired",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "expired",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(-time.Hour),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.session.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserSession_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		session  *models.UserSession
		expected bool
	}{
		{
			name: "valid session",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			expected: true,
		},
		{
			name: "expired session",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(-time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.session.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserSession_UpdateLastAccessed(t *testing.T) {
	session := &models.UserSession{
		UserID:       uuid.New(),
		SessionToken: "test_session_token",
		RefreshToken: "test_refresh_token",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAccessedAt: time.Now().Add(-time.Hour),
	}

	oldLastAccessed := session.LastAccessedAt
	time.Sleep(time.Millisecond)

	session.UpdateLastAccessed()

	assert.True(t, session.LastAccessedAt.After(oldLastAccessed))
}

func TestUserSession_GetRemainingTime(t *testing.T) {
	tests := []struct {
		name     string
		session  *models.UserSession
		expected time.Duration
	}{
		{
			name: "one hour remaining",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			expected: time.Hour,
		},
		{
			name: "expired session",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(-time.Hour),
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.session.GetRemainingTime()
			
			if tt.expected > 0 {
				// Allow for small timing differences
				assert.True(t, result >= tt.expected-time.Second)
				assert.True(t, result <= tt.expected+time.Second)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestUserSession_Extend(t *testing.T) {
	session := &models.UserSession{
		UserID:       uuid.New(),
		SessionToken: "test_session_token",
		RefreshToken: "test_refresh_token",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAccessedAt: time.Now().Add(-time.Hour),
	}

	originalExpiry := session.ExpiresAt
	oldLastAccessed := session.LastAccessedAt
	extension := 30 * time.Minute
	time.Sleep(time.Millisecond)

	session.Extend(extension)

	assert.True(t, session.ExpiresAt.After(originalExpiry))
	assert.True(t, session.LastAccessedAt.After(oldLastAccessed))
}

func TestUserSession_SetExpiration(t *testing.T) {
	tests := []struct {
		name        string
		session     *models.UserSession
		expiresAt   time.Time
		expectError bool
	}{
		{
			name: "set future expiration",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			expiresAt:   time.Now().Add(2 * time.Hour),
			expectError: false,
		},
		{
			name: "set past expiration",
			session: &models.UserSession{
				UserID:       uuid.New(),
				SessionToken: "test_session_token",
				RefreshToken: "test_refresh_token",
				ExpiresAt:    time.Now().Add(time.Hour),
			},
			expiresAt:   time.Now().Add(-time.Hour),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.session.SetExpiration(tt.expiresAt)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expiresAt, tt.session.ExpiresAt)
			}
		})
	}
}

func TestUserSession_GetSessionInfo(t *testing.T) {
	userID := uuid.New()
	ipAddress := "192.168.1.1"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	expiresAt := time.Now().Add(time.Hour)

	session := &models.UserSession{
		ID:             uuid.New(),
		UserID:         userID,
		SessionToken:   "test_session_token",
		RefreshToken:   "test_refresh_token",
		IPAddress:      &ipAddress,
		UserAgent:      &userAgent,
		ExpiresAt:      expiresAt,
		CreatedAt:      time.Now().Add(-30 * time.Minute),
		LastAccessedAt: time.Now().Add(-5 * time.Minute),
	}

	info := session.GetSessionInfo()

	assert.Equal(t, session.ID, info["session_id"])
	assert.Equal(t, session.UserID, info["user_id"])
	assert.Equal(t, session.IPAddress, info["ip_address"])
	assert.Equal(t, session.UserAgent, info["user_agent"])
	assert.Equal(t, session.CreatedAt, info["created_at"])
	assert.Equal(t, session.ExpiresAt, info["expires_at"])
	assert.Equal(t, session.IsExpired(), info["is_expired"])
	assert.NotEmpty(t, info["remaining_time"])
} 