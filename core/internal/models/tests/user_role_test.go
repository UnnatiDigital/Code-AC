package tests

import (
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserRole_BeforeCreate(t *testing.T) {
	userRole := &models.UserRole{
		UserID: uuid.New(),
		RoleID: uuid.New(),
	}

	err := userRole.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, userRole.ID)
	assert.False(t, userRole.AssignedAt.IsZero())
}

func TestUserRole_Validate(t *testing.T) {
	tests := []struct {
		name    string
		userRole *models.UserRole
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid user role",
			userRole: &models.UserRole{
				UserID: uuid.New(),
				RoleID: uuid.New(),
			},
			wantErr: false,
		},
		{
			name: "missing user ID",
			userRole: &models.UserRole{
				RoleID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "user ID is required",
		},
		{
			name: "missing role ID",
			userRole: &models.UserRole{
				UserID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "role ID is required",
		},
		{
			name: "expiration date in past",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(-time.Hour)),
			},
			wantErr: true,
			errMsg:  "expiration date must be in the future",
		},
		{
			name: "expiration date in future",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(time.Hour)),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.userRole.Validate()
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

func TestUserRole_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		userRole *models.UserRole
		expected bool
	}{
		{
			name: "no expiration date",
			userRole: &models.UserRole{
				UserID: uuid.New(),
				RoleID: uuid.New(),
			},
			expected: false,
		},
		{
			name: "expiration date in future",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(time.Hour)),
			},
			expected: false,
		},
		{
			name: "expiration date in past",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(-time.Hour)),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.userRole.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserRole_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		userRole *models.UserRole
		expected bool
	}{
		{
			name: "active and not expired",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				IsActive:  true,
				ExpiresAt: timePtr(time.Now().Add(time.Hour)),
			},
			expected: true,
		},
		{
			name: "active and no expiration",
			userRole: &models.UserRole{
				UserID:   uuid.New(),
				RoleID:   uuid.New(),
				IsActive: true,
			},
			expected: true,
		},
		{
			name: "inactive",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				IsActive:  false,
				ExpiresAt: timePtr(time.Now().Add(time.Hour)),
			},
			expected: false,
		},
		{
			name: "expired",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				IsActive:  true,
				ExpiresAt: timePtr(time.Now().Add(-time.Hour)),
			},
			expected: false,
		},
		{
			name: "inactive and expired",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				IsActive:  false,
				ExpiresAt: timePtr(time.Now().Add(-time.Hour)),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.userRole.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserRole_Expire(t *testing.T) {
	userRole := &models.UserRole{
		UserID:    uuid.New(),
		RoleID:    uuid.New(),
		IsActive:  true,
		ExpiresAt: timePtr(time.Now().Add(time.Hour)),
	}

	userRole.Expire()

	assert.False(t, userRole.IsActive)
	assert.NotNil(t, userRole.ExpiresAt)
	assert.True(t, userRole.ExpiresAt.Before(time.Now()) || userRole.ExpiresAt.Equal(time.Now()))
}

func TestUserRole_Extend(t *testing.T) {
	tests := []struct {
		name        string
		userRole    *models.UserRole
		duration    time.Duration
		expectError bool
	}{
		{
			name: "extend with expiration date",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(time.Hour)),
			},
			duration:    30 * time.Minute,
			expectError: false,
		},
		{
			name: "extend without expiration date",
			userRole: &models.UserRole{
				UserID: uuid.New(),
				RoleID: uuid.New(),
			},
			duration:    30 * time.Minute,
			expectError: true,
		},
		{
			name: "extend to past date",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(-time.Hour)),
			},
			duration:    -2 * time.Hour,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalExpiry := tt.userRole.ExpiresAt
			err := tt.userRole.Extend(tt.duration)
			
			if tt.expectError {
				assert.Error(t, err)
				if originalExpiry != nil {
					assert.Equal(t, originalExpiry, tt.userRole.ExpiresAt)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tt.userRole.ExpiresAt)
				assert.True(t, tt.userRole.ExpiresAt.After(*originalExpiry))
			}
		})
	}
}

func TestUserRole_SetExpiration(t *testing.T) {
	tests := []struct {
		name        string
		userRole    *models.UserRole
		expiresAt   time.Time
		expectError bool
	}{
		{
			name: "set future expiration",
			userRole: &models.UserRole{
				UserID: uuid.New(),
				RoleID: uuid.New(),
			},
			expiresAt:   time.Now().Add(time.Hour),
			expectError: false,
		},
		{
			name: "set past expiration",
			userRole: &models.UserRole{
				UserID: uuid.New(),
				RoleID: uuid.New(),
			},
			expiresAt:   time.Now().Add(-time.Hour),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.userRole.SetExpiration(tt.expiresAt)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expiresAt, *tt.userRole.ExpiresAt)
			}
		})
	}
}

func TestUserRole_RemoveExpiration(t *testing.T) {
	userRole := &models.UserRole{
		UserID:    uuid.New(),
		RoleID:    uuid.New(),
		ExpiresAt: timePtr(time.Now().Add(time.Hour)),
	}

	userRole.RemoveExpiration()

	assert.Nil(t, userRole.ExpiresAt)
}

func TestUserRole_Activate(t *testing.T) {
	userRole := &models.UserRole{
		UserID:   uuid.New(),
		RoleID:   uuid.New(),
		IsActive: false,
	}

	userRole.Activate()

	assert.True(t, userRole.IsActive)
}

func TestUserRole_Deactivate(t *testing.T) {
	userRole := &models.UserRole{
		UserID:   uuid.New(),
		RoleID:   uuid.New(),
		IsActive: true,
	}

	userRole.Deactivate()

	assert.False(t, userRole.IsActive)
}

func TestUserRole_GetRemainingTime(t *testing.T) {
	tests := []struct {
		name     string
		userRole *models.UserRole
		expected *time.Duration
	}{
		{
			name: "no expiration date",
			userRole: &models.UserRole{
				UserID: uuid.New(),
				RoleID: uuid.New(),
			},
			expected: nil,
		},
		{
			name: "expiration date in future",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(time.Hour)),
			},
			expected: durationPtr(time.Hour),
		},
		{
			name: "expiration date in past",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(-time.Hour)),
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.userRole.GetRemainingTime()
			
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				// Allow for small timing differences
				assert.True(t, *result >= *tt.expected-time.Second)
				assert.True(t, *result <= *tt.expected+time.Second)
			}
		})
	}
}

func TestUserRole_IsPermanent(t *testing.T) {
	tests := []struct {
		name     string
		userRole *models.UserRole
		expected bool
	}{
		{
			name: "no expiration date",
			userRole: &models.UserRole{
				UserID: uuid.New(),
				RoleID: uuid.New(),
			},
			expected: true,
		},
		{
			name: "with expiration date",
			userRole: &models.UserRole{
				UserID:    uuid.New(),
				RoleID:    uuid.New(),
				ExpiresAt: timePtr(time.Now().Add(time.Hour)),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.userRole.IsPermanent()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper functions
func timePtr(t time.Time) *time.Time {
	return &t
}

func durationPtr(d time.Duration) *time.Duration {
	return &d
} 