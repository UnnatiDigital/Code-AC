package tests

import (
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_BeforeCreate(t *testing.T) {
	user := &models.User{
		Username: "testuser",
		Email:    "test@example.com",
	}

	err := user.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, user.ID)
	assert.False(t, user.CreatedAt.IsZero())
	assert.False(t, user.UpdatedAt.IsZero())
}

func TestUser_BeforeUpdate(t *testing.T) {
	user := &models.User{
		ID:        uuid.New(),
		Username:  "testuser",
		Email:     "test@example.com",
		CreatedAt: time.Now().Add(-time.Hour),
		UpdatedAt: time.Now().Add(-time.Hour),
	}

	oldUpdatedAt := user.UpdatedAt
	time.Sleep(time.Millisecond) // Ensure time difference

	err := user.BeforeUpdate()
	require.NoError(t, err)

	assert.True(t, user.UpdatedAt.After(oldUpdatedAt))
}

func TestUser_SetPassword(t *testing.T) {
	user := &models.User{
		Username: "testuser",
		Email:    "test@example.com",
	}

	// Test valid password
	err := user.SetPassword("securepassword123")
	require.NoError(t, err)
	assert.NotNil(t, user.PasswordHash)
	assert.NotEmpty(t, *user.PasswordHash)

	// Test empty password
	err = user.SetPassword("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password cannot be empty")
}

func TestUser_CheckPassword(t *testing.T) {
	user := &models.User{
		Username: "testuser",
		Email:    "test@example.com",
	}

	// Set password
	err := user.SetPassword("securepassword123")
	require.NoError(t, err)

	// Test correct password
	assert.True(t, user.CheckPassword("securepassword123"))

	// Test incorrect password
	assert.False(t, user.CheckPassword("wrongpassword"))

	// Test with nil password hash
	user.PasswordHash = nil
	assert.False(t, user.CheckPassword("anypassword"))

	// Test with empty password hash
	emptyHash := ""
	user.PasswordHash = &emptyHash
	assert.False(t, user.CheckPassword("anypassword"))
}

func TestUser_IncrementFailedLoginAttempts(t *testing.T) {
	user := &models.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	initialAttempts := user.FailedLoginAttempts
	oldUpdatedAt := user.UpdatedAt
	time.Sleep(time.Millisecond)

	user.IncrementFailedLoginAttempts()

	assert.Equal(t, initialAttempts+1, user.FailedLoginAttempts)
	assert.True(t, user.UpdatedAt.After(oldUpdatedAt))
}

func TestUser_ResetFailedLoginAttempts(t *testing.T) {
	user := &models.User{
		ID:                    uuid.New(),
		Username:              "testuser",
		Email:                 "test@example.com",
		FailedLoginAttempts:   5,
		IsLocked:              true,
		LockedUntil:           &time.Time{},
	}

	oldUpdatedAt := user.UpdatedAt
	time.Sleep(time.Millisecond)

	user.ResetFailedLoginAttempts()

	assert.Equal(t, 0, user.FailedLoginAttempts)
	assert.False(t, user.IsLocked)
	assert.Nil(t, user.LockedUntil)
	assert.True(t, user.UpdatedAt.After(oldUpdatedAt))
}

func TestUser_LockAccount(t *testing.T) {
	user := &models.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	duration := 30 * time.Minute
	oldUpdatedAt := user.UpdatedAt
	time.Sleep(time.Millisecond)

	user.LockAccount(duration)

	assert.True(t, user.IsLocked)
	assert.NotNil(t, user.LockedUntil)
	assert.True(t, user.LockedUntil.After(time.Now()))
	assert.True(t, user.UpdatedAt.After(oldUpdatedAt))
}

func TestUser_IsAccountLocked(t *testing.T) {
	user := &models.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	// Test unlocked account
	assert.False(t, user.IsAccountLocked())

	// Test locked account with future lock time
	futureTime := time.Now().Add(time.Hour)
	user.IsLocked = true
	user.LockedUntil = &futureTime
	assert.True(t, user.IsAccountLocked())

	// Test locked account with past lock time
	pastTime := time.Now().Add(-time.Hour)
	user.LockedUntil = &pastTime
	assert.False(t, user.IsAccountLocked())

	// Test locked account with nil lock time
	user.LockedUntil = nil
	assert.False(t, user.IsAccountLocked())
}

func TestUser_UpdateLastLogin(t *testing.T) {
	user := &models.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
	}

	oldUpdatedAt := user.UpdatedAt
	time.Sleep(time.Millisecond)

	user.UpdateLastLogin()

	assert.NotNil(t, user.LastLoginAt)
	assert.True(t, user.LastLoginAt.After(oldUpdatedAt))
	assert.True(t, user.UpdatedAt.After(oldUpdatedAt))
}

func TestUser_HasRole(t *testing.T) {
	user := &models.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
		Roles: []models.UserRole{
			{
				ID:       uuid.New(),
				UserID:   user.ID,
				RoleID:   uuid.New(),
				IsActive: true,
				Role: &models.Role{
					ID:   uuid.New(),
					Name: "doctor",
				},
			},
			{
				ID:       uuid.New(),
				UserID:   user.ID,
				RoleID:   uuid.New(),
				IsActive: false, // Inactive role
				Role: &models.Role{
					ID:   uuid.New(),
					Name: "nurse",
				},
			},
		},
	}

	// Test existing active role
	assert.True(t, user.HasRole("doctor"))

	// Test existing inactive role
	assert.False(t, user.HasRole("nurse"))

	// Test non-existing role
	assert.False(t, user.HasRole("admin"))

	// Test with nil role
	user.Roles[0].Role = nil
	assert.False(t, user.HasRole("doctor"))
}

func TestUser_HasPermission(t *testing.T) {
	user := &models.User{
		ID:       uuid.New(),
		Username: "testuser",
		Email:    "test@example.com",
		Roles: []models.UserRole{
			{
				ID:       uuid.New(),
				UserID:   user.ID,
				RoleID:   uuid.New(),
				IsActive: true,
				Role: &models.Role{
					ID:   uuid.New(),
					Name: "doctor",
					Permissions: []models.RolePermission{
						{
							ID:           uuid.New(),
							RoleID:       uuid.New(),
							PermissionID: uuid.New(),
							Permission: &models.Permission{
								ID:       uuid.New(),
								Resource: "patients",
								Action:   "read",
							},
						},
					},
				},
			},
		},
	}

	// Test existing permission
	assert.True(t, user.HasPermission("patients", "read"))

	// Test non-existing permission
	assert.False(t, user.HasPermission("patients", "write"))

	// Test with inactive role
	user.Roles[0].IsActive = false
	assert.False(t, user.HasPermission("patients", "read"))

	// Test with nil role
	user.Roles[0].Role = nil
	assert.False(t, user.HasPermission("patients", "read"))
}

func TestUser_Validate(t *testing.T) {
	tests := []struct {
		name    string
		user    *models.User
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid user",
			user: &models.User{
				Username: "testuser",
				Email:    "test@example.com",
			},
			wantErr: false,
		},
		{
			name: "missing username",
			user: &models.User{
				Email: "test@example.com",
			},
			wantErr: true,
			errMsg:  "username is required",
		},
		{
			name: "username too short",
			user: &models.User{
				Username: "ab",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "username must be between 3 and 50 characters",
		},
		{
			name: "username too long",
			user: &models.User{
				Username: "a" + string(make([]byte, 50)),
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "username must be between 3 and 50 characters",
		},
		{
			name: "missing email",
			user: &models.User{
				Username: "testuser",
			},
			wantErr: true,
			errMsg:  "email is required",
		},
		{
			name: "invalid email format",
			user: &models.User{
				Username: "testuser",
				Email:    "invalid-email",
			},
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name: "email too short",
			user: &models.User{
				Username: "testuser",
				Email:    "a@b",
			},
			wantErr: true,
			errMsg:  "invalid email format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.Validate()
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

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{"valid email", "test@example.com", true},
		{"valid email with subdomain", "test@sub.example.com", true},
		{"valid email with numbers", "test123@example.com", true},
		{"valid email with dots", "test.name@example.com", true},
		{"valid email with underscores", "test_name@example.com", true},
		{"valid email with hyphens", "test-name@example.com", true},
		{"too short", "a@b", false},
		{"too long", "a" + string(make([]byte, 250)) + "@example.com", false},
		{"missing @", "testexample.com", false},
		{"missing domain", "test@", false},
		{"missing local part", "@example.com", false},
		{"multiple @ symbols", "test@@example.com", false},
		{"no dot in domain", "test@example", false},
		{"dot at end", "test@example.", false},
		{"dot at start", "test@.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := models.IsValidEmail(tt.email)
			assert.Equal(t, tt.expected, result)
		})
	}
} 