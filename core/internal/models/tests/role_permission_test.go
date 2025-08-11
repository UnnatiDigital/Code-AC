package tests

import (
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRolePermission_BeforeCreate(t *testing.T) {
	rolePermission := &models.RolePermission{
		RoleID:       uuid.New(),
		PermissionID: uuid.New(),
	}

	err := rolePermission.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, rolePermission.ID)
	assert.False(t, rolePermission.GrantedAt.IsZero())
}

func TestRolePermission_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rolePerm *models.RolePermission
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid role permission",
			rolePerm: &models.RolePermission{
				RoleID:       uuid.New(),
				PermissionID: uuid.New(),
			},
			wantErr: false,
		},
		{
			name: "missing role ID",
			rolePerm: &models.RolePermission{
				PermissionID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "role ID is required",
		},
		{
			name: "missing permission ID",
			rolePerm: &models.RolePermission{
				RoleID: uuid.New(),
			},
			wantErr: true,
			errMsg:  "permission ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rolePerm.Validate()
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

func TestRolePermission_IsGrantedBySystem(t *testing.T) {
	tests := []struct {
		name     string
		rolePerm *models.RolePermission
		expected bool
	}{
		{
			name: "granted by system",
			rolePerm: &models.RolePermission{
				ID:           uuid.New(),
				RoleID:       uuid.New(),
				PermissionID: uuid.New(),
				GrantedBy:    nil,
			},
			expected: true,
		},
		{
			name: "granted by user",
			rolePerm: &models.RolePermission{
				ID:           uuid.New(),
				RoleID:       uuid.New(),
				PermissionID: uuid.New(),
				GrantedBy:    uuidPtr(uuid.New()),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rolePerm.IsGrantedBySystem()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRolePermission_IsGrantedByUser(t *testing.T) {
	userID := uuid.New()
	
	tests := []struct {
		name     string
		rolePerm *models.RolePermission
		userID   uuid.UUID
		expected bool
	}{
		{
			name: "granted by specific user",
			rolePerm: &models.RolePermission{
				ID:           uuid.New(),
				RoleID:       uuid.New(),
				PermissionID: uuid.New(),
				GrantedBy:    &userID,
			},
			userID:   userID,
			expected: true,
		},
		{
			name: "granted by different user",
			rolePerm: &models.RolePermission{
				ID:           uuid.New(),
				RoleID:       uuid.New(),
				PermissionID: uuid.New(),
				GrantedBy:    &userID,
			},
			userID:   uuid.New(),
			expected: false,
		},
		{
			name: "granted by system",
			rolePerm: &models.RolePermission{
				ID:           uuid.New(),
				RoleID:       uuid.New(),
				PermissionID: uuid.New(),
				GrantedBy:    nil,
			},
			userID:   userID,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rolePerm.IsGrantedByUser(tt.userID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create UUID pointers
func uuidPtr(id uuid.UUID) *uuid.UUID {
	return &id
} 