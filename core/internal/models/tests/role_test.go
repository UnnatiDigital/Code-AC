package tests

import (
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRole_BeforeCreate(t *testing.T) {
	role := &models.Role{
		Name: "test_role",
	}

	err := role.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, role.ID)
	assert.False(t, role.CreatedAt.IsZero())
	assert.False(t, role.UpdatedAt.IsZero())
}

func TestRole_BeforeUpdate(t *testing.T) {
	role := &models.Role{
		ID:        uuid.New(),
		Name:      "test_role",
		CreatedAt: time.Now().Add(-time.Hour),
		UpdatedAt: time.Now().Add(-time.Hour),
	}

	oldUpdatedAt := role.UpdatedAt
	time.Sleep(time.Millisecond) // Ensure time difference

	err := role.BeforeUpdate()
	require.NoError(t, err)

	assert.True(t, role.UpdatedAt.After(oldUpdatedAt))
}

func TestRole_HasPermission(t *testing.T) {
	role := &models.Role{
		ID:   uuid.New(),
		Name: "test_role",
		Permissions: []models.RolePermission{
			{
				ID:           uuid.New(),
				RoleID:       role.ID,
				PermissionID: uuid.New(),
				Permission: &models.Permission{
					ID:       uuid.New(),
					Resource: "patients",
					Action:   "read",
				},
			},
			{
				ID:           uuid.New(),
				RoleID:       role.ID,
				PermissionID: uuid.New(),
				Permission: &models.Permission{
					ID:       uuid.New(),
					Resource: "medical_records",
					Action:   "write",
				},
			},
		},
	}

	// Test existing permissions
	assert.True(t, role.HasPermission("patients", "read"))
	assert.True(t, role.HasPermission("medical_records", "write"))

	// Test non-existing permissions
	assert.False(t, role.HasPermission("patients", "write"))
	assert.False(t, role.HasPermission("users", "read"))

	// Test with nil permission
	role.Permissions[0].Permission = nil
	assert.False(t, role.HasPermission("patients", "read"))
}

func TestRole_AddPermission(t *testing.T) {
	role := &models.Role{
		ID:   uuid.New(),
		Name: "test_role",
	}

	permission := &models.Permission{
		ID:       uuid.New(),
		Resource: "patients",
		Action:   "read",
	}

	grantedBy := uuid.New()

	role.AddPermission(permission, &grantedBy)

	assert.Len(t, role.Permissions, 1)
	assert.Equal(t, permission.ID, role.Permissions[0].PermissionID)
	assert.Equal(t, &grantedBy, role.Permissions[0].GrantedBy)
	assert.False(t, role.Permissions[0].GrantedAt.IsZero())
}

func TestRole_RemovePermission(t *testing.T) {
	permission1 := &models.Permission{ID: uuid.New()}
	permission2 := &models.Permission{ID: uuid.New()}

	role := &models.Role{
		ID:   uuid.New(),
		Name: "test_role",
		Permissions: []models.RolePermission{
			{
				ID:           uuid.New(),
				RoleID:       uuid.New(),
				PermissionID: permission1.ID,
				Permission:   permission1,
			},
			{
				ID:           uuid.New(),
				RoleID:       uuid.New(),
				PermissionID: permission2.ID,
				Permission:   permission2,
			},
		},
	}

	// Remove first permission
	role.RemovePermission(permission1.ID)
	assert.Len(t, role.Permissions, 1)
	assert.Equal(t, permission2.ID, role.Permissions[0].PermissionID)

	// Remove second permission
	role.RemovePermission(permission2.ID)
	assert.Len(t, role.Permissions, 0)

	// Try to remove non-existing permission
	role.RemovePermission(uuid.New())
	assert.Len(t, role.Permissions, 0)
}

func TestRole_Validate(t *testing.T) {
	tests := []struct {
		name    string
		role    *models.Role
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid role",
			role: &models.Role{
				Name: "test_role",
			},
			wantErr: false,
		},
		{
			name: "valid role with description",
			role: &models.Role{
				Name:        "test_role",
				Description: stringPtr("Test role description"),
			},
			wantErr: false,
		},
		{
			name: "missing name",
			role: &models.Role{},
			wantErr: true,
			errMsg:  "role name is required",
		},
		{
			name: "name too short",
			role: &models.Role{
				Name: "a",
			},
			wantErr: true,
			errMsg:  "role name must be between 2 and 100 characters",
		},
		{
			name: "name too long",
			role: &models.Role{
				Name: string(make([]byte, 101)),
			},
			wantErr: true,
			errMsg:  "role name must be between 2 and 100 characters",
		},
		{
			name: "name with invalid characters",
			role: &models.Role{
				Name: "test@role",
			},
			wantErr: true,
			errMsg:  "role name contains invalid characters",
		},
		{
			name: "name with spaces",
			role: &models.Role{
				Name: "test role",
			},
			wantErr: true,
			errMsg:  "role name contains invalid characters",
		},
		{
			name: "name with valid characters",
			role: &models.Role{
				Name: "test_role-123",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.role.Validate()
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

func TestIsValidRoleNameChar(t *testing.T) {
	tests := []struct {
		name     string
		char     rune
		expected bool
	}{
		{"lowercase letter", 'a', true},
		{"uppercase letter", 'A', true},
		{"digit", '0', true},
		{"digit 9", '9', true},
		{"underscore", '_', true},
		{"hyphen", '-', true},
		{"space", ' ', false},
		{"at symbol", '@', false},
		{"exclamation", '!', false},
		{"hash", '#', false},
		{"dollar", '$', false},
		{"percent", '%', false},
		{"ampersand", '&', false},
		{"asterisk", '*', false},
		{"plus", '+', false},
		{"equals", '=', false},
		{"question mark", '?', false},
		{"period", '.', false},
		{"comma", ',', false},
		{"semicolon", ';', false},
		{"colon", ':', false},
		{"slash", '/', false},
		{"backslash", '\\', false},
		{"pipe", '|', false},
		{"less than", '<', false},
		{"greater than", '>', false},
		{"open bracket", '[', false},
		{"close bracket", ']', false},
		{"open brace", '{', false},
		{"close brace", '}', false},
		{"open parenthesis", '(', false},
		{"close parenthesis", ')', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := models.IsValidRoleNameChar(tt.char)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRole_IsSystemRole(t *testing.T) {
	tests := []struct {
		name     string
		role     *models.Role
		expected bool
	}{
		{
			name: "system role",
			role: &models.Role{
				ID:           uuid.New(),
				Name:         "super_admin",
				IsSystemRole: true,
			},
			expected: true,
		},
		{
			name: "non-system role",
			role: &models.Role{
				ID:           uuid.New(),
				Name:         "custom_role",
				IsSystemRole: false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.role.IsSystemRole()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRole_CanBeDeleted(t *testing.T) {
	tests := []struct {
		name     string
		role     *models.Role
		expected bool
	}{
		{
			name: "system role cannot be deleted",
			role: &models.Role{
				ID:           uuid.New(),
				Name:         "super_admin",
				IsSystemRole: true,
			},
			expected: false,
		},
		{
			name: "custom role with no users can be deleted",
			role: &models.Role{
				ID:           uuid.New(),
				Name:         "custom_role",
				IsSystemRole: false,
				UserRoles:    []models.UserRole{},
			},
			expected: true,
		},
		{
			name: "custom role with users cannot be deleted",
			role: &models.Role{
				ID:           uuid.New(),
				Name:         "custom_role",
				IsSystemRole: false,
				UserRoles: []models.UserRole{
					{
						ID:     uuid.New(),
						UserID: uuid.New(),
						RoleID: uuid.New(),
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.role.CanBeDeleted()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
} 