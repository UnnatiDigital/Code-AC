package tests

import (
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermission_BeforeCreate(t *testing.T) {
	permission := &models.Permission{
		Name:     "test_permission",
		Resource: "test_resource",
		Action:   "read",
	}

	err := permission.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, permission.ID)
	assert.False(t, permission.CreatedAt.IsZero())
}

func TestPermission_Validate(t *testing.T) {
	tests := []struct {
		name    string
		perm    *models.Permission
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid permission",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: "test_resource",
				Action:   "read",
			},
			wantErr: false,
		},
		{
			name: "valid permission with description",
			perm: &models.Permission{
				Name:        "test_permission",
				Description: stringPtr("Test permission description"),
				Resource:    "test_resource",
				Action:      "read",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			perm: &models.Permission{
				Resource: "test_resource",
				Action:   "read",
			},
			wantErr: true,
			errMsg:  "permission name is required",
		},
		{
			name: "name too short",
			perm: &models.Permission{
				Name:     "a",
				Resource: "test_resource",
				Action:   "read",
			},
			wantErr: true,
			errMsg:  "permission name must be between 2 and 100 characters",
		},
		{
			name: "name too long",
			perm: &models.Permission{
				Name:     string(make([]byte, 101)),
				Resource: "test_resource",
				Action:   "read",
			},
			wantErr: true,
			errMsg:  "permission name must be between 2 and 100 characters",
		},
		{
			name: "missing resource",
			perm: &models.Permission{
				Name:   "test_permission",
				Action: "read",
			},
			wantErr: true,
			errMsg:  "permission resource is required",
		},
		{
			name: "resource too short",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: "a",
				Action:   "read",
			},
			wantErr: true,
			errMsg:  "permission resource must be between 2 and 100 characters",
		},
		{
			name: "resource too long",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: string(make([]byte, 101)),
				Action:   "read",
			},
			wantErr: true,
			errMsg:  "permission resource must be between 2 and 100 characters",
		},
		{
			name: "resource with invalid characters",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: "test@resource",
				Action:   "read",
			},
			wantErr: true,
			errMsg:  "invalid permission resource format",
		},
		{
			name: "missing action",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: "test_resource",
			},
			wantErr: true,
			errMsg:  "permission action is required",
		},
		{
			name: "action too short",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: "test_resource",
				Action:   "a",
			},
			wantErr: true,
			errMsg:  "permission action must be between 2 and 100 characters",
		},
		{
			name: "action too long",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: "test_resource",
				Action:   string(make([]byte, 101)),
			},
			wantErr: true,
			errMsg:  "permission action must be between 2 and 100 characters",
		},
		{
			name: "action with invalid characters",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: "test_resource",
				Action:   "read@write",
			},
			wantErr: true,
			errMsg:  "invalid permission action format",
		},
		{
			name: "valid resource and action with underscores",
			perm: &models.Permission{
				Name:     "test_permission",
				Resource: "test_resource_123",
				Action:   "read_write",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.perm.Validate()
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

func TestIsValidPermissionFormat(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"empty string", "", false},
		{"valid lowercase", "test", true},
		{"valid with numbers", "test123", true},
		{"valid with underscores", "test_resource", true},
		{"valid with multiple underscores", "test_resource_123", true},
		{"uppercase letters", "Test", false},
		{"with spaces", "test resource", false},
		{"with hyphens", "test-resource", false},
		{"with dots", "test.resource", false},
		{"with at symbol", "test@resource", false},
		{"with exclamation", "test!resource", false},
		{"with hash", "test#resource", false},
		{"with dollar", "test$resource", false},
		{"with percent", "test%resource", false},
		{"with ampersand", "test&resource", false},
		{"with asterisk", "test*resource", false},
		{"with plus", "test+resource", false},
		{"with equals", "test=resource", false},
		{"with question mark", "test?resource", false},
		{"with period", "test.resource", false},
		{"with comma", "test,resource", false},
		{"with semicolon", "test;resource", false},
		{"with colon", "test:resource", false},
		{"with slash", "test/resource", false},
		{"with backslash", "test\\resource", false},
		{"with pipe", "test|resource", false},
		{"with less than", "test<resource", false},
		{"with greater than", "test>resource", false},
		{"with open bracket", "test[resource", false},
		{"with close bracket", "test]resource", false},
		{"with open brace", "test{resource", false},
		{"with close brace", "test}resource", false},
		{"with open parenthesis", "test(resource", false},
		{"with close parenthesis", "test)resource", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := models.IsValidPermissionFormat(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPermission_GetFullPermission(t *testing.T) {
	permission := &models.Permission{
		ID:       uuid.New(),
		Name:     "test_permission",
		Resource: "patients",
		Action:   "read",
	}

	fullPermission := permission.GetFullPermission()
	assert.Equal(t, "patients:read", fullPermission)
}

func TestPermission_Matches(t *testing.T) {
	permission := &models.Permission{
		ID:       uuid.New(),
		Name:     "test_permission",
		Resource: "patients",
		Action:   "read",
	}

	// Test matching resource and action
	assert.True(t, permission.Matches("patients", "read"))

	// Test non-matching resource
	assert.False(t, permission.Matches("users", "read"))

	// Test non-matching action
	assert.False(t, permission.Matches("patients", "write"))

	// Test non-matching both
	assert.False(t, permission.Matches("users", "write"))
}

func TestPermission_IsSystemPermission(t *testing.T) {
	tests := []struct {
		name     string
		perm     *models.Permission
		expected bool
	}{
		{
			name: "system permission - patients:read",
			perm: &models.Permission{
				ID:       uuid.New(),
				Name:     "view_patients",
				Resource: "patients",
				Action:   "read",
			},
			expected: true,
		},
		{
			name: "system permission - medical_records:create",
			perm: &models.Permission{
				ID:       uuid.New(),
				Name:     "create_medical_records",
				Resource: "medical_records",
				Action:   "create",
			},
			expected: true,
		},
		{
			name: "system permission - users:delete",
			perm: &models.Permission{
				ID:       uuid.New(),
				Name:     "delete_users",
				Resource: "users",
				Action:   "delete",
			},
			expected: true,
		},
		{
			name: "custom permission",
			perm: &models.Permission{
				ID:       uuid.New(),
				Name:     "custom_permission",
				Resource: "custom_resource",
				Action:   "custom_action",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.perm.IsSystemPermission()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPermission_CanBeDeleted(t *testing.T) {
	tests := []struct {
		name     string
		perm     *models.Permission
		expected bool
	}{
		{
			name: "system permission cannot be deleted",
			perm: &models.Permission{
				ID:       uuid.New(),
				Name:     "view_patients",
				Resource: "patients",
				Action:   "read",
				RolePermissions: []models.RolePermission{},
			},
			expected: false,
		},
		{
			name: "custom permission with no roles can be deleted",
			perm: &models.Permission{
				ID:       uuid.New(),
				Name:     "custom_permission",
				Resource: "custom_resource",
				Action:   "custom_action",
				RolePermissions: []models.RolePermission{},
			},
			expected: true,
		},
		{
			name: "custom permission with roles cannot be deleted",
			perm: &models.Permission{
				ID:       uuid.New(),
				Name:     "custom_permission",
				Resource: "custom_resource",
				Action:   "custom_action",
				RolePermissions: []models.RolePermission{
					{
						ID:           uuid.New(),
						RoleID:       uuid.New(),
						PermissionID: uuid.New(),
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.perm.CanBeDeleted()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
} 