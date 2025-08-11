package tests

import (
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserOTPDevice_BeforeCreate(t *testing.T) {
	device := &models.UserOTPDevice{
		UserID:          uuid.New(),
		DeviceType:      models.DeviceTypeSMS,
		DeviceIdentifier: "+1234567890",
	}

	err := device.BeforeCreate()
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, device.ID)
	assert.False(t, device.CreatedAt.IsZero())
}

func TestUserOTPDevice_Validate(t *testing.T) {
	tests := []struct {
		name    string
		device  *models.UserOTPDevice
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid SMS device",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "+1234567890",
			},
			wantErr: false,
		},
		{
			name: "valid email device",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeEmail,
				DeviceIdentifier: "test@example.com",
			},
			wantErr: false,
		},
		{
			name: "valid TOTP device",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeTOTP,
				DeviceIdentifier: "my_totp_device",
				SecretKey:       stringPtr("JBSWY3DPEHPK3PXP"),
			},
			wantErr: false,
		},
		{
			name: "missing user ID",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "+1234567890",
			},
			wantErr: true,
			errMsg:  "user ID is required",
		},
		{
			name: "missing device type",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceIdentifier: "+1234567890",
			},
			wantErr: true,
			errMsg:  "device type is required",
		},
		{
			name: "invalid device type",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      "invalid_type",
				DeviceIdentifier: "+1234567890",
			},
			wantErr: true,
			errMsg:  "invalid device type",
		},
		{
			name: "missing device identifier",
			device: &models.UserOTPDevice{
				UserID:     uuid.New(),
				DeviceType: models.DeviceTypeSMS,
			},
			wantErr: true,
			errMsg:  "device identifier is required",
		},
		{
			name: "TOTP device without secret key",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeTOTP,
				DeviceIdentifier: "my_totp_device",
			},
			wantErr: true,
			errMsg:  "secret key is required for TOTP devices",
		},
		{
			name: "TOTP device with empty secret key",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeTOTP,
				DeviceIdentifier: "my_totp_device",
				SecretKey:       stringPtr(""),
			},
			wantErr: true,
			errMsg:  "secret key is required for TOTP devices",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.device.Validate()
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

func TestUserOTPDevice_IsValidDeviceType(t *testing.T) {
	tests := []struct {
		name     string
		deviceType models.DeviceType
		expected bool
	}{
		{"SMS device", models.DeviceTypeSMS, true},
		{"Email device", models.DeviceTypeEmail, true},
		{"TOTP device", models.DeviceTypeTOTP, true},
		{"Invalid device", "invalid", false},
		{"Empty device type", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := &models.UserOTPDevice{DeviceType: tt.deviceType}
			result := device.IsValidDeviceType()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserOTPDevice_ValidateDeviceIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		device  *models.UserOTPDevice
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid SMS phone number",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "1234567890",
			},
			wantErr: false,
		},
		{
			name: "valid email address",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeEmail,
				DeviceIdentifier: "test@example.com",
			},
			wantErr: false,
		},
		{
			name: "valid TOTP identifier",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeTOTP,
				DeviceIdentifier: "my_totp_device",
			},
			wantErr: false,
		},
		{
			name: "SMS phone number too short",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "123",
			},
			wantErr: true,
			errMsg:  "phone number must be between 10 and 15 digits",
		},
		{
			name: "SMS phone number too long",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "1234567890123456",
			},
			wantErr: true,
			errMsg:  "phone number must be between 10 and 15 digits",
		},
		{
			name: "SMS phone number with letters",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "123456789a",
			},
			wantErr: true,
			errMsg:  "phone number must contain only digits",
		},
		{
			name: "email too short",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeEmail,
				DeviceIdentifier: "a@b",
			},
			wantErr: true,
			errMsg:  "email must be between 5 and 255 characters",
		},
		{
			name: "invalid email format",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeEmail,
				DeviceIdentifier: "invalid-email",
			},
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name: "TOTP identifier too short",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeTOTP,
				DeviceIdentifier: "ab",
			},
			wantErr: true,
			errMsg:  "TOTP device identifier must be between 3 and 100 characters",
		},
		{
			name: "TOTP identifier with invalid characters",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeTOTP,
				DeviceIdentifier: "my@device",
			},
			wantErr: true,
			errMsg:  "TOTP device identifier contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.device.ValidateDeviceIdentifier()
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

func TestUserOTPDevice_Verify(t *testing.T) {
	device := &models.UserOTPDevice{
		UserID:          uuid.New(),
		DeviceType:      models.DeviceTypeSMS,
		DeviceIdentifier: "+1234567890",
		IsVerified:      false,
	}

	device.Verify()

	assert.True(t, device.IsVerified)
	assert.NotNil(t, device.VerifiedAt)
	assert.True(t, device.VerifiedAt.After(time.Now().Add(-time.Second)))
}

func TestUserOTPDevice_Activate(t *testing.T) {
	device := &models.UserOTPDevice{
		UserID:          uuid.New(),
		DeviceType:      models.DeviceTypeSMS,
		DeviceIdentifier: "+1234567890",
		IsActive:        false,
	}

	device.Activate()

	assert.True(t, device.IsActive)
}

func TestUserOTPDevice_Deactivate(t *testing.T) {
	device := &models.UserOTPDevice{
		UserID:          uuid.New(),
		DeviceType:      models.DeviceTypeSMS,
		DeviceIdentifier: "+1234567890",
		IsActive:        true,
	}

	device.Deactivate()

	assert.False(t, device.IsActive)
}

func TestUserOTPDevice_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		device   *models.UserOTPDevice
		expected bool
	}{
		{
			name: "verified and active",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "+1234567890",
				IsVerified:      true,
				IsActive:        true,
			},
			expected: true,
		},
		{
			name: "not verified",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "+1234567890",
				IsVerified:      false,
				IsActive:        true,
			},
			expected: false,
		},
		{
			name: "not active",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "+1234567890",
				IsVerified:      true,
				IsActive:        false,
			},
			expected: false,
		},
		{
			name: "neither verified nor active",
			device: &models.UserOTPDevice{
				UserID:          uuid.New(),
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "+1234567890",
				IsVerified:      false,
				IsActive:        false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.device.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserOTPDevice_GetMaskedIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		device   *models.UserOTPDevice
		expected string
	}{
		{
			name: "SMS device",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "1234567890",
			},
			expected: "12***90",
		},
		{
			name: "SMS device short",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "123",
			},
			expected: "***",
		},
		{
			name: "email device",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeEmail,
				DeviceIdentifier: "test@example.com",
			},
			expected: "t***@example.com",
		},
		{
			name: "email device short",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeEmail,
				DeviceIdentifier: "a@b",
			},
			expected: "***@b",
		},
		{
			name: "TOTP device",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeTOTP,
				DeviceIdentifier: "my_totp_device",
			},
			expected: "my_totp_device",
		},
		{
			name: "empty identifier",
			device: &models.UserOTPDevice{
				DeviceType:      models.DeviceTypeSMS,
				DeviceIdentifier: "",
			},
			expected: "",
		},
		{
			name: "unknown device type",
			device: &models.UserOTPDevice{
				DeviceType:      "unknown",
				DeviceIdentifier: "test",
			},
			expected: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.device.GetMaskedIdentifier()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
} 