package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DeviceType represents the type of OTP device
type DeviceType string

const (
	DeviceTypeSMS   DeviceType = "sms"
	DeviceTypeEmail DeviceType = "email"
	DeviceTypeTOTP  DeviceType = "totp"
)

// UserOTPDevice represents a user's OTP device for MFA
type UserOTPDevice struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	DeviceType      DeviceType `json:"device_type" db:"device_type"`
	DeviceIdentifier string    `json:"device_identifier" db:"device_identifier"`
	SecretKey       *string    `json:"-" db:"secret_key"`
	IsVerified      bool       `json:"is_verified" db:"is_verified"`
	IsActive        bool       `json:"is_active" db:"is_active"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	VerifiedAt      *time.Time `json:"verified_at" db:"verified_at"`
	
	// Relationships
	User *User `json:"user,omitempty" db:"-"`
}

// TableName returns the table name for the UserOTPDevice model
func (UserOTPDevice) TableName() string {
	return "user_otp_devices"
}

// BeforeCreate is called before creating a new OTP device
func (uod *UserOTPDevice) BeforeCreate() error {
	if uod.ID == uuid.Nil {
		uod.ID = uuid.New()
	}
	uod.CreatedAt = time.Now()
	return nil
}

// Validate validates the OTP device data
func (uod *UserOTPDevice) Validate() error {
	if uod.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	
	if uod.DeviceType == "" {
		return fmt.Errorf("device type is required")
	}
	
	if !uod.IsValidDeviceType() {
		return fmt.Errorf("invalid device type: %s", uod.DeviceType)
	}
	
	if uod.DeviceIdentifier == "" {
		return fmt.Errorf("device identifier is required")
	}
	
	// Validate device identifier based on type
	if err := uod.ValidateDeviceIdentifier(); err != nil {
		return err
	}
	
	// TOTP devices must have a secret key
	if uod.DeviceType == DeviceTypeTOTP && (uod.SecretKey == nil || *uod.SecretKey == "") {
		return fmt.Errorf("secret key is required for TOTP devices")
	}
	
	return nil
}

// IsValidDeviceType checks if the device type is valid
func (uod *UserOTPDevice) IsValidDeviceType() bool {
	switch uod.DeviceType {
	case DeviceTypeSMS, DeviceTypeEmail, DeviceTypeTOTP:
		return true
	default:
		return false
	}
}

// ValidateDeviceIdentifier validates the device identifier based on type
func (uod *UserOTPDevice) ValidateDeviceIdentifier() error {
	switch uod.DeviceType {
	case DeviceTypeSMS:
		return uod.validatePhoneNumber()
	case DeviceTypeEmail:
		return uod.validateEmail()
	case DeviceTypeTOTP:
		return uod.validateTOTPIdentifier()
	default:
		return fmt.Errorf("unknown device type")
	}
}

// validatePhoneNumber validates phone number format
func (uod *UserOTPDevice) validatePhoneNumber() error {
	// Basic phone number validation - in production, use a proper phone validation library
	if len(uod.DeviceIdentifier) < 10 || len(uod.DeviceIdentifier) > 15 {
		return fmt.Errorf("phone number must be between 10 and 15 digits")
	}
	
	// Check if all characters are digits
	for _, char := range uod.DeviceIdentifier {
		if char < '0' || char > '9' {
			return fmt.Errorf("phone number must contain only digits")
		}
	}
	
	return nil
}

// validateEmail validates email format
func (uod *UserOTPDevice) validateEmail() error {
	if len(uod.DeviceIdentifier) < 5 || len(uod.DeviceIdentifier) > 255 {
		return fmt.Errorf("email must be between 5 and 255 characters")
	}
	
	// Basic email validation
	atIndex := -1
	dotIndex := -1
	
	for i, char := range uod.DeviceIdentifier {
		if char == '@' {
			if atIndex != -1 {
				return fmt.Errorf("invalid email format")
			}
			atIndex = i
		} else if char == '.' {
			dotIndex = i
		}
	}
	
	if atIndex <= 0 || dotIndex <= atIndex+1 || dotIndex >= len(uod.DeviceIdentifier)-1 {
		return fmt.Errorf("invalid email format")
	}
	
	return nil
}

// validateTOTPIdentifier validates TOTP device identifier
func (uod *UserOTPDevice) validateTOTPIdentifier() error {
	if len(uod.DeviceIdentifier) < 3 || len(uod.DeviceIdentifier) > 100 {
		return fmt.Errorf("TOTP device identifier must be between 3 and 100 characters")
	}
	
	// Check for valid characters
	for _, char := range uod.DeviceIdentifier {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			return fmt.Errorf("TOTP device identifier contains invalid characters")
		}
	}
	
	return nil
}

// Verify marks the device as verified
func (uod *UserOTPDevice) Verify() {
	uod.IsVerified = true
	now := time.Now()
	uod.VerifiedAt = &now
}

// Activate activates the device
func (uod *UserOTPDevice) Activate() {
	uod.IsActive = true
}

// Deactivate deactivates the device
func (uod *UserOTPDevice) Deactivate() {
	uod.IsActive = false
}

// IsValid checks if the device is valid (verified and active)
func (uod *UserOTPDevice) IsValid() bool {
	return uod.IsVerified && uod.IsActive
}

// GetMaskedIdentifier returns a masked version of the device identifier
func (uod *UserOTPDevice) GetMaskedIdentifier() string {
	if uod.DeviceIdentifier == "" {
		return ""
	}
	
	switch uod.DeviceType {
	case DeviceTypeSMS:
		return uod.maskPhoneNumber()
	case DeviceTypeEmail:
		return uod.maskEmail()
	case DeviceTypeTOTP:
		return uod.DeviceIdentifier // Don't mask TOTP identifiers
	default:
		return "***"
	}
}

// maskPhoneNumber masks a phone number
func (uod *UserOTPDevice) maskPhoneNumber() string {
	if len(uod.DeviceIdentifier) < 4 {
		return "***"
	}
	
	return uod.DeviceIdentifier[:2] + "***" + uod.DeviceIdentifier[len(uod.DeviceIdentifier)-2:]
}

// maskEmail masks an email address
func (uod *UserOTPDevice) maskEmail() string {
	if uod.DeviceIdentifier == "" {
		return ""
	}
	
	atIndex := -1
	for i, char := range uod.DeviceIdentifier {
		if char == '@' {
			atIndex = i
			break
		}
	}
	
	if atIndex <= 1 {
		return "***@" + uod.DeviceIdentifier[atIndex+1:]
	}
	
	return uod.DeviceIdentifier[:1] + "***@" + uod.DeviceIdentifier[atIndex+1:]
} 