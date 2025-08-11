package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PatientAddress represents a patient's address
type PatientAddress struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	PatientID    uuid.UUID  `json:"patient_id" db:"patient_id"`
	AddressType  string     `json:"address_type" db:"address_type"` // "permanent", "current", "office", "emergency"
	IsPrimary    bool       `json:"is_primary" db:"is_primary"`
	
	// Address Details
	AddressLine1 string     `json:"address_line1" db:"address_line1"`
	AddressLine2 *string    `json:"address_line2" db:"address_line2"`
	City         string     `json:"city" db:"city"`
	State        string     `json:"state" db:"state"`
	District     string     `json:"district" db:"district"`
	SubDistrict  *string    `json:"sub_district" db:"sub_district"`
	PINCode      string     `json:"pin_code" db:"pin_code"`
	Country      string     `json:"country" db:"country"`
	
	// Location Details
	Latitude     *float64   `json:"latitude" db:"latitude"`
	Longitude    *float64   `json:"longitude" db:"longitude"`
	
	// Audit Fields
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy    *uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy    *uuid.UUID `json:"updated_by" db:"updated_by"`
}

// TableName returns the table name for the PatientAddress model
func (PatientAddress) TableName() string {
	return "patient_addresses"
}

// BeforeCreate is called before creating a new patient address
func (pa *PatientAddress) BeforeCreate() error {
	if pa.ID == uuid.Nil {
		pa.ID = uuid.New()
	}
	pa.CreatedAt = time.Now()
	pa.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating a patient address
func (pa *PatientAddress) BeforeUpdate() error {
	pa.UpdatedAt = time.Now()
	return nil
}

// Validate validates the patient address data
func (pa *PatientAddress) Validate() error {
	if pa.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	
	if pa.AddressType == "" {
		return fmt.Errorf("address type is required")
	}
	
	if !isValidAddressType(pa.AddressType) {
		return fmt.Errorf("invalid address type")
	}
	
	if pa.AddressLine1 == "" {
		return fmt.Errorf("address line 1 is required")
	}
	
	if pa.City == "" {
		return fmt.Errorf("city is required")
	}
	
	if pa.State == "" {
		return fmt.Errorf("state is required")
	}
	
	if pa.District == "" {
		return fmt.Errorf("district is required")
	}
	
	if pa.PINCode == "" {
		return fmt.Errorf("PIN code is required")
	}
	
	if !isValidPINCode(pa.PINCode) {
		return fmt.Errorf("invalid PIN code format")
	}
	
	if pa.Country == "" {
		return fmt.Errorf("country is required")
	}
	
	return nil
}

// GetFullAddress returns the complete address as a string
func (pa *PatientAddress) GetFullAddress() string {
	address := pa.AddressLine1
	
	if pa.AddressLine2 != nil && *pa.AddressLine2 != "" {
		address += ", " + *pa.AddressLine2
	}
	
	address += ", " + pa.City
	
	if pa.SubDistrict != nil && *pa.SubDistrict != "" {
		address += ", " + *pa.SubDistrict
	}
	
	address += ", " + pa.District + ", " + pa.State + " - " + pa.PINCode + ", " + pa.Country
	
	return address
}

// Validation helper functions
func isValidAddressType(addressType string) bool {
	validTypes := []string{"permanent", "current", "office", "emergency"}
	for _, valid := range validTypes {
		if addressType == valid {
			return true
		}
	}
	return false
}

func isValidPINCode(pinCode string) bool {
	// Indian PIN code validation (6 digits)
	if len(pinCode) != 6 {
		return false
	}
	for _, char := range pinCode {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
} 