package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Patient represents a patient in the healthcare system
type Patient struct {
	ID                    uuid.UUID       `json:"id" db:"id"`
	UHID                  string          `json:"uhid" db:"uhid"`
	FirstName             string          `json:"first_name" db:"first_name"`
	LastName              *string         `json:"last_name" db:"last_name"`
	MiddleName            *string         `json:"middle_name" db:"middle_name"`
	DateOfBirth           *time.Time      `json:"date_of_birth" db:"date_of_birth"`
	Age                   *int            `json:"age" db:"age"`
	Gender                string          `json:"gender" db:"gender"`
	BloodGroup            *string         `json:"blood_group" db:"blood_group"`
	RhFactor              *string         `json:"rh_factor" db:"rh_factor"`
	MobileNumber          string          `json:"mobile_number" db:"mobile_number"`
	Email                 *string         `json:"email" db:"email"`
	EmergencyContact      *string         `json:"emergency_contact" db:"emergency_contact"`
	EmergencyContactName  *string         `json:"emergency_contact_name" db:"emergency_contact_name"`
	EmergencyContactRel   *string         `json:"emergency_contact_rel" db:"emergency_contact_rel"`
	
	// Address Information
	Addresses             []PatientAddress `json:"addresses,omitempty" db:"-"`
	
	// Identification
	AadhaarNumber         *string         `json:"aadhaar_number" db:"aadhaar_number"`
	PANNumber             *string         `json:"pan_number" db:"pan_number"`
	ABHAID                *string         `json:"abha_id" db:"abha_id"`
	RationCardNumber      *string         `json:"ration_card_number" db:"ration_card_number"`
	
	// Demographics
	Religion              *string         `json:"religion" db:"religion"`
	Caste                 *string         `json:"caste" db:"caste"`
	Education             *string         `json:"education" db:"education"`
	Occupation            *string         `json:"occupation" db:"occupation"`
	MaritalStatus         *string         `json:"marital_status" db:"marital_status"`
	Nationality           *string         `json:"nationality" db:"nationality"`
	MotherTongue          *string         `json:"mother_tongue" db:"mother_tongue"`
	
	// Medical Information
	Allergies             []PatientAllergy `json:"allergies,omitempty" db:"-"`
	MedicalHistory        *string         `json:"medical_history" db:"medical_history"`
	FamilyHistory         *string         `json:"family_history" db:"family_history"`
	
	// Insurance
	InsurancePolicies     []InsurancePolicy `json:"insurance_policies,omitempty" db:"-"`
	
	// Biometric Data
	BiometricData         *BiometricData  `json:"biometric_data,omitempty" db:"-"`
	
	// Consent and Privacy
	BiometricConsent      bool            `json:"biometric_consent" db:"biometric_consent"`
	DataSharingConsent    bool            `json:"data_sharing_consent" db:"data_sharing_consent"`
	ConsentTimestamp      *time.Time      `json:"consent_timestamp" db:"consent_timestamp"`
	
	// Family Management
	FamilyID              *uuid.UUID      `json:"family_id" db:"family_id"`
	FamilyRole            *string         `json:"family_role" db:"family_role"`
	
	// Registration Details
	RegistrationType      string          `json:"registration_type" db:"registration_type"` // "standard", "emergency"
	RegistrationSource    string          `json:"registration_source" db:"registration_source"` // "walk_in", "referral", "emergency"
	ReferredBy            *string         `json:"referred_by" db:"referred_by"`
	
	// Status and Flags
	IsActive              bool            `json:"is_active" db:"is_active"`
	IsVerified            bool            `json:"is_verified" db:"is_verified"`
	VerificationMethod    *string         `json:"verification_method" db:"verification_method"`
	VerificationTimestamp *time.Time      `json:"verification_timestamp" db:"verification_timestamp"`
	
	// Audit Fields
	CreatedAt             time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at" db:"updated_at"`
	CreatedBy             *uuid.UUID      `json:"created_by" db:"created_by"`
	UpdatedBy             *uuid.UUID      `json:"updated_by" db:"updated_by"`
	
	// Soft Delete
	DeletedAt             *time.Time      `json:"deleted_at" db:"deleted_at"`
}

// TableName returns the table name for the Patient model
func (Patient) TableName() string {
	return "patients"
}

// BeforeCreate is called before creating a new patient
func (p *Patient) BeforeCreate() error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	
	// Generate UHID if not provided
	if p.UHID == "" {
		p.UHID = p.GenerateUHID()
	}
	
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating a patient
func (p *Patient) BeforeUpdate() error {
	p.UpdatedAt = time.Now()
	return nil
}

// GenerateUHID generates a unique UHID for the patient
func (p *Patient) GenerateUHID() string {
	year := time.Now().Year()
	// Format: HMIS-YYYY-XXXXX (where XXXXX is a sequential number)
	// Use a combination of timestamp and UUID for uniqueness
	randomPart := fmt.Sprintf("%05d", p.ID.ID()%100000)
	return fmt.Sprintf("HMIS-%d-%s", year, randomPart)
}

// Validate validates the patient data
func (p *Patient) Validate() error {
	if p.FirstName == "" {
		return fmt.Errorf("first name is required")
	}
	
	if len(p.FirstName) < 2 || len(p.FirstName) > 50 {
		return fmt.Errorf("first name must be between 2 and 50 characters")
	}
	
	if p.MobileNumber == "" {
		return fmt.Errorf("mobile number is required")
	}
	
	if !isValidMobileNumber(p.MobileNumber) {
		return fmt.Errorf("invalid mobile number format")
	}
	
	if p.Gender == "" {
		return fmt.Errorf("gender is required")
	}
	
	if !isValidGender(p.Gender) {
		return fmt.Errorf("invalid gender value")
	}
	
	if p.BloodGroup != nil && !isValidBloodGroup(*p.BloodGroup) {
		return fmt.Errorf("invalid blood group")
	}
	
	if p.AadhaarNumber != nil && !isValidAadhaarNumber(*p.AadhaarNumber) {
		return fmt.Errorf("invalid Aadhaar number")
	}
	
	if p.PANNumber != nil && !isValidPANNumber(*p.PANNumber) {
		return fmt.Errorf("invalid PAN number")
	}
	
	return nil
}

// GetFullName returns the patient's full name
func (p *Patient) GetFullName() string {
	name := p.FirstName
	if p.MiddleName != nil && *p.MiddleName != "" {
		name += " " + *p.MiddleName
	}
	if p.LastName != nil && *p.LastName != "" {
		name += " " + *p.LastName
	}
	return name
}

// GetAge returns the patient's age
func (p *Patient) GetAge() int {
	if p.Age != nil {
		return *p.Age
	}
	if p.DateOfBirth != nil {
		return int(time.Since(*p.DateOfBirth).Hours() / 8760)
	}
	return 0
}

// GetPrimaryAddress returns the primary address
func (p *Patient) GetPrimaryAddress() *PatientAddress {
	for _, addr := range p.Addresses {
		if addr.IsPrimary {
			return &addr
		}
	}
	if len(p.Addresses) > 0 {
		return &p.Addresses[0]
	}
	return nil
}

// HasBiometricData checks if patient has biometric data
func (p *Patient) HasBiometricData() bool {
	return p.BiometricData != nil && (len(p.BiometricData.Fingerprints) > 0 || p.BiometricData.FaceImage != nil)
}

// IsEmergencyRegistration checks if this is an emergency registration
func (p *Patient) IsEmergencyRegistration() bool {
	return p.RegistrationType == "emergency"
}

// Validation helper functions
func isValidMobileNumber(mobile string) bool {
	// Indian mobile number validation (10 digits starting with 6-9)
	if len(mobile) != 10 {
		return false
	}
	for _, char := range mobile {
		if char < '0' || char > '9' {
			return false
		}
	}
	return mobile[0] >= '6' && mobile[0] <= '9'
}

func isValidGender(gender string) bool {
	validGenders := []string{"male", "female", "other", "prefer_not_to_say"}
	for _, valid := range validGenders {
		if gender == valid {
			return true
		}
	}
	return false
}

func isValidBloodGroup(bloodGroup string) bool {
	validGroups := []string{"A", "B", "AB", "O"}
	for _, valid := range validGroups {
		if bloodGroup == valid {
			return true
		}
	}
	return false
}

func isValidAadhaarNumber(aadhaar string) bool {
	if len(aadhaar) != 12 {
		return false
	}
	for _, char := range aadhaar {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func isValidPANNumber(pan string) bool {
	if len(pan) != 10 {
		return false
	}
	// PAN format: ABCDE1234F (5 letters, 4 digits, 1 letter)
	if pan[0] < 'A' || pan[0] > 'Z' {
		return false
	}
	if pan[9] < 'A' || pan[9] > 'Z' {
		return false
	}
	for i := 1; i < 5; i++ {
		if pan[i] < 'A' || pan[i] > 'Z' {
			return false
		}
	}
	for i := 5; i < 9; i++ {
		if pan[i] < '0' || pan[i] > '9' {
			return false
		}
	}
	return true
} 