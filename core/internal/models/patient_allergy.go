package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PatientAllergy represents a patient's allergy
type PatientAllergy struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	PatientID   uuid.UUID  `json:"patient_id" db:"patient_id"`
	AllergyName string     `json:"allergy_name" db:"allergy_name"`
	Severity    string     `json:"severity" db:"severity"` // "mild", "severe"
	Reaction    *string    `json:"reaction" db:"reaction"`
	OnsetDate   *time.Time `json:"onset_date" db:"onset_date"`
	IsActive    bool       `json:"is_active" db:"is_active"`
	
	// Medical Details
	ICD10Code   *string    `json:"icd10_code" db:"icd10_code"`
	Notes       *string    `json:"notes" db:"notes"`
	
	// Audit Fields
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy   *uuid.UUID `json:"updated_by" db:"updated_by"`
}

// TableName returns the table name for the PatientAllergy model
func (PatientAllergy) TableName() string {
	return "patient_allergies"
}

// BeforeCreate is called before creating a new patient allergy
func (pa *PatientAllergy) BeforeCreate() error {
	if pa.ID == uuid.Nil {
		pa.ID = uuid.New()
	}
	pa.CreatedAt = time.Now()
	pa.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating a patient allergy
func (pa *PatientAllergy) BeforeUpdate() error {
	pa.UpdatedAt = time.Now()
	return nil
}

// Validate validates the patient allergy data
func (pa *PatientAllergy) Validate() error {
	if pa.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	
	if pa.AllergyName == "" {
		return fmt.Errorf("allergy name is required")
	}
	
	if len(pa.AllergyName) < 2 || len(pa.AllergyName) > 100 {
		return fmt.Errorf("allergy name must be between 2 and 100 characters")
	}
	
	if pa.Severity == "" {
		return fmt.Errorf("severity is required")
	}
	
	if !isValidAllergySeverity(pa.Severity) {
		return fmt.Errorf("invalid severity value")
	}
	
	return nil
}

// IsSevereAllergy checks if this is a severe allergy
func (pa *PatientAllergy) IsSevereAllergy() bool {
	return pa.Severity == "severe"
}

// IsPenicillinAllergy checks if this is a penicillin allergy
func (pa *PatientAllergy) IsPenicillinAllergy() bool {
	return pa.AllergyName == "Penicillin" || pa.AllergyName == "penicillin"
}

// Validation helper functions
func isValidAllergySeverity(severity string) bool {
	validSeverities := []string{"mild", "severe"}
	for _, valid := range validSeverities {
		if severity == valid {
			return true
		}
	}
	return false
} 