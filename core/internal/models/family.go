package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Family represents a family unit in the healthcare system
type Family struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	FamilyName      string     `json:"family_name" db:"family_name"`
	FamilyCode      string     `json:"family_code" db:"family_code"`
	PrimaryContact  uuid.UUID  `json:"primary_contact" db:"primary_contact"`
	PrimaryMobile   string     `json:"primary_mobile" db:"primary_mobile"`
	PrimaryEmail    *string    `json:"primary_email" db:"primary_email"`
	
	// Family Details
	Address         *string    `json:"address" db:"address"`
	City            *string    `json:"city" db:"city"`
	State           *string    `json:"state" db:"state"`
	PINCode         *string    `json:"pin_code" db:"pin_code"`
	
	// Family Information
	TotalMembers    int        `json:"total_members" db:"total_members"`
	MaxMembers      int        `json:"max_members" db:"max_members"`
	IsActive        bool       `json:"is_active" db:"is_active"`
	
	// Audit Fields
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy       *uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy       *uuid.UUID `json:"updated_by" db:"updated_by"`
	
	// Relationships
	Members         []FamilyMember `json:"members,omitempty" db:"-"`
}

// TableName returns the table name for the Family model
func (Family) TableName() string {
	return "families"
}

// BeforeCreate is called before creating a new family
func (f *Family) BeforeCreate() error {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	
	// Generate family code if not provided
	if f.FamilyCode == "" {
		f.FamilyCode = f.generateFamilyCode()
	}
	
	f.CreatedAt = time.Now()
	f.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating a family
func (f *Family) BeforeUpdate() error {
	f.UpdatedAt = time.Now()
	return nil
}

// generateFamilyCode generates a unique family code
func (f *Family) generateFamilyCode() string {
	// Format: FAM-YYYY-XXXXX (5 digits)
	year := time.Now().Year()
	randomPart := fmt.Sprintf("%05d", f.ID.ID()%100000)
	return fmt.Sprintf("FAM-%d-%s", year, randomPart)
}

// Validate validates the family data
func (f *Family) Validate() error {
	if f.FamilyName == "" {
		return fmt.Errorf("family name is required")
	}
	
	if len(f.FamilyName) < 2 || len(f.FamilyName) > 100 {
		return fmt.Errorf("family name must be between 2 and 100 characters")
	}
	
	if f.PrimaryContact == uuid.Nil {
		return fmt.Errorf("primary contact is required")
	}
	
	if f.PrimaryMobile == "" {
		return fmt.Errorf("primary mobile number is required")
	}
	
	if !isValidMobileNumber(f.PrimaryMobile) {
		return fmt.Errorf("invalid primary mobile number format")
	}
	
	if f.MaxMembers < 1 {
		return fmt.Errorf("maximum members must be at least 1")
	}
	
	if f.TotalMembers > f.MaxMembers {
		return fmt.Errorf("total members cannot exceed maximum members")
	}
	
	return nil
}

// CanAddMember checks if a new member can be added to the family
func (f *Family) CanAddMember() bool {
	return f.TotalMembers < f.MaxMembers && f.IsActive
}

// GetAvailableSlots returns the number of available member slots
func (f *Family) GetAvailableSlots() int {
	return f.MaxMembers - f.TotalMembers
}

// FamilyMember represents a member within a family
type FamilyMember struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	FamilyID        uuid.UUID  `json:"family_id" db:"family_id"`
	PatientID       uuid.UUID  `json:"patient_id" db:"patient_id"`
	Relationship    string     `json:"relationship" db:"relationship"`
	IsPrimaryContact bool      `json:"is_primary_contact" db:"is_primary_contact"`
	IsActive        bool       `json:"is_active" db:"is_active"`
	
	// Authorization and Permissions
	CanViewRecords  bool       `json:"can_view_records" db:"can_view_records"`
	CanBookAppointments bool   `json:"can_book_appointments" db:"can_book_appointments"`
	CanMakePayments bool       `json:"can_make_payments" db:"can_make_payments"`
	EmergencyAccess bool       `json:"emergency_access" db:"emergency_access"`
	
	// Audit Fields
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy       *uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy       *uuid.UUID `json:"updated_by" db:"updated_by"`
	
	// Relationships
	Patient         *Patient   `json:"patient,omitempty" db:"-"`
	Family          *Family    `json:"family,omitempty" db:"-"`
}

// TableName returns the table name for the FamilyMember model
func (FamilyMember) TableName() string {
	return "family_members"
}

// BeforeCreate is called before creating a new family member
func (fm *FamilyMember) BeforeCreate() error {
	if fm.ID == uuid.Nil {
		fm.ID = uuid.New()
	}
	fm.CreatedAt = time.Now()
	fm.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating a family member
func (fm *FamilyMember) BeforeUpdate() error {
	fm.UpdatedAt = time.Now()
	return nil
}

// Validate validates the family member data
func (fm *FamilyMember) Validate() error {
	if fm.FamilyID == uuid.Nil {
		return fmt.Errorf("family ID is required")
	}
	
	if fm.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	
	if fm.Relationship == "" {
		return fmt.Errorf("relationship is required")
	}
	
	if !isValidFamilyRelationship(fm.Relationship) {
		return fmt.Errorf("invalid relationship")
	}
	
	return nil
}

// HasPermission checks if the family member has a specific permission
func (fm *FamilyMember) HasPermission(permission string) bool {
	switch permission {
	case "view_records":
		return fm.CanViewRecords
	case "book_appointments":
		return fm.CanBookAppointments
	case "make_payments":
		return fm.CanMakePayments
	case "emergency_access":
		return fm.EmergencyAccess
	default:
		return false
	}
}

// FamilyRelationship represents the relationship between family members
type FamilyRelationship struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	FamilyID        uuid.UUID  `json:"family_id" db:"family_id"`
	FromMemberID    uuid.UUID  `json:"from_member_id" db:"from_member_id"`
	ToMemberID      uuid.UUID  `json:"to_member_id" db:"to_member_id"`
	Relationship    string     `json:"relationship" db:"relationship"`
	IsActive        bool       `json:"is_active" db:"is_active"`
	
	// Audit Fields
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy       *uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy       *uuid.UUID `json:"updated_by" db:"updated_by"`
}

// TableName returns the table name for the FamilyRelationship model
func (FamilyRelationship) TableName() string {
	return "family_relationships"
}

// BeforeCreate is called before creating a new family relationship
func (fr *FamilyRelationship) BeforeCreate() error {
	if fr.ID == uuid.Nil {
		fr.ID = uuid.New()
	}
	fr.CreatedAt = time.Now()
	fr.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating a family relationship
func (fr *FamilyRelationship) BeforeUpdate() error {
	fr.UpdatedAt = time.Now()
	return nil
}

// Validate validates the family relationship data
func (fr *FamilyRelationship) Validate() error {
	if fr.FamilyID == uuid.Nil {
		return fmt.Errorf("family ID is required")
	}
	
	if fr.FromMemberID == uuid.Nil {
		return fmt.Errorf("from member ID is required")
	}
	
	if fr.ToMemberID == uuid.Nil {
		return fmt.Errorf("to member ID is required")
	}
	
	if fr.FromMemberID == fr.ToMemberID {
		return fmt.Errorf("from and to member cannot be the same")
	}
	
	if fr.Relationship == "" {
		return fmt.Errorf("relationship is required")
	}
	
	if !isValidFamilyRelationship(fr.Relationship) {
		return fmt.Errorf("invalid relationship")
	}
	
	return nil
}

// Validation helper functions
func isValidFamilyRelationship(relationship string) bool {
	validRelationships := []string{
		"self", "spouse", "father", "mother", "son", "daughter",
		"brother", "sister", "grandfather", "grandmother",
		"grandson", "granddaughter", "uncle", "aunt",
		"nephew", "niece", "cousin", "guardian", "ward",
		"father_in_law", "mother_in_law", "brother_in_law", "sister_in_law",
	}
	for _, valid := range validRelationships {
		if relationship == valid {
			return true
		}
	}
	return false
} 