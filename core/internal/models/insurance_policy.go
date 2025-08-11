package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// InsurancePolicy represents a patient's insurance policy
type InsurancePolicy struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	PatientID       uuid.UUID  `json:"patient_id" db:"patient_id"`
	PolicyNumber    string     `json:"policy_number" db:"policy_number"`
	PolicyType      string     `json:"policy_type" db:"policy_type"` // "health", "life", "accident", "critical_illness"
	InsuranceProvider string   `json:"insurance_provider" db:"insurance_provider"`
	GroupPolicy     bool       `json:"group_policy" db:"group_policy"`
	GroupName       *string    `json:"group_name" db:"group_name"`
	
	// Policy Details
	SumInsured      *float64   `json:"sum_insured" db:"sum_insured"`
	PremiumAmount   *float64   `json:"premium_amount" db:"premium_amount"`
	PremiumFrequency *string   `json:"premium_frequency" db:"premium_frequency"` // "monthly", "quarterly", "yearly"
	
	// Dates
	StartDate       time.Time  `json:"start_date" db:"start_date"`
	EndDate         time.Time  `json:"end_date" db:"end_date"`
	RenewalDate     *time.Time `json:"renewal_date" db:"renewal_date"`
	
	// Policy Holder Information
	PolicyHolderName string    `json:"policy_holder_name" db:"policy_holder_name"`
	PolicyHolderRelation *string `json:"policy_holder_relation" db:"policy_holder_relation"`
	PolicyHolderDOB   *time.Time `json:"policy_holder_dob" db:"policy_holder_dob"`
	
	// Coverage Details
	CoverageDetails *string    `json:"coverage_details" db:"coverage_details"`
	Exclusions      *string    `json:"exclusions" db:"exclusions"`
	WaitingPeriod   *int       `json:"waiting_period" db:"waiting_period"` // in days
	
	// Status and Priority
	IsActive        bool       `json:"is_active" db:"is_active"`
	Priority        int        `json:"priority" db:"priority"` // 1 = primary, 2 = secondary, etc.
	IsVerified      bool       `json:"is_verified" db:"is_verified"`
	VerificationDate *time.Time `json:"verification_date" db:"verification_date"`
	
	// Documents
	PolicyDocument  *string    `json:"policy_document" db:"policy_document"` // file path or URL
	CardImage       *string    `json:"card_image" db:"card_image"` // file path or URL
	
	// Contact Information
	ProviderContact *string    `json:"provider_contact" db:"provider_contact"`
	ProviderEmail   *string    `json:"provider_email" db:"provider_email"`
	ProviderAddress *string    `json:"provider_address" db:"provider_address"`
	
	// Audit Fields
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy       *uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy       *uuid.UUID `json:"updated_by" db:"updated_by"`
}

// TableName returns the table name for the InsurancePolicy model
func (InsurancePolicy) TableName() string {
	return "insurance_policies"
}

// BeforeCreate is called before creating a new insurance policy
func (ip *InsurancePolicy) BeforeCreate() error {
	if ip.ID == uuid.Nil {
		ip.ID = uuid.New()
	}
	ip.CreatedAt = time.Now()
	ip.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating an insurance policy
func (ip *InsurancePolicy) BeforeUpdate() error {
	ip.UpdatedAt = time.Now()
	return nil
}

// Validate validates the insurance policy data
func (ip *InsurancePolicy) Validate() error {
	if ip.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	
	if ip.PolicyNumber == "" {
		return fmt.Errorf("policy number is required")
	}
	
	if len(ip.PolicyNumber) < 5 || len(ip.PolicyNumber) > 50 {
		return fmt.Errorf("policy number must be between 5 and 50 characters")
	}
	
	if ip.PolicyType == "" {
		return fmt.Errorf("policy type is required")
	}
	
	if !isValidPolicyType(ip.PolicyType) {
		return fmt.Errorf("invalid policy type")
	}
	
	if ip.InsuranceProvider == "" {
		return fmt.Errorf("insurance provider is required")
	}
	
	if ip.PolicyHolderName == "" {
		return fmt.Errorf("policy holder name is required")
	}
	
	if ip.StartDate.IsZero() {
		return fmt.Errorf("start date is required")
	}
	
	if ip.EndDate.IsZero() {
		return fmt.Errorf("end date is required")
	}
	
	if ip.StartDate.After(ip.EndDate) {
		return fmt.Errorf("start date cannot be after end date")
	}
	
	if ip.Priority < 1 {
		return fmt.Errorf("priority must be at least 1")
	}
	
	if ip.PremiumFrequency != nil && !isValidPremiumFrequency(*ip.PremiumFrequency) {
		return fmt.Errorf("invalid premium frequency")
	}
	
	return nil
}

// IsExpired checks if the policy is expired
func (ip *InsurancePolicy) IsExpired() bool {
	return time.Now().After(ip.EndDate)
}

// IsExpiringSoon checks if the policy is expiring within the given days
func (ip *InsurancePolicy) IsExpiringSoon(days int) bool {
	expiryThreshold := time.Now().AddDate(0, 0, days)
	return ip.EndDate.Before(expiryThreshold) && !ip.IsExpired()
}

// GetDaysUntilExpiry returns the number of days until policy expiry
func (ip *InsurancePolicy) GetDaysUntilExpiry() int {
	if ip.IsExpired() {
		return 0
	}
	duration := ip.EndDate.Sub(time.Now())
	return int(duration.Hours() / 24)
}

// IsPrimaryPolicy checks if this is the primary insurance policy
func (ip *InsurancePolicy) IsPrimaryPolicy() bool {
	return ip.Priority == 1
}

// Validation helper functions
func isValidPolicyType(policyType string) bool {
	validTypes := []string{"health", "life", "accident", "critical_illness", "dental", "vision"}
	for _, valid := range validTypes {
		if policyType == valid {
			return true
		}
	}
	return false
}

func isValidPremiumFrequency(frequency string) bool {
	validFrequencies := []string{"monthly", "quarterly", "yearly", "one_time"}
	for _, valid := range validFrequencies {
		if frequency == valid {
			return true
		}
	}
	return false
} 