package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bmad-method/hmis-core/internal/database"
	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/repositories"
)

// DuplicatePatientError represents an error when a duplicate patient is found
type DuplicatePatientError struct {
	Message    string
	Duplicates []*models.Patient
}

func (e *DuplicatePatientError) Error() string {
	return e.Message
}

// PatientService handles patient-related business logic
type PatientService struct {
	db             *database.Connection
	patientRepo    *repositories.PatientRepository
	addressRepo    *repositories.PatientAddressRepository
	allergyRepo    *repositories.PatientAllergyRepository
}

// NewPatientService creates a new patient service
func NewPatientService(db *database.Connection) *PatientService {
	return &PatientService{
		db:          db,
		patientRepo: repositories.NewPatientRepository(db.DB),
		addressRepo: repositories.NewPatientAddressRepository(db.DB),
		allergyRepo: repositories.NewPatientAllergyRepository(db.DB),
	}
}

// PatientSearchCriteria defines search parameters
type PatientSearchCriteria struct {
	Query         string `json:"query"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	MobileNumber  string `json:"mobileNumber"`
	AadhaarNumber string `json:"aadhaarNumber"`
	UHID          string `json:"uhid"`
	Page          int    `json:"page"`
	Limit         int    `json:"limit"`
}

// RegisterPatient registers a new patient
func (s *PatientService) RegisterPatient(patient *models.Patient) error {
	ctx := context.Background()
	
	// Set timestamps
	now := time.Now()
	patient.CreatedAt = now
	patient.UpdatedAt = now
	patient.IsActive = true

	// Generate UHID if not provided
	if patient.UHID == "" {
		uhid, err := s.GenerateUHID(patient)
		if err != nil {
			return fmt.Errorf("failed to generate UHID: %w", err)
		}
		patient.UHID = uhid
	}

	// Validate patient data before insertion
	if err := patient.Validate(); err != nil {
		return fmt.Errorf("patient validation failed: %w", err)
	}

	// Check for duplicates before registration
	duplicates, err := s.CheckDuplicatePatient(patient)
	if err != nil {
		return fmt.Errorf("failed to check for duplicates: %w", err)
	}

	// If duplicates found, return error
	if len(duplicates) > 0 {
		// Determine the type of duplicate and create appropriate error message
		var errorMessage string
		duplicate := duplicates[0] // Get the first duplicate for error message
		
		if duplicate.MobileNumber == patient.MobileNumber && patient.MobileNumber != "" {
			errorMessage = fmt.Sprintf("A patient with mobile number %s already exists (UHID: %s)", patient.MobileNumber, duplicate.UHID)
		} else if duplicate.AadhaarNumber != nil && patient.AadhaarNumber != nil && *duplicate.AadhaarNumber == *patient.AadhaarNumber {
			errorMessage = fmt.Sprintf("A patient with Aadhaar number %s already exists (UHID: %s)", *patient.AadhaarNumber, duplicate.UHID)
		} else {
			// Name + DOB match
			errorMessage = fmt.Sprintf("A patient with the same name and date of birth already exists (UHID: %s)", duplicate.UHID)
		}
		
		duplicateErr := &DuplicatePatientError{
			Message:    errorMessage,
			Duplicates: duplicates,
		}
		return duplicateErr
	}

	// Insert patient using repository
	err = s.patientRepo.Create(ctx, patient)
	if err != nil {
		return fmt.Errorf("failed to register patient: %w", err)
	}

	return nil
}

// GetPatientByID retrieves a patient by ID
func (s *PatientService) GetPatientByID(id uuid.UUID) (*models.Patient, error) {
	query := `
		SELECT id, uhid, first_name, last_name, date_of_birth, gender, blood_group,
		       marital_status, mobile_number, email, aadhaar_number, pan_number,
		       abha_id, is_active, created_at, updated_at
		FROM patients WHERE id = $1 AND deleted_at IS NULL
	`

	var patient models.Patient
	err := s.db.QueryRow(query, id).Scan(
		&patient.ID, &patient.UHID, &patient.FirstName, &patient.LastName,
		&patient.DateOfBirth, &patient.Gender, &patient.BloodGroup,
		&patient.MaritalStatus, &patient.MobileNumber, &patient.Email,
		&patient.AadhaarNumber, &patient.PANNumber, &patient.ABHAID,
		&patient.IsActive, &patient.CreatedAt, &patient.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get patient: %w", err)
	}

	return &patient, nil
}

// GetPatientByUHID retrieves a patient by UHID
func (s *PatientService) GetPatientByUHID(uhid string) (*models.Patient, error) {
	query := `
		SELECT id, uhid, first_name, last_name, date_of_birth, gender, blood_group,
		       marital_status, mobile_number, email, aadhaar_number, pan_number,
		       abha_id, is_active, created_at, updated_at
		FROM patients WHERE uhid = $1 AND deleted_at IS NULL
	`

	var patient models.Patient
	err := s.db.QueryRow(query, uhid).Scan(
		&patient.ID, &patient.UHID, &patient.FirstName, &patient.LastName,
		&patient.DateOfBirth, &patient.Gender, &patient.BloodGroup,
		&patient.MaritalStatus, &patient.MobileNumber, &patient.Email,
		&patient.AadhaarNumber, &patient.PANNumber, &patient.ABHAID,
		&patient.IsActive, &patient.CreatedAt, &patient.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get patient by UHID: %w", err)
	}

	return &patient, nil
}

// SearchPatients searches for patients based on criteria
func (s *PatientService) SearchPatients(criteria *PatientSearchCriteria) ([]*models.Patient, int, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}
	placeholderCount := 0

	if criteria.Query != "" {
		placeholderCount++
		conditions = append(conditions, fmt.Sprintf("(first_name ILIKE $%d OR last_name ILIKE $%d OR uhid ILIKE $%d)", 
			placeholderCount, placeholderCount+1, placeholderCount+2))
		query := "%" + criteria.Query + "%"
		args = append(args, query, query, query)
		placeholderCount += 2
	}

	if criteria.FirstName != "" {
		placeholderCount++
		conditions = append(conditions, fmt.Sprintf("first_name ILIKE $%d", placeholderCount))
		args = append(args, "%"+criteria.FirstName+"%")
	}

	if criteria.LastName != "" {
		placeholderCount++
		conditions = append(conditions, fmt.Sprintf("last_name ILIKE $%d", placeholderCount))
		args = append(args, "%"+criteria.LastName+"%")
	}

	if criteria.MobileNumber != "" {
		placeholderCount++
		conditions = append(conditions, fmt.Sprintf("mobile_number = $%d", placeholderCount))
		args = append(args, criteria.MobileNumber)
	}

	if criteria.AadhaarNumber != "" {
		placeholderCount++
		conditions = append(conditions, fmt.Sprintf("aadhaar_number = $%d", placeholderCount))
		args = append(args, criteria.AadhaarNumber)
	}

	if criteria.UHID != "" {
		placeholderCount++
		conditions = append(conditions, fmt.Sprintf("uhid = $%d", placeholderCount))
		args = append(args, criteria.UHID)
	}

	// Add status condition
	conditions = append(conditions, "deleted_at IS NULL")

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total records
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM patients %s", whereClause)
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count patients: %w", err)
	}

	// Get paginated results
	limit := criteria.Limit
	if limit <= 0 {
		limit = 10
	}
	offset := (criteria.Page - 1) * limit

	placeholderCount++
	limitPlaceholder := placeholderCount
	placeholderCount++
	offsetPlaceholder := placeholderCount

	query := fmt.Sprintf(`
		SELECT id, uhid, first_name, last_name, date_of_birth, gender, blood_group,
		       marital_status, mobile_number, email, aadhaar_number, pan_number,
		       abha_id, is_active, created_at, updated_at
		FROM patients %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, limitPlaceholder, offsetPlaceholder)

	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search patients: %w", err)
	}
	defer rows.Close()

	var patients []*models.Patient
	for rows.Next() {
		var patient models.Patient
		err := rows.Scan(
			&patient.ID, &patient.UHID, &patient.FirstName, &patient.LastName,
			&patient.DateOfBirth, &patient.Gender, &patient.BloodGroup,
			&patient.MaritalStatus, &patient.MobileNumber, &patient.Email,
			&patient.AadhaarNumber, &patient.PANNumber, &patient.ABHAID,
			&patient.IsActive, &patient.CreatedAt, &patient.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan patient: %w", err)
		}
		patients = append(patients, &patient)
	}

	return patients, total, nil
}

// UpdatePatient updates patient information
func (s *PatientService) UpdatePatient(patient *models.Patient) error {
	patient.UpdatedAt = time.Now()

		query := `
		UPDATE patients SET 
			first_name = $1, last_name = $2, date_of_birth = $3, gender = $4, 
			blood_group = $5, marital_status = $6, mobile_number = $7, email = $8, 
			aadhaar_number = $9, pan_number = $10, abha_id = $11, updated_at = $12
		WHERE id = $13 AND deleted_at IS NULL
	`

	result, err := s.db.Exec(query,
		patient.FirstName, patient.LastName, patient.DateOfBirth, patient.Gender,
		patient.BloodGroup, patient.MaritalStatus, patient.MobileNumber, patient.Email,
		patient.AadhaarNumber, patient.PANNumber, patient.ABHAID, patient.UpdatedAt,
		patient.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update patient: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// DeletePatient soft deletes a patient
func (s *PatientService) DeletePatient(id uuid.UUID) error {
	query := `UPDATE patients SET deleted_at = $1, updated_at = $2 WHERE id = $3`

	result, err := s.db.Exec(query, time.Now(), time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to delete patient: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// AddPatientAddress adds an address for a patient
func (s *PatientService) AddPatientAddress(patientID uuid.UUID, address *models.PatientAddress) error {
	address.ID = uuid.New()
	address.PatientID = patientID
	address.CreatedAt = time.Now()
	address.UpdatedAt = time.Now()

	query := `
		INSERT INTO patient_addresses (
			id, patient_id, address_type, address_line1, address_line2, city, state,
			district, pin_code, country, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := s.db.Exec(query,
		address.ID, address.PatientID, address.AddressType, address.AddressLine1,
		address.AddressLine2, address.City, address.State, address.District,
		address.PINCode, address.Country, address.CreatedAt, address.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to add patient address: %w", err)
	}

	return nil
}

// GetPatientAddresses retrieves addresses for a patient
func (s *PatientService) GetPatientAddresses(patientID uuid.UUID) ([]*models.PatientAddress, error) {
	query := `
		SELECT id, patient_id, address_type, address_line1, address_line2, city, state,
		       district, pin_code, country, created_at, updated_at
		FROM patient_addresses WHERE patient_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query, patientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get patient addresses: %w", err)
	}
	defer rows.Close()

	var addresses []*models.PatientAddress
	for rows.Next() {
		var address models.PatientAddress
		err := rows.Scan(
			&address.ID, &address.PatientID, &address.AddressType, &address.AddressLine1,
			&address.AddressLine2, &address.City, &address.State, &address.District,
			&address.PINCode, &address.Country, &address.CreatedAt, &address.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan address: %w", err)
		}
		addresses = append(addresses, &address)
	}

	return addresses, nil
}

// AddPatientAllergy adds an allergy for a patient
func (s *PatientService) AddPatientAllergy(patientID uuid.UUID, allergy *models.PatientAllergy) error {
	allergy.ID = uuid.New()
	allergy.PatientID = patientID
	allergy.CreatedAt = time.Now()
	allergy.UpdatedAt = time.Now()

	query := `
		INSERT INTO patient_allergies (
			id, patient_id, allergy_name, severity, reaction, notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := s.db.Exec(query,
		allergy.ID, allergy.PatientID, allergy.AllergyName, allergy.Severity,
		allergy.Reaction, allergy.Notes, allergy.CreatedAt, allergy.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to add patient allergy: %w", err)
	}

	return nil
}

// GetPatientAllergies retrieves allergies for a patient
func (s *PatientService) GetPatientAllergies(patientID uuid.UUID) ([]*models.PatientAllergy, error) {
	query := `
		SELECT id, patient_id, allergy_name, severity, reaction, notes, created_at, updated_at
		FROM patient_allergies WHERE patient_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query, patientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get patient allergies: %w", err)
	}
	defer rows.Close()

	var allergies []*models.PatientAllergy
	for rows.Next() {
		var allergy models.PatientAllergy
		err := rows.Scan(
			&allergy.ID, &allergy.PatientID, &allergy.AllergyName, &allergy.Severity,
			&allergy.Reaction, &allergy.Notes, &allergy.CreatedAt, &allergy.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan allergy: %w", err)
		}
		allergies = append(allergies, &allergy)
	}

	return allergies, nil
}

// AddInsurancePolicy adds an insurance policy for a patient
func (s *PatientService) AddInsurancePolicy(patientID uuid.UUID, policy *models.InsurancePolicy) error {
	policy.ID = uuid.New()
	policy.PatientID = patientID
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	query := `
		INSERT INTO insurance_policies (
			id, patient_id, policy_number, policy_type, insurance_provider, 
			start_date, end_date, policy_holder_name, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := s.db.Exec(query,
		policy.ID, policy.PatientID, policy.PolicyNumber, policy.PolicyType,
		policy.InsuranceProvider, policy.StartDate, policy.EndDate,
		policy.PolicyHolderName, policy.CreatedAt, policy.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to add insurance policy: %w", err)
	}

	return nil
}

// GetPatientInsurancePolicies retrieves insurance policies for a patient
func (s *PatientService) GetPatientInsurancePolicies(patientID uuid.UUID) ([]*models.InsurancePolicy, error) {
	query := `
		SELECT id, patient_id, policy_number, policy_type, insurance_provider,
		       start_date, end_date, policy_holder_name, created_at, updated_at
		FROM insurance_policies WHERE patient_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query, patientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get insurance policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.InsurancePolicy
	for rows.Next() {
		var policy models.InsurancePolicy
		err := rows.Scan(
			&policy.ID, &policy.PatientID, &policy.PolicyNumber, &policy.PolicyType,
			&policy.InsuranceProvider, &policy.StartDate, &policy.EndDate,
			&policy.PolicyHolderName, &policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan insurance policy: %w", err)
		}
		policies = append(policies, &policy)
	}

	return policies, nil
}

// RegisterBiometricData registers biometric data for a patient
func (s *PatientService) RegisterBiometricData(patientID uuid.UUID, biometricData *models.BiometricData) error {
	biometricData.ID = uuid.New()
	biometricData.PatientID = patientID
	biometricData.CreatedAt = time.Now()
	biometricData.UpdatedAt = time.Now()

	query := `
		INSERT INTO biometric_data (
			id, patient_id, quality_score, device_type, device_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.db.Exec(query,
		biometricData.ID, biometricData.PatientID, biometricData.QualityScore,
		biometricData.DeviceType, biometricData.DeviceID, biometricData.CreatedAt,
		biometricData.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to register biometric data: %w", err)
	}

	return nil
}

// SearchByBiometric searches for patients using biometric data
func (s *PatientService) SearchByBiometric(biometricData *models.BiometricData) ([]*models.Patient, error) {
	// This is a simplified implementation
	// In a real system, you would use specialized biometric matching algorithms
	query := `
		SELECT p.id, p.uhid, p.first_name, p.last_name, p.date_of_birth, p.gender,
		       p.blood_group, p.marital_status, p.mobile_number, p.email,
		       p.aadhaar_number, p.pan_number, p.abha_id, p.is_active, p.created_at, p.updated_at
		FROM patients p
		JOIN biometric_data b ON p.id = b.patient_id
		WHERE p.deleted_at IS NULL
		ORDER BY b.quality_score DESC
		LIMIT 10
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to search by biometric: %w", err)
	}
	defer rows.Close()

	var patients []*models.Patient
	for rows.Next() {
		var patient models.Patient
		err := rows.Scan(
			&patient.ID, &patient.UHID, &patient.FirstName, &patient.LastName,
			&patient.DateOfBirth, &patient.Gender, &patient.BloodGroup,
			&patient.MaritalStatus, &patient.MobileNumber, &patient.Email,
			&patient.AadhaarNumber, &patient.PANNumber, &patient.ABHAID,
			&patient.IsActive, &patient.CreatedAt, &patient.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan patient: %w", err)
		}
		patients = append(patients, &patient)
	}

	return patients, nil
}

// CheckDuplicatePatient checks for potential duplicate patients
func (s *PatientService) CheckDuplicatePatient(patient *models.Patient) ([]*models.Patient, error) {
	// Check for mobile number duplicates first (most common case)
	if patient.MobileNumber != "" {
		mobileQuery := `
			SELECT id, uhid, first_name, last_name, date_of_birth, gender, blood_group,
			       marital_status, mobile_number, email, aadhaar_number, pan_number,
			       abha_id, is_active, created_at, updated_at
			FROM patients
			WHERE deleted_at IS NULL AND mobile_number = $1
			LIMIT 5
		`
		
		rows, err := s.db.Query(mobileQuery, patient.MobileNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to check mobile duplicates: %w", err)
		}
		defer rows.Close()

		var duplicates []*models.Patient
		for rows.Next() {
			var duplicate models.Patient
			err := rows.Scan(
				&duplicate.ID, &duplicate.UHID, &duplicate.FirstName, &duplicate.LastName,
				&duplicate.DateOfBirth, &duplicate.Gender, &duplicate.BloodGroup,
				&duplicate.MaritalStatus, &duplicate.MobileNumber, &duplicate.Email,
				&duplicate.AadhaarNumber, &duplicate.PANNumber, &duplicate.ABHAID,
				&duplicate.IsActive, &duplicate.CreatedAt, &duplicate.UpdatedAt,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan duplicate: %w", err)
			}
			duplicates = append(duplicates, &duplicate)
		}
		
		if len(duplicates) > 0 {
			return duplicates, nil
		}
	}

	// Check for Aadhaar number duplicates
	if patient.AadhaarNumber != nil && *patient.AadhaarNumber != "" {
		aadhaarQuery := `
			SELECT id, uhid, first_name, last_name, date_of_birth, gender, blood_group,
			       marital_status, mobile_number, email, aadhaar_number, pan_number,
			       abha_id, is_active, created_at, updated_at
			FROM patients
			WHERE deleted_at IS NULL AND aadhaar_number = $1
			LIMIT 5
		`
		
		rows, err := s.db.Query(aadhaarQuery, *patient.AadhaarNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to check aadhaar duplicates: %w", err)
		}
		defer rows.Close()

		var duplicates []*models.Patient
		for rows.Next() {
			var duplicate models.Patient
			err := rows.Scan(
				&duplicate.ID, &duplicate.UHID, &duplicate.FirstName, &duplicate.LastName,
				&duplicate.DateOfBirth, &duplicate.Gender, &duplicate.BloodGroup,
				&duplicate.MaritalStatus, &duplicate.MobileNumber, &duplicate.Email,
				&duplicate.AadhaarNumber, &duplicate.PANNumber, &duplicate.ABHAID,
				&duplicate.IsActive, &duplicate.CreatedAt, &duplicate.UpdatedAt,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan duplicate: %w", err)
			}
			duplicates = append(duplicates, &duplicate)
		}
		
		if len(duplicates) > 0 {
			return duplicates, nil
		}
	}

	// Check for name + date of birth duplicates (potential same person)
	if patient.FirstName != "" && patient.LastName != nil && *patient.LastName != "" && patient.DateOfBirth != nil {
		nameQuery := `
			SELECT id, uhid, first_name, last_name, date_of_birth, gender, blood_group,
			       marital_status, mobile_number, email, aadhaar_number, pan_number,
			       abha_id, is_active, created_at, updated_at
			FROM patients
			WHERE deleted_at IS NULL AND 
			      LOWER(first_name) = LOWER($1) AND 
			      LOWER(last_name) = LOWER($2) AND 
			      date_of_birth = $3
			LIMIT 5
		`
		
		rows, err := s.db.Query(nameQuery, patient.FirstName, *patient.LastName, patient.DateOfBirth)
		if err != nil {
			return nil, fmt.Errorf("failed to check name duplicates: %w", err)
		}
		defer rows.Close()

		var duplicates []*models.Patient
		for rows.Next() {
			var duplicate models.Patient
			err := rows.Scan(
				&duplicate.ID, &duplicate.UHID, &duplicate.FirstName, &duplicate.LastName,
				&duplicate.DateOfBirth, &duplicate.Gender, &duplicate.BloodGroup,
				&duplicate.MaritalStatus, &duplicate.MobileNumber, &duplicate.Email,
				&duplicate.AadhaarNumber, &duplicate.PANNumber, &duplicate.ABHAID,
				&duplicate.IsActive, &duplicate.CreatedAt, &duplicate.UpdatedAt,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to scan duplicate: %w", err)
			}
			duplicates = append(duplicates, &duplicate)
		}
		
		if len(duplicates) > 0 {
			return duplicates, nil
		}
	}

	return nil, nil
}

// GenerateUHID generates a unique health identifier
func (s *PatientService) GenerateUHID(patient *models.Patient) (string, error) {
	ctx := context.Background()
	
	// Simple UHID generation based on timestamp and patient info
	// In a real system, this would be more sophisticated
	year := time.Now().Year()
	
	// Format: HMIS-YYYY-XXXXX (where XXXXX is a sequential number)
	query := `
		SELECT COUNT(*) + 1 FROM patients 
		WHERE EXTRACT(YEAR FROM created_at) = $1 AND deleted_at IS NULL
	`
	
	var sequence int
	err := s.db.QueryRowContext(ctx, query, year).Scan(&sequence)
	if err != nil {
		// If query fails, use a fallback method
		sequence = int(time.Now().Unix() % 100000)
	}
	
	uhid := fmt.Sprintf("HMIS-%d-%05d", year, sequence)
	
	// Ensure UHID is unique by checking if it already exists
	checkQuery := `SELECT COUNT(*) FROM patients WHERE uhid = $1 AND deleted_at IS NULL`
	var count int
	err = s.db.QueryRowContext(ctx, checkQuery, uhid).Scan(&count)
	if err != nil {
		return "", fmt.Errorf("failed to check UHID uniqueness: %w", err)
	}
	
	// If UHID already exists, append a random suffix
	if count > 0 {
		randomSuffix := fmt.Sprintf("%03d", int(time.Now().UnixNano()%1000))
		uhid = fmt.Sprintf("HMIS-%d-%05d-%s", year, sequence, randomSuffix)
	}
	
	return uhid, nil
}

// GetPatientStatistics returns patient statistics for dashboard
func (s *PatientService) GetPatientStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Total patients
	var totalPatients int
	err := s.db.QueryRow("SELECT COUNT(*) FROM patients WHERE deleted_at IS NULL").Scan(&totalPatients)
	if err != nil {
		return nil, fmt.Errorf("failed to get total patients: %w", err)
	}
	stats["totalPatients"] = totalPatients
	
	// Patients registered today
	var newRegistrationsToday int
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM patients 
		WHERE DATE(created_at) = CURRENT_DATE AND deleted_at IS NULL
	`).Scan(&newRegistrationsToday)
	if err != nil {
		return nil, fmt.Errorf("failed to get today's patients: %w", err)
	}
	stats["newRegistrationsToday"] = newRegistrationsToday
	
	// Patients by gender
	var maleCount, femaleCount, otherCount int
	err = s.db.QueryRow(`
		SELECT 
			COUNT(CASE WHEN gender = 'male' THEN 1 END),
			COUNT(CASE WHEN gender = 'female' THEN 1 END),
			COUNT(CASE WHEN gender NOT IN ('male', 'female') THEN 1 END)
		FROM patients WHERE deleted_at IS NULL
	`).Scan(&maleCount, &femaleCount, &otherCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get gender stats: %w", err)
	}
	
	stats["patientsByGender"] = map[string]interface{}{
		"male":   maleCount,
		"female": femaleCount,
		"other":  otherCount,
	}
	
	// Patients by age group
	var age0_18, age19_30, age31_50, age51_70, age70_plus int
	err = s.db.QueryRow(`
		SELECT 
			COUNT(CASE WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 0 AND 18 THEN 1 END),
			COUNT(CASE WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 19 AND 30 THEN 1 END),
			COUNT(CASE WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 31 AND 50 THEN 1 END),
			COUNT(CASE WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 51 AND 70 THEN 1 END),
			COUNT(CASE WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) > 70 THEN 1 END)
		FROM patients WHERE deleted_at IS NULL AND date_of_birth IS NOT NULL
	`).Scan(&age0_18, &age19_30, &age31_50, &age51_70, &age70_plus)
	if err != nil {
		return nil, fmt.Errorf("failed to get age group stats: %w", err)
	}
	
	stats["patientsByAgeGroup"] = map[string]interface{}{
		"0-18":  age0_18,
		"19-30": age19_30,
		"31-50": age31_50,
		"51-70": age51_70,
		"70+":   age70_plus,
	}
	
	// Patients by blood group
	rows, err := s.db.Query(`
		SELECT blood_group, COUNT(*) 
		FROM patients 
		WHERE deleted_at IS NULL AND blood_group IS NOT NULL AND blood_group != ''
		GROUP BY blood_group
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get blood group stats: %w", err)
	}
	defer rows.Close()
	
	patientsByBloodGroup := make(map[string]interface{})
	for rows.Next() {
		var bloodGroup string
		var count int
		if err := rows.Scan(&bloodGroup, &count); err != nil {
			return nil, fmt.Errorf("failed to scan blood group stats: %w", err)
		}
		patientsByBloodGroup[bloodGroup] = count
	}
	stats["patientsByBloodGroup"] = patientsByBloodGroup
	
	// Registrations by source
	var walkInCount, referralCount, onlineCount int
	err = s.db.QueryRow(`
		SELECT 
			COUNT(CASE WHEN registration_source = 'walk_in' THEN 1 END),
			COUNT(CASE WHEN registration_source = 'referral' THEN 1 END),
			COUNT(CASE WHEN registration_source = 'online' THEN 1 END)
		FROM patients WHERE deleted_at IS NULL
	`).Scan(&walkInCount, &referralCount, &onlineCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get registration source stats: %w", err)
	}
	
	stats["registrationsBySource"] = map[string]interface{}{
		"walk_in":  walkInCount,
		"referral": referralCount,
		"online":   onlineCount,
	}
	
	return stats, nil
}

// ValidateAadhaar validates Aadhaar number format
func (s *PatientService) ValidateAadhaar(aadhaarNumber string) (bool, error) {
	// Simple validation - 12 digits
	if len(aadhaarNumber) != 12 {
		return false, nil
	}
	
	for _, char := range aadhaarNumber {
		if char < '0' || char > '9' {
			return false, nil
		}
	}
	
	return true, nil
}

// ValidatePAN validates PAN number format
func (s *PatientService) ValidatePAN(panNumber string) (bool, error) {
	// Simple validation - 10 characters, alphanumeric
	if len(panNumber) != 10 {
		return false, nil
	}
	
	return true, nil
}

// ValidateMobile validates mobile number format
func (s *PatientService) ValidateMobile(mobileNumber string) (bool, error) {
	// Simple validation - 10 digits starting with 6-9
	if len(mobileNumber) != 10 {
		return false, nil
	}
	
	if mobileNumber[0] < '6' || mobileNumber[0] > '9' {
		return false, nil
	}
	
	for _, char := range mobileNumber {
		if char < '0' || char > '9' {
			return false, nil
		}
	}
	
	return true, nil
} 