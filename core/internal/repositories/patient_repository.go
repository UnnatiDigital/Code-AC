package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bmad-method/hmis-core/internal/models"
)

// PatientRepository handles database operations for patients
type PatientRepository struct {
	db *sql.DB
}

// NewPatientRepository creates a new patient repository
func NewPatientRepository(db *sql.DB) *PatientRepository {
	return &PatientRepository{db: db}
}

// Create creates a new patient
func (r *PatientRepository) Create(ctx context.Context, patient *models.Patient) error {
	// Call BeforeCreate to generate UHID and set timestamps
	if err := patient.BeforeCreate(); err != nil {
		return fmt.Errorf("failed to prepare patient: %w", err)
	}

	// Ensure UHID is generated
	if patient.UHID == "" {
		patient.UHID = patient.GenerateUHID()
	}

	query := `
		INSERT INTO patients (
			id, uhid, first_name, last_name, date_of_birth, gender, blood_group, 
			marital_status, mobile_number, email, aadhaar_number, pan_number, 
			abha_id, is_active, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		) RETURNING id, uhid, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query,
		patient.ID, patient.UHID, patient.FirstName, patient.LastName,
		patient.DateOfBirth, patient.Gender, patient.BloodGroup,
		patient.MaritalStatus, patient.MobileNumber, patient.Email,
		patient.AadhaarNumber, patient.PANNumber, patient.ABHAID,
		patient.IsActive, patient.CreatedAt, patient.UpdatedAt,
	).Scan(&patient.ID, &patient.UHID, &patient.CreatedAt, &patient.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create patient: %w", err)
	}

	return nil
}

// GetByID retrieves a patient by ID
func (r *PatientRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Patient, error) {
	query := `
		SELECT id, uhid, first_name, last_name, middle_name, date_of_birth, age, gender,
			blood_group, rh_factor, mobile_number, email, emergency_contact,
			emergency_contact_name, emergency_contact_rel, aadhaar_number, pan_number,
			abha_id, ration_card_number, religion, caste, education, occupation,
			marital_status, nationality, mother_tongue, medical_history, family_history,
			biometric_consent, data_sharing_consent, consent_timestamp, family_id,
			family_role, registration_type, registration_source, referred_by,
			is_active, is_verified, verification_method, verification_timestamp,
			created_at, updated_at, created_by, updated_by
		FROM patients
		WHERE id = $1 AND deleted_at IS NULL`

	patient := &models.Patient{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&patient.ID, &patient.UHID, &patient.FirstName, &patient.LastName,
		&patient.MiddleName, &patient.DateOfBirth, &patient.Age, &patient.Gender,
		&patient.BloodGroup, &patient.RhFactor, &patient.MobileNumber, &patient.Email,
		&patient.EmergencyContact, &patient.EmergencyContactName, &patient.EmergencyContactRel,
		&patient.AadhaarNumber, &patient.PANNumber, &patient.ABHAID, &patient.RationCardNumber,
		&patient.Religion, &patient.Caste, &patient.Education, &patient.Occupation,
		&patient.MaritalStatus, &patient.Nationality, &patient.MotherTongue,
		&patient.MedicalHistory, &patient.FamilyHistory, &patient.BiometricConsent,
		&patient.DataSharingConsent, &patient.ConsentTimestamp, &patient.FamilyID,
		&patient.FamilyRole, &patient.RegistrationType, &patient.RegistrationSource,
		&patient.ReferredBy, &patient.IsActive, &patient.IsVerified,
		&patient.VerificationMethod, &patient.VerificationTimestamp, &patient.CreatedAt,
		&patient.UpdatedAt, &patient.CreatedBy, &patient.UpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("patient not found")
		}
		return nil, fmt.Errorf("failed to get patient: %w", err)
	}

	return patient, nil
}

// GetByUHID retrieves a patient by UHID
func (r *PatientRepository) GetByUHID(ctx context.Context, uhid string) (*models.Patient, error) {
	query := `
		SELECT id, uhid, first_name, last_name, middle_name, date_of_birth, age, gender,
			blood_group, rh_factor, mobile_number, email, emergency_contact,
			emergency_contact_name, emergency_contact_rel, aadhaar_number, pan_number,
			abha_id, ration_card_number, religion, caste, education, occupation,
			marital_status, nationality, mother_tongue, medical_history, family_history,
			biometric_consent, data_sharing_consent, consent_timestamp, family_id,
			family_role, registration_type, registration_source, referred_by,
			is_active, is_verified, verification_method, verification_timestamp,
			created_at, updated_at, created_by, updated_by
		FROM patients
		WHERE uhid = $1 AND deleted_at IS NULL`

	patient := &models.Patient{}
	err := r.db.QueryRowContext(ctx, query, uhid).Scan(
		&patient.ID, &patient.UHID, &patient.FirstName, &patient.LastName,
		&patient.MiddleName, &patient.DateOfBirth, &patient.Age, &patient.Gender,
		&patient.BloodGroup, &patient.RhFactor, &patient.MobileNumber, &patient.Email,
		&patient.EmergencyContact, &patient.EmergencyContactName, &patient.EmergencyContactRel,
		&patient.AadhaarNumber, &patient.PANNumber, &patient.ABHAID, &patient.RationCardNumber,
		&patient.Religion, &patient.Caste, &patient.Education, &patient.Occupation,
		&patient.MaritalStatus, &patient.Nationality, &patient.MotherTongue,
		&patient.MedicalHistory, &patient.FamilyHistory, &patient.BiometricConsent,
		&patient.DataSharingConsent, &patient.ConsentTimestamp, &patient.FamilyID,
		&patient.FamilyRole, &patient.RegistrationType, &patient.RegistrationSource,
		&patient.ReferredBy, &patient.IsActive, &patient.IsVerified,
		&patient.VerificationMethod, &patient.VerificationTimestamp, &patient.CreatedAt,
		&patient.UpdatedAt, &patient.CreatedBy, &patient.UpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("patient not found")
		}
		return nil, fmt.Errorf("failed to get patient: %w", err)
	}

	return patient, nil
}

// GetByMobileNumber retrieves a patient by mobile number
func (r *PatientRepository) GetByMobileNumber(ctx context.Context, mobileNumber string) (*models.Patient, error) {
	query := `
		SELECT id, uhid, first_name, last_name, middle_name, date_of_birth, age, gender,
			blood_group, rh_factor, mobile_number, email, emergency_contact,
			emergency_contact_name, emergency_contact_rel, aadhaar_number, pan_number,
			abha_id, ration_card_number, religion, caste, education, occupation,
			marital_status, nationality, mother_tongue, medical_history, family_history,
			biometric_consent, data_sharing_consent, consent_timestamp, family_id,
			family_role, registration_type, registration_source, referred_by,
			is_active, is_verified, verification_method, verification_timestamp,
			created_at, updated_at, created_by, updated_by
		FROM patients
		WHERE mobile_number = $1 AND deleted_at IS NULL`

	patient := &models.Patient{}
	err := r.db.QueryRowContext(ctx, query, mobileNumber).Scan(
		&patient.ID, &patient.UHID, &patient.FirstName, &patient.LastName,
		&patient.MiddleName, &patient.DateOfBirth, &patient.Age, &patient.Gender,
		&patient.BloodGroup, &patient.RhFactor, &patient.MobileNumber, &patient.Email,
		&patient.EmergencyContact, &patient.EmergencyContactName, &patient.EmergencyContactRel,
		&patient.AadhaarNumber, &patient.PANNumber, &patient.ABHAID, &patient.RationCardNumber,
		&patient.Religion, &patient.Caste, &patient.Education, &patient.Occupation,
		&patient.MaritalStatus, &patient.Nationality, &patient.MotherTongue,
		&patient.MedicalHistory, &patient.FamilyHistory, &patient.BiometricConsent,
		&patient.DataSharingConsent, &patient.ConsentTimestamp, &patient.FamilyID,
		&patient.FamilyRole, &patient.RegistrationType, &patient.RegistrationSource,
		&patient.ReferredBy, &patient.IsActive, &patient.IsVerified,
		&patient.VerificationMethod, &patient.VerificationTimestamp, &patient.CreatedAt,
		&patient.UpdatedAt, &patient.CreatedBy, &patient.UpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("patient not found")
		}
		return nil, fmt.Errorf("failed to get patient: %w", err)
	}

	return patient, nil
}

// Search searches for patients based on various criteria
func (r *PatientRepository) Search(ctx context.Context, criteria *PatientSearchCriteria) ([]*models.Patient, error) {
	query := `
		SELECT id, uhid, first_name, last_name, middle_name, date_of_birth, age, gender,
			blood_group, rh_factor, mobile_number, email, emergency_contact,
			emergency_contact_name, emergency_contact_rel, aadhaar_number, pan_number,
			abha_id, ration_card_number, religion, caste, education, occupation,
			marital_status, nationality, mother_tongue, medical_history, family_history,
			biometric_consent, data_sharing_consent, consent_timestamp, family_id,
			family_role, registration_type, registration_source, referred_by,
			is_active, is_verified, verification_method, verification_timestamp,
			created_at, updated_at, created_by, updated_by
		FROM patients
		WHERE deleted_at IS NULL`

	var conditions []string
	var args []interface{}
	argIndex := 1

	// Add search conditions
	if criteria.Name != "" {
		conditions = append(conditions, fmt.Sprintf("(first_name ILIKE $%d OR last_name ILIKE $%d OR middle_name ILIKE $%d)", 
			argIndex, argIndex, argIndex))
		args = append(args, "%"+criteria.Name+"%")
		argIndex++
	}

	if criteria.MobileNumber != "" {
		conditions = append(conditions, fmt.Sprintf("mobile_number = $%d", argIndex))
		args = append(args, criteria.MobileNumber)
		argIndex++
	}

	if criteria.AadhaarNumber != "" {
		conditions = append(conditions, fmt.Sprintf("aadhaar_number = $%d", argIndex))
		args = append(args, criteria.AadhaarNumber)
		argIndex++
	}

	if criteria.ABHAID != "" {
		conditions = append(conditions, fmt.Sprintf("abha_id = $%d", argIndex))
		args = append(args, criteria.ABHAID)
		argIndex++
	}

	if criteria.Gender != "" {
		conditions = append(conditions, fmt.Sprintf("gender = $%d", argIndex))
		args = append(args, criteria.Gender)
		argIndex++
	}

	if criteria.RegistrationType != "" {
		conditions = append(conditions, fmt.Sprintf("registration_type = $%d", argIndex))
		args = append(args, criteria.RegistrationType)
		argIndex++
	}

	if criteria.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *criteria.IsActive)
		argIndex++
	}

	if criteria.CreatedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIndex))
		args = append(args, *criteria.CreatedAfter)
		argIndex++
	}

	if criteria.CreatedBefore != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIndex))
		args = append(args, *criteria.CreatedBefore)
		argIndex++
	}

	// Add WHERE clause if conditions exist
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}

	// Add ORDER BY
	query += " ORDER BY created_at DESC"

	// Add LIMIT and OFFSET
	if criteria.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, criteria.Limit)
		argIndex++
	}

	if criteria.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, criteria.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to search patients: %w", err)
	}
	defer rows.Close()

	var patients []*models.Patient
	for rows.Next() {
		patient := &models.Patient{}
		err := rows.Scan(
			&patient.ID, &patient.UHID, &patient.FirstName, &patient.LastName,
			&patient.MiddleName, &patient.DateOfBirth, &patient.Age, &patient.Gender,
			&patient.BloodGroup, &patient.RhFactor, &patient.MobileNumber, &patient.Email,
			&patient.EmergencyContact, &patient.EmergencyContactName, &patient.EmergencyContactRel,
			&patient.AadhaarNumber, &patient.PANNumber, &patient.ABHAID, &patient.RationCardNumber,
			&patient.Religion, &patient.Caste, &patient.Education, &patient.Occupation,
			&patient.MaritalStatus, &patient.Nationality, &patient.MotherTongue,
			&patient.MedicalHistory, &patient.FamilyHistory, &patient.BiometricConsent,
			&patient.DataSharingConsent, &patient.ConsentTimestamp, &patient.FamilyID,
			&patient.FamilyRole, &patient.RegistrationType, &patient.RegistrationSource,
			&patient.ReferredBy, &patient.IsActive, &patient.IsVerified,
			&patient.VerificationMethod, &patient.VerificationTimestamp, &patient.CreatedAt,
			&patient.UpdatedAt, &patient.CreatedBy, &patient.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan patient: %w", err)
		}
		patients = append(patients, patient)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating patients: %w", err)
	}

	return patients, nil
}

// Update updates a patient
func (r *PatientRepository) Update(ctx context.Context, patient *models.Patient) error {
	query := `
		UPDATE patients SET
			first_name = $1, last_name = $2, middle_name = $3, date_of_birth = $4,
			age = $5, gender = $6, blood_group = $7, rh_factor = $8, mobile_number = $9,
			email = $10, emergency_contact = $11, emergency_contact_name = $12,
			emergency_contact_rel = $13, aadhaar_number = $14, pan_number = $15,
			abha_id = $16, ration_card_number = $17, religion = $18, caste = $19,
			education = $20, occupation = $21, marital_status = $22, nationality = $23,
			mother_tongue = $24, medical_history = $25, family_history = $26,
			biometric_consent = $27, data_sharing_consent = $28, consent_timestamp = $29,
			family_id = $30, family_role = $31, registration_type = $32,
			registration_source = $33, referred_by = $34, is_active = $35,
			is_verified = $36, verification_method = $37, verification_timestamp = $38,
			updated_by = $39, updated_at = CURRENT_TIMESTAMP
		WHERE id = $40 AND deleted_at IS NULL`

	if err := patient.BeforeUpdate(); err != nil {
		return fmt.Errorf("failed to prepare patient update: %w", err)
	}

	result, err := r.db.ExecContext(ctx, query,
		patient.FirstName, patient.LastName, patient.MiddleName, patient.DateOfBirth,
		patient.Age, patient.Gender, patient.BloodGroup, patient.RhFactor,
		patient.MobileNumber, patient.Email, patient.EmergencyContact,
		patient.EmergencyContactName, patient.EmergencyContactRel, patient.AadhaarNumber,
		patient.PANNumber, patient.ABHAID, patient.RationCardNumber, patient.Religion,
		patient.Caste, patient.Education, patient.Occupation, patient.MaritalStatus,
		patient.Nationality, patient.MotherTongue, patient.MedicalHistory,
		patient.FamilyHistory, patient.BiometricConsent, patient.DataSharingConsent,
		patient.ConsentTimestamp, patient.FamilyID, patient.FamilyRole,
		patient.RegistrationType, patient.RegistrationSource, patient.ReferredBy,
		patient.IsActive, patient.IsVerified, patient.VerificationMethod,
		patient.VerificationTimestamp, patient.UpdatedBy, patient.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update patient: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("patient not found or no changes made")
	}

	return nil
}

// Delete soft deletes a patient
func (r *PatientRepository) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `
		UPDATE patients 
		SET deleted_at = CURRENT_TIMESTAMP, updated_by = $1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, deletedBy, id)
	if err != nil {
		return fmt.Errorf("failed to delete patient: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("patient not found")
	}

	return nil
}

// CheckDuplicate checks for potential duplicate patients
func (r *PatientRepository) CheckDuplicate(ctx context.Context, patient *models.Patient) ([]*models.Patient, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	// Check by mobile number
	if patient.MobileNumber != "" {
		conditions = append(conditions, fmt.Sprintf("mobile_number = $%d", argIndex))
		args = append(args, patient.MobileNumber)
		argIndex++
	}

	// Check by Aadhaar number
	if patient.AadhaarNumber != nil && *patient.AadhaarNumber != "" {
		conditions = append(conditions, fmt.Sprintf("aadhaar_number = $%d", argIndex))
		args = append(args, *patient.AadhaarNumber)
		argIndex++
	}

	// Check by name and date of birth
	if patient.FirstName != "" && patient.DateOfBirth != nil {
		conditions = append(conditions, fmt.Sprintf("(first_name ILIKE $%d AND date_of_birth = $%d)", 
			argIndex, argIndex+1))
		args = append(args, patient.FirstName, *patient.DateOfBirth)
		argIndex += 2
	}

	if len(conditions) == 0 {
		return nil, nil
	}

	query := `
		SELECT id, uhid, first_name, last_name, middle_name, date_of_birth, age, gender,
			mobile_number, aadhaar_number, created_at
		FROM patients
		WHERE deleted_at IS NULL AND (` + strings.Join(conditions, " OR ") + ")"

	if patient.ID != uuid.Nil {
		query += fmt.Sprintf(" AND id != $%d", argIndex)
		args = append(args, patient.ID)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to check duplicates: %w", err)
	}
	defer rows.Close()

	var duplicates []*models.Patient
	for rows.Next() {
		duplicate := &models.Patient{}
		err := rows.Scan(
			&duplicate.ID, &duplicate.UHID, &duplicate.FirstName, &duplicate.LastName,
			&duplicate.MiddleName, &duplicate.DateOfBirth, &duplicate.Age, &duplicate.Gender,
			&duplicate.MobileNumber, &duplicate.AadhaarNumber, &duplicate.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan duplicate: %w", err)
		}
		duplicates = append(duplicates, duplicate)
	}

	return duplicates, nil
}

// PatientSearchCriteria defines search criteria for patients
type PatientSearchCriteria struct {
	Name             string     `json:"name"`
	MobileNumber     string     `json:"mobile_number"`
	AadhaarNumber    string     `json:"aadhaar_number"`
	ABHAID           string     `json:"abha_id"`
	Gender           string     `json:"gender"`
	RegistrationType string     `json:"registration_type"`
	IsActive         *bool      `json:"is_active"`
	CreatedAfter     *time.Time `json:"created_after"`
	CreatedBefore    *time.Time `json:"created_before"`
	Limit            int        `json:"limit"`
	Offset           int        `json:"offset"`
} 