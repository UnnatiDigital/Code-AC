package models

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BiometricData represents patient biometric information
type BiometricData struct {
	ID          uuid.UUID           `json:"id" db:"id"`
	PatientID   uuid.UUID           `json:"patient_id" db:"patient_id"`
	
	// Fingerprint Data
	Fingerprints []FingerprintData `json:"fingerprints,omitempty" db:"-"`
	
	// Facial Recognition Data
	FaceImage    *FaceImageData     `json:"face_image,omitempty" db:"-"`
	
	// Iris Data
	IrisData     []IrisData         `json:"iris_data,omitempty" db:"-"`
	
	// Quality and Compliance
	QualityScore *float64           `json:"quality_score" db:"quality_score"`
	NFIQScore    *float64           `json:"nfiq_score" db:"nfiq_score"`
	ICAOCompliant bool              `json:"icao_compliant" db:"icao_compliant"`
	LivenessCheck bool              `json:"liveness_check" db:"liveness_check"`
	
	// Device Information
	DeviceType   *string            `json:"device_type" db:"device_type"`
	DeviceID     *string            `json:"device_id" db:"device_id"`
	DeviceModel  *string            `json:"device_model" db:"device_model"`
	
	// Audit Fields
	CreatedAt    time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at" db:"updated_at"`
	CreatedBy    *uuid.UUID         `json:"created_by" db:"created_by"`
	UpdatedBy    *uuid.UUID         `json:"updated_by" db:"updated_by"`
}

// TableName returns the table name for the BiometricData model
func (BiometricData) TableName() string {
	return "biometric_data"
}

// BeforeCreate is called before creating new biometric data
func (bd *BiometricData) BeforeCreate() error {
	if bd.ID == uuid.Nil {
		bd.ID = uuid.New()
	}
	bd.CreatedAt = time.Now()
	bd.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating biometric data
func (bd *BiometricData) BeforeUpdate() error {
	bd.UpdatedAt = time.Now()
	return nil
}

// Validate validates the biometric data
func (bd *BiometricData) Validate() error {
	if bd.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	
	// At least one biometric modality should be present
	if len(bd.Fingerprints) == 0 && bd.FaceImage == nil && len(bd.IrisData) == 0 {
		return fmt.Errorf("at least one biometric modality is required")
	}
	
	// Validate fingerprints
	for _, fp := range bd.Fingerprints {
		if err := fp.Validate(); err != nil {
			return fmt.Errorf("fingerprint validation failed: %w", err)
		}
	}
	
	// Validate face image
	if bd.FaceImage != nil {
		if err := bd.FaceImage.Validate(); err != nil {
			return fmt.Errorf("face image validation failed: %w", err)
		}
	}
	
	// Validate iris data
	for _, iris := range bd.IrisData {
		if err := iris.Validate(); err != nil {
			return fmt.Errorf("iris data validation failed: %w", err)
		}
	}
	
	return nil
}

// HasFingerprints checks if biometric data has fingerprints
func (bd *BiometricData) HasFingerprints() bool {
	return len(bd.Fingerprints) > 0
}

// HasFaceImage checks if biometric data has face image
func (bd *BiometricData) HasFaceImage() bool {
	return bd.FaceImage != nil
}

// HasIrisData checks if biometric data has iris data
func (bd *BiometricData) HasIrisData() bool {
	return len(bd.IrisData) > 0
}

// GetQualityScore returns the overall quality score
func (bd *BiometricData) GetQualityScore() float64 {
	if bd.QualityScore != nil {
		return *bd.QualityScore
	}
	return 0.0
}

// IsHighQuality checks if biometric data meets quality standards
func (bd *BiometricData) IsHighQuality() bool {
	score := bd.GetQualityScore()
	return score >= 60.0 // NFIQ 2.0 standard
}

// FingerprintData represents individual fingerprint data
type FingerprintData struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	BiometricDataID uuid.UUID  `json:"biometric_data_id" db:"biometric_data_id"`
	FingerType      string     `json:"finger_type" db:"finger_type"` // "left_thumb", "right_thumb", etc.
	Template        []byte     `json:"template" db:"template"`
	Minutiae        []byte     `json:"minutiae" db:"minutiae"`
	QualityScore    float64    `json:"quality_score" db:"quality_score"`
	NFIQScore       float64    `json:"nfiq_score" db:"nfiq_score"`
	CaptureAttempts int        `json:"capture_attempts" db:"capture_attempts"`
	IsPreferred     bool       `json:"is_preferred" db:"is_preferred"`
	
	// Audit Fields
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// TableName returns the table name for the FingerprintData model
func (FingerprintData) TableName() string {
	return "fingerprint_data"
}

// BeforeCreate is called before creating new fingerprint data
func (fd *FingerprintData) BeforeCreate() error {
	if fd.ID == uuid.Nil {
		fd.ID = uuid.New()
	}
	fd.CreatedAt = time.Now()
	fd.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating fingerprint data
func (fd *FingerprintData) BeforeUpdate() error {
	fd.UpdatedAt = time.Now()
	return nil
}

// Validate validates the fingerprint data
func (fd *FingerprintData) Validate() error {
	if fd.BiometricDataID == uuid.Nil {
		return fmt.Errorf("biometric data ID is required")
	}
	
	if fd.FingerType == "" {
		return fmt.Errorf("finger type is required")
	}
	
	if !isValidFingerType(fd.FingerType) {
		return fmt.Errorf("invalid finger type")
	}
	
	if len(fd.Template) == 0 {
		return fmt.Errorf("fingerprint template is required")
	}
	
	if fd.QualityScore < 0 || fd.QualityScore > 100 {
		return fmt.Errorf("quality score must be between 0 and 100")
	}
	
	if fd.NFIQScore < 0 || fd.NFIQScore > 100 {
		return fmt.Errorf("NFIQ score must be between 0 and 100")
	}
	
	return nil
}

// GetTemplateBase64 returns the template as base64 string
func (fd *FingerprintData) GetTemplateBase64() string {
	return base64.StdEncoding.EncodeToString(fd.Template)
}

// GetMinutiaeBase64 returns the minutiae as base64 string
func (fd *FingerprintData) GetMinutiaeBase64() string {
	return base64.StdEncoding.EncodeToString(fd.Minutiae)
}

// FaceImageData represents facial recognition data
type FaceImageData struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	BiometricDataID uuid.UUID  `json:"biometric_data_id" db:"biometric_data_id"`
	ImageData       []byte     `json:"image_data" db:"image_data"`
	Template        []byte     `json:"template" db:"template"`
	QualityScore    float64    `json:"quality_score" db:"quality_score"`
	ICAOCompliant   bool       `json:"icao_compliant" db:"icao_compliant"`
	LivenessCheck   bool       `json:"liveness_check" db:"liveness_check"`
	FaceLandmarks   []byte     `json:"face_landmarks" db:"face_landmarks"`
	CaptureAngle    *string    `json:"capture_angle" db:"capture_angle"`
	
	// Audit Fields
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// TableName returns the table name for the FaceImageData model
func (FaceImageData) TableName() string {
	return "face_image_data"
}

// BeforeCreate is called before creating new face image data
func (fid *FaceImageData) BeforeCreate() error {
	if fid.ID == uuid.Nil {
		fid.ID = uuid.New()
	}
	fid.CreatedAt = time.Now()
	fid.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating face image data
func (fid *FaceImageData) BeforeUpdate() error {
	fid.UpdatedAt = time.Now()
	return nil
}

// Validate validates the face image data
func (fid *FaceImageData) Validate() error {
	if fid.BiometricDataID == uuid.Nil {
		return fmt.Errorf("biometric data ID is required")
	}
	
	if len(fid.ImageData) == 0 {
		return fmt.Errorf("face image data is required")
	}
	
	if len(fid.Template) == 0 {
		return fmt.Errorf("face template is required")
	}
	
	if fid.QualityScore < 0 || fid.QualityScore > 100 {
		return fmt.Errorf("quality score must be between 0 and 100")
	}
	
	return nil
}

// GetImageBase64 returns the image as base64 string
func (fid *FaceImageData) GetImageBase64() string {
	return base64.StdEncoding.EncodeToString(fid.ImageData)
}

// GetTemplateBase64 returns the template as base64 string
func (fid *FaceImageData) GetTemplateBase64() string {
	return base64.StdEncoding.EncodeToString(fid.Template)
}

// IrisData represents iris recognition data
type IrisData struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	BiometricDataID uuid.UUID  `json:"biometric_data_id" db:"biometric_data_id"`
	EyeType         string     `json:"eye_type" db:"eye_type"` // "left", "right"
	ImageData       []byte     `json:"image_data" db:"image_data"`
	Template        []byte     `json:"template" db:"template"`
	QualityScore    float64    `json:"quality_score" db:"quality_score"`
	IrisCode        []byte     `json:"iris_code" db:"iris_code"`
	
	// Audit Fields
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// TableName returns the table name for the IrisData model
func (IrisData) TableName() string {
	return "iris_data"
}

// BeforeCreate is called before creating new iris data
func (id *IrisData) BeforeCreate() error {
	if id.ID == uuid.Nil {
		id.ID = uuid.New()
	}
	id.CreatedAt = time.Now()
	id.UpdatedAt = time.Now()
	return nil
}

// BeforeUpdate is called before updating iris data
func (id *IrisData) BeforeUpdate() error {
	id.UpdatedAt = time.Now()
	return nil
}

// Validate validates the iris data
func (id *IrisData) Validate() error {
	if id.BiometricDataID == uuid.Nil {
		return fmt.Errorf("biometric data ID is required")
	}
	
	if id.EyeType == "" {
		return fmt.Errorf("eye type is required")
	}
	
	if !isValidEyeType(id.EyeType) {
		return fmt.Errorf("invalid eye type")
	}
	
	if len(id.ImageData) == 0 {
		return fmt.Errorf("iris image data is required")
	}
	
	if len(id.Template) == 0 {
		return fmt.Errorf("iris template is required")
	}
	
	if id.QualityScore < 0 || id.QualityScore > 100 {
		return fmt.Errorf("quality score must be between 0 and 100")
	}
	
	return nil
}

// GetImageBase64 returns the image as base64 string
func (id *IrisData) GetImageBase64() string {
	return base64.StdEncoding.EncodeToString(id.ImageData)
}

// GetTemplateBase64 returns the template as base64 string
func (id *IrisData) GetTemplateBase64() string {
	return base64.StdEncoding.EncodeToString(id.Template)
}

// Validation helper functions
func isValidFingerType(fingerType string) bool {
	validTypes := []string{
		"left_thumb", "left_index", "left_middle", "left_ring", "left_little",
		"right_thumb", "right_index", "right_middle", "right_ring", "right_little",
	}
	for _, valid := range validTypes {
		if fingerType == valid {
			return true
		}
	}
	return false
}

func isValidEyeType(eyeType string) bool {
	validTypes := []string{"left", "right"}
	for _, valid := range validTypes {
		if eyeType == valid {
			return true
		}
	}
	return false
} 