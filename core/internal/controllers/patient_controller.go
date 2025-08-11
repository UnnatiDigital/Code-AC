package controllers

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/bmad-method/hmis-core/internal/database"
	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/services"
)

// PatientController handles patient-related HTTP requests
type PatientController struct {
	patientService *services.PatientService
	db             *database.Connection
}

// NewPatientController creates a new patient controller
func NewPatientController(db *database.Connection) *PatientController {
	patientService := services.NewPatientService(db)
	return &PatientController{
		patientService: patientService,
		db:             db,
	}
}

// PatientService returns the patient service
func (pc *PatientController) PatientService() *services.PatientService {
	return pc.patientService
}

// RegisterPatient handles patient registration
func (pc *PatientController) RegisterPatient(c *gin.Context) {
	var err error
	var request struct {
		BasicInfo struct {
			FirstName    string `json:"firstName" binding:"required"`
			LastName     string `json:"lastName"`
			DateOfBirth  string `json:"dateOfBirth" binding:"required"`
			Gender       string `json:"gender" binding:"required"`
			BloodGroup   string `json:"bloodGroup"`
			MaritalStatus string `json:"maritalStatus"`
		} `json:"basicInfo" binding:"required"`
		ContactInfo struct {
			MobileNumber string `json:"mobileNumber" binding:"required"`
			Email        string `json:"email"`
			EmergencyContact struct {
				Name         string `json:"name"`
				Relationship string `json:"relationship"`
				MobileNumber string `json:"mobileNumber"`
			} `json:"emergencyContact"`
		} `json:"contactInfo" binding:"required"`
		AddressInfo []struct {
			Type        string `json:"type" binding:"required"`
			AddressLine1 string `json:"addressLine1" binding:"required"`
			AddressLine2 string `json:"addressLine2"`
			City        string `json:"city" binding:"required"`
			State       string `json:"state" binding:"required"`
			District    string `json:"district" binding:"required"`
			PINCode     string `json:"pinCode" binding:"required"`
			Country     string `json:"country"`
		} `json:"addressInfo"`
		MedicalInfo struct {
			Allergies []struct {
				Allergen     string `json:"allergen"`
				Severity     string `json:"severity"`
				Reaction     string `json:"reaction"`
				Notes        string `json:"notes"`
			} `json:"allergies"`
			MedicalHistory string `json:"medicalHistory"`
			CurrentMedications []string `json:"currentMedications"`
		} `json:"medicalInfo"`
		InsuranceInfo []struct {
			Provider     string `json:"provider"`
			PolicyNumber string `json:"policyNumber"`
			GroupNumber  string `json:"groupNumber"`
			ExpiryDate   string `json:"expiryDate"`
			CoverageType string `json:"coverageType"`
		} `json:"insuranceInfo"`
		Documents struct {
			AadhaarNumber string `json:"aadhaarNumber"`
			PANNumber     string `json:"panNumber"`
			ABHAID        string `json:"abhaId"`
		} `json:"documents"`
		Consents struct {
			Biometric    bool `json:"biometric"`
			DataSharing  bool `json:"dataSharing"`
			Treatment    bool `json:"treatment"`
			Research     bool `json:"research"`
		} `json:"consents"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Create patient model
	patient := &models.Patient{
		ID:          uuid.New(),
		FirstName:   request.BasicInfo.FirstName,
		LastName:    stringPtrOrNil(request.BasicInfo.LastName),
		DateOfBirth: parseDate(request.BasicInfo.DateOfBirth),
		Gender:      request.BasicInfo.Gender,
		BloodGroup:  stringPtrOrNil(request.BasicInfo.BloodGroup),
		MaritalStatus: stringPtrOrNil(request.BasicInfo.MaritalStatus),
		MobileNumber: request.ContactInfo.MobileNumber,
		Email:        stringPtrOrNil(request.ContactInfo.Email),
		AadhaarNumber: stringPtrOrNil(request.Documents.AadhaarNumber),
		PANNumber:     stringPtrOrNil(request.Documents.PANNumber),
		ABHAID:        stringPtrOrNil(request.Documents.ABHAID),
		IsActive:      true,
		// Set consent data
		BiometricConsent:   request.Consents.Biometric,
		DataSharingConsent: request.Consents.DataSharing,
		// Set registration details
		RegistrationType:   "standard",
		RegistrationSource: "walk_in",
		// Set audit fields to nil to avoid foreign key issues
		CreatedBy:          nil,
		UpdatedBy:          nil,
	}
	
	// Set consent timestamp if any consent is provided
	if request.Consents.Biometric || request.Consents.DataSharing || request.Consents.Treatment {
		now := time.Now()
		patient.ConsentTimestamp = &now
	}



	// Register patient
	err = pc.patientService.RegisterPatient(patient)
	if err != nil {
		// Check if it's a duplicate patient error
		if duplicateErr, ok := err.(*services.DuplicatePatientError); ok {
			c.JSON(http.StatusConflict, gin.H{
				"success": false,
				"error":   duplicateErr.Message,
				"duplicates": duplicateErr.Duplicates,
			})
			return
		}
		
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to register patient",
			"details": err.Error(),
		})
		return
	}

	// Add addresses
	for _, addr := range request.AddressInfo {
		address := &models.PatientAddress{
			ID:          uuid.New(),
			PatientID:   patient.ID,
			AddressType: strings.ToLower(addr.Type),
			AddressLine1: addr.AddressLine1,
			AddressLine2: &addr.AddressLine2,
			City:        addr.City,
			State:       addr.State,
			District:    addr.District,
			PINCode:     addr.PINCode,
			Country:     addr.Country,
		}
		err = pc.patientService.AddPatientAddress(patient.ID, address)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to add address",
			})
			return
		}
	}

	// Add allergies
	for _, allergy := range request.MedicalInfo.Allergies {
		allergyModel := &models.PatientAllergy{
			ID:        uuid.New(),
			PatientID: patient.ID,
			AllergyName: allergy.Allergen,
			Severity:  allergy.Severity,
			Reaction:  &allergy.Reaction,
			Notes:     &allergy.Notes,
		}
		err = pc.patientService.AddPatientAllergy(patient.ID, allergyModel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to add allergy",
			})
			return
		}
	}

	// Add insurance policies
	for _, insurance := range request.InsuranceInfo {
		endDate := parseDate(insurance.ExpiryDate)
		if endDate == nil {
			endDate = &time.Time{} // Use zero time if parsing fails
		}
		
		policy := &models.InsurancePolicy{
			ID:           uuid.New(),
			PatientID:    patient.ID,
			InsuranceProvider: insurance.Provider,
			PolicyNumber: insurance.PolicyNumber,
			GroupName:    &insurance.GroupNumber,
			EndDate:      *endDate,
			PolicyType:   insurance.CoverageType,
		}
		err = pc.patientService.AddInsurancePolicy(patient.ID, policy)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to add insurance policy",
			})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data": gin.H{
			"patientId": patient.ID,
			"uhid":      patient.UHID,
			"message":   "Patient registered successfully",
		},
	})
}

// GetPatient retrieves a patient by ID
func (pc *PatientController) GetPatient(c *gin.Context) {
	patientID := c.Param("id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Patient ID is required",
		})
		return
	}

	// Parse UUID
	id, err := uuid.Parse(patientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid patient ID format",
		})
		return
	}

	patient, err := pc.patientService.GetPatientByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "Patient not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to retrieve patient",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    patient,
	})
}

// GetPatientByUHID retrieves a patient by UHID
func (pc *PatientController) GetPatientByUHID(c *gin.Context) {
	uhid := c.Param("uhid")
	if uhid == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "UHID is required",
		})
		return
	}

	patient, err := pc.patientService.GetPatientByUHID(uhid)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "Patient not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to retrieve patient",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    patient,
	})
}

// SearchPatients searches for patients based on criteria
func (pc *PatientController) SearchPatients(c *gin.Context) {
	var request struct {
		Query       string `json:"query"`
		FirstName   string `json:"firstName"`
		LastName    string `json:"lastName"`
		MobileNumber string `json:"mobileNumber"`
		AadhaarNumber string `json:"aadhaarNumber"`
		UHID        string `json:"uhid"`
		Page        int    `json:"page"`
		Limit       int    `json:"limit"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request data",
		})
		return
	}

	// Set default pagination
	if request.Page <= 0 {
		request.Page = 1
	}
	if request.Limit <= 0 {
		request.Limit = 10
	}

	// Build search criteria
	criteria := &services.PatientSearchCriteria{
		Query:         request.Query,
		FirstName:     request.FirstName,
		LastName:      request.LastName,
		MobileNumber:  request.MobileNumber,
		AadhaarNumber: request.AadhaarNumber,
		UHID:          request.UHID,
		Page:          request.Page,
		Limit:         request.Limit,
	}

	patients, total, err := pc.patientService.SearchPatients(criteria)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to search patients",
		})
		return
	}

	totalPages := (total + request.Limit - 1) / request.Limit

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"patients":    patients,
			"pagination": gin.H{
				"page":       request.Page,
				"limit":      request.Limit,
				"total":      total,
				"totalPages": totalPages,
			},
		},
	})
}

// UpdatePatient updates patient information
func (pc *PatientController) UpdatePatient(c *gin.Context) {
	patientID := c.Param("id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Patient ID is required",
		})
		return
	}

	id, err := uuid.Parse(patientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid patient ID format",
		})
		return
	}

	var request struct {
		FirstName    string `json:"firstName"`
		LastName     string `json:"lastName"`
		DateOfBirth  string `json:"dateOfBirth"`
		Gender       string `json:"gender"`
		BloodGroup   string `json:"bloodGroup"`
		MaritalStatus string `json:"maritalStatus"`
		MobileNumber string `json:"mobileNumber"`
		Email        string `json:"email"`
		AadhaarNumber string `json:"aadhaarNumber"`
		PANNumber     string `json:"panNumber"`
		ABHAID        string `json:"abhaId"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request data",
		})
		return
	}

	// Get existing patient
	patient, err := pc.patientService.GetPatientByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "Patient not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to retrieve patient",
		})
		return
	}

	// Update fields if provided
	if request.FirstName != "" {
		patient.FirstName = request.FirstName
	}
	if request.LastName != "" {
		patient.LastName = &request.LastName
	}
	if request.DateOfBirth != "" {
		patient.DateOfBirth = parseDate(request.DateOfBirth)
	}
	if request.Gender != "" {
		patient.Gender = request.Gender
	}
	if request.BloodGroup != "" {
		patient.BloodGroup = &request.BloodGroup
	}
	if request.MaritalStatus != "" {
		patient.MaritalStatus = &request.MaritalStatus
	}
	if request.MobileNumber != "" {
		patient.MobileNumber = request.MobileNumber
	}
	if request.Email != "" {
		patient.Email = &request.Email
	}
	if request.AadhaarNumber != "" {
		patient.AadhaarNumber = &request.AadhaarNumber
	}
	if request.PANNumber != "" {
		patient.PANNumber = &request.PANNumber
	}
	if request.ABHAID != "" {
		patient.ABHAID = &request.ABHAID
	}

	err = pc.patientService.UpdatePatient(patient)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to update patient",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    patient,
		"message": "Patient updated successfully",
	})
}

// DeletePatient deletes a patient (soft delete)
func (pc *PatientController) DeletePatient(c *gin.Context) {
	patientID := c.Param("id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Patient ID is required",
		})
		return
	}

	id, err := uuid.Parse(patientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid patient ID format",
		})
		return
	}

	err = pc.patientService.DeletePatient(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to delete patient",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Patient deleted successfully",
	})
}

// RegisterBiometricData registers biometric data for a patient
func (pc *PatientController) RegisterBiometricData(c *gin.Context) {
	patientID := c.Param("id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Patient ID is required",
		})
		return
	}

	id, err := uuid.Parse(patientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid patient ID format",
		})
		return
	}

	var request struct {
		Type        string  `json:"type" binding:"required"` // fingerprint, face, iris
		Data        string  `json:"data" binding:"required"`
		Quality     float64 `json:"quality"`
		DeviceID    string  `json:"deviceId"`
		TemplateID  string  `json:"templateId"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request data",
		})
		return
	}

	biometricData := &models.BiometricData{
		ID:         uuid.New(),
		PatientID:  id,
		DeviceType: &request.Type,
		DeviceID:   &request.DeviceID,
		QualityScore: &request.Quality,
	}

	err = pc.patientService.RegisterBiometricData(id, biometricData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to register biometric data",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data": gin.H{
			"biometricId": biometricData.ID,
			"message":     "Biometric data registered successfully",
		},
	})
}

// SearchByBiometric searches for patients using biometric data
func (pc *PatientController) SearchByBiometric(c *gin.Context) {
	var request struct {
		Type string `json:"type" binding:"required"`
		Data string `json:"data" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request data",
		})
		return
	}

	biometricData := &models.BiometricData{
		DeviceType: &request.Type,
	}

	matches, err := pc.patientService.SearchByBiometric(biometricData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to search by biometric",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"matches": matches,
			"count":   len(matches),
		},
	})
}

// GetPatientAddresses retrieves addresses for a patient
func (pc *PatientController) GetPatientAddresses(c *gin.Context) {
	patientID := c.Param("id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Patient ID is required",
		})
		return
	}

	id, err := uuid.Parse(patientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid patient ID format",
		})
		return
	}

	addresses, err := pc.patientService.GetPatientAddresses(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to retrieve addresses",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    addresses,
	})
}

// GetPatientAllergies retrieves allergies for a patient
func (pc *PatientController) GetPatientAllergies(c *gin.Context) {
	patientID := c.Param("id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Patient ID is required",
		})
		return
	}

	id, err := uuid.Parse(patientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid patient ID format",
		})
		return
	}

	allergies, err := pc.patientService.GetPatientAllergies(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to retrieve allergies",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    allergies,
	})
}

// GetPatientInsurance retrieves insurance policies for a patient
func (pc *PatientController) GetPatientInsurance(c *gin.Context) {
	patientID := c.Param("id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Patient ID is required",
		})
		return
	}

	id, err := uuid.Parse(patientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid patient ID format",
		})
		return
	}

	policies, err := pc.patientService.GetPatientInsurancePolicies(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to retrieve insurance policies",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    policies,
	})
}

// GetDashboardData retrieves dashboard statistics
func (pc *PatientController) GetDashboardData(c *gin.Context) {
	stats, err := pc.patientService.GetPatientStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to retrieve dashboard data",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// GetPatientStatistics returns patient statistics
func (pc *PatientController) GetPatientStatistics(c *gin.Context) {
	stats, err := pc.patientService.GetPatientStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to retrieve patient statistics",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// CheckDuplicatePatient checks for potential duplicate patients
func (pc *PatientController) CheckDuplicatePatient(c *gin.Context) {
	var request struct {
		FirstName    string `json:"firstName"`
		LastName     string `json:"lastName"`
		MobileNumber string `json:"mobileNumber"`
		AadhaarNumber string `json:"aadhaarNumber"`
		DateOfBirth  string `json:"dateOfBirth"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Create a temporary patient object for duplicate checking
	patient := &models.Patient{
		FirstName:     request.FirstName,
		LastName:      stringPtrOrNil(request.LastName),
		MobileNumber:  request.MobileNumber,
		AadhaarNumber: stringPtrOrNil(request.AadhaarNumber),
		DateOfBirth:   parseDate(request.DateOfBirth),
	}

	// Check for duplicates
	duplicates, err := pc.patientService.CheckDuplicatePatient(patient)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to check for duplicates",
		})
		return
	}

	isDuplicate := len(duplicates) > 0
	confidence := 0.0
	matchType := ""

	if isDuplicate {
		// Calculate confidence based on match type
		for _, duplicate := range duplicates {
			if duplicate.MobileNumber == request.MobileNumber && request.MobileNumber != "" {
				confidence = 0.9
				matchType = "mobile"
				break
			}
			if duplicate.AadhaarNumber != nil && request.AadhaarNumber != "" && *duplicate.AadhaarNumber == request.AadhaarNumber {
				confidence = 0.95
				matchType = "aadhaar"
				break
			}
			if duplicate.FirstName == request.FirstName && duplicate.DateOfBirth != nil && request.DateOfBirth != "" {
				confidence = 0.7
				matchType = "name_dob"
				break
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"isDuplicate":     isDuplicate,
			"confidence":      confidence,
			"matchedPatients": duplicates,
			"matchType":       matchType,
		},
	})
}

// ValidateDocument validates Aadhaar, PAN, or mobile number
func (pc *PatientController) ValidateDocument(c *gin.Context) {
	docType := c.Param("type")
	value := c.Query("value")

	if docType == "" || value == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Document type and value are required",
		})
		return
	}

	var isValid bool
	var err error

	switch strings.ToLower(docType) {
	case "aadhaar":
		isValid, err = pc.patientService.ValidateAadhaar(value)
	case "pan":
		isValid, err = pc.patientService.ValidatePAN(value)
	case "mobile":
		isValid, err = pc.patientService.ValidateMobile(value)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Unsupported document type",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Validation failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"isValid": isValid,
			"value":   value,
			"type":    docType,
		},
	})
}

// parseDate parses a date string into a time.Time pointer
func parseDate(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}
	
	// Try different date formats
	formats := []string{
		"2006-01-02",
		"02/01/2006",
		"01/02/2006",
		"2006-01-02T15:04:05Z",
	}
	
	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}
	
	// If parsing fails, return nil
	return nil
}

// stringPtrOrNil returns a pointer to the string if it's not empty, otherwise nil
func stringPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
} 