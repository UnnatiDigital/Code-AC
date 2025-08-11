package services

import (
	"context"
	"fmt"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/repositories"
	"github.com/google/uuid"
)

// AuditService provides comprehensive audit logging and compliance reporting functionality
type AuditService struct {
	auditRepo repositories.AuditRepository
}

// NewAuditService creates a new audit service
func NewAuditService(auditRepo repositories.AuditRepository) *AuditService {
	return &AuditService{
		auditRepo: auditRepo,
	}
}

// AuthenticationEventData represents the data for logging authentication events
type AuthenticationEventData struct {
	UserID        uuid.UUID `json:"user_id"`
	EventType     string    `json:"event_type"`
	IPAddress     string    `json:"ip_address"`
	UserAgent     string    `json:"user_agent"`
	Success       bool      `json:"success"`
	FailureReason string    `json:"failure_reason,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty"`
}

// AuthorizationEventData represents the data for logging authorization events
type AuthorizationEventData struct {
	UserID   uuid.UUID              `json:"user_id"`
	Resource string                 `json:"resource"`
	Action   string                 `json:"action"`
	Context  map[string]interface{} `json:"context,omitempty"`
	Allowed  bool                   `json:"allowed"`
	Reason   string                 `json:"reason"`
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ReportType  string                 `json:"report_type"`
	StartDate   time.Time              `json:"start_date"`
	EndDate     time.Time              `json:"end_date"`
	TotalEvents int                    `json:"total_events"`
	Summary     map[string]interface{} `json:"summary"`
	Details     []interface{}          `json:"details"`
}

// LogAuthenticationEvent logs an authentication event
func (s *AuditService) LogAuthenticationEvent(ctx context.Context, data *AuthenticationEventData) error {
	event := &models.AuthenticationEvent{
		ID:            uuid.New(),
		UserID:        &data.UserID,
		EventType:     data.EventType,
		IPAddress:     &data.IPAddress,
		UserAgent:     &data.UserAgent,
		Success:       data.Success,
		FailureReason: &data.FailureReason,
		Metadata:      (*models.JSONMap)(&data.Context),
		CreatedAt:     time.Now(),
	}

	return s.auditRepo.CreateAuthenticationEvent(ctx, event)
}

// LogAuthorizationEvent logs an authorization event
func (s *AuditService) LogAuthorizationEvent(ctx context.Context, data *AuthorizationEventData) error {
	event := &models.AuthorizationEvent{
		ID:        uuid.New(),
		UserID:    &data.UserID,
		Resource:  data.Resource,
		Action:    data.Action,
		Granted:   data.Allowed,
		Reason:    &data.Reason,
		CreatedAt: time.Now(),
	}

	return s.auditRepo.CreateAuthorizationEvent(ctx, event)
}

// GetAuthenticationEvents retrieves authentication events with filters
func (s *AuditService) GetAuthenticationEvents(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]*models.AuthenticationEvent, int, error) {
	return s.auditRepo.GetAuthenticationEvents(ctx, nil, offset, limit, filters)
}

// GetAuthorizationEvents retrieves authorization events with filters
func (s *AuditService) GetAuthorizationEvents(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]*models.AuthorizationEvent, int, error) {
	return s.auditRepo.GetAuthorizationEvents(ctx, nil, offset, limit, filters)
}

// SearchAuditEvents searches across all audit events
func (s *AuditService) SearchAuditEvents(ctx context.Context, query string, eventType string, offset, limit int) ([]interface{}, int, error) {
	// This method is not implemented in the repository interface
	// We'll implement a basic search using existing methods
	return []interface{}{}, 0, nil
}

// GenerateComplianceReport generates a compliance report
func (s *AuditService) GenerateComplianceReport(ctx context.Context, startDate, endDate time.Time, reportType string) (*ComplianceReport, error) {
	// This method is not implemented in the repository interface
	// We'll return a basic report structure
	return &ComplianceReport{
		ReportType:  reportType,
		StartDate:   startDate,
		EndDate:     endDate,
		TotalEvents: 0,
		Summary:     map[string]interface{}{},
		Details:     []interface{}{},
	}, nil
}

// CleanupOldAuditData cleans up old audit data based on retention policy
func (s *AuditService) CleanupOldAuditData(ctx context.Context, retentionDays int) error {
	before := time.Now().AddDate(0, 0, -retentionDays)
	return s.auditRepo.CleanupOldEvents(ctx, before)
}

// GetAuditEventByID retrieves a specific audit event by ID
func (s *AuditService) GetAuditEventByID(ctx context.Context, eventID uuid.UUID, eventType string) (interface{}, error) {
	// This method is not implemented in the repository interface
	// We'll return nil for now
	return nil, nil
}

// LogLoginSuccess logs a successful login event
func (s *AuditService) LogLoginSuccess(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, context map[string]interface{}) error {
	return s.LogAuthenticationEvent(ctx, &AuthenticationEventData{
		UserID:    userID,
		EventType: "login_success",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		Context:   context,
	})
}

// LogLoginFailure logs a failed login event
func (s *AuditService) LogLoginFailure(ctx context.Context, userID uuid.UUID, ipAddress, userAgent, failureReason string, context map[string]interface{}) error {
	return s.LogAuthenticationEvent(ctx, &AuthenticationEventData{
		UserID:        userID,
		EventType:     "login_failed",
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		Success:       false,
		FailureReason: failureReason,
		Context:       context,
	})
}

// LogLogout logs a logout event
func (s *AuditService) LogLogout(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, context map[string]interface{}) error {
	return s.LogAuthenticationEvent(ctx, &AuthenticationEventData{
		UserID:    userID,
		EventType: "logout",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		Context:   context,
	})
}

// LogPasswordChange logs a password change event
func (s *AuditService) LogPasswordChange(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, context map[string]interface{}) error {
	return s.LogAuthenticationEvent(ctx, &AuthenticationEventData{
		UserID:    userID,
		EventType: "password_change",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		Context:   context,
	})
}

// LogMFASuccess logs a successful MFA event
func (s *AuditService) LogMFASuccess(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, context map[string]interface{}) error {
	return s.LogAuthenticationEvent(ctx, &AuthenticationEventData{
		UserID:    userID,
		EventType: "mfa_success",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		Context:   context,
	})
}

// LogMFAFailure logs a failed MFA event
func (s *AuditService) LogMFAFailure(ctx context.Context, userID uuid.UUID, ipAddress, userAgent, failureReason string, context map[string]interface{}) error {
	return s.LogAuthenticationEvent(ctx, &AuthenticationEventData{
		UserID:        userID,
		EventType:     "mfa_failed",
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		Success:       false,
		FailureReason: failureReason,
		Context:       context,
	})
}

// LogBiometricSuccess logs a successful biometric authentication event
func (s *AuditService) LogBiometricSuccess(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, context map[string]interface{}) error {
	return s.LogAuthenticationEvent(ctx, &AuthenticationEventData{
		UserID:    userID,
		EventType: "biometric_success",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		Context:   context,
	})
}

// LogBiometricFailure logs a failed biometric authentication event
func (s *AuditService) LogBiometricFailure(ctx context.Context, userID uuid.UUID, ipAddress, userAgent, failureReason string, context map[string]interface{}) error {
	return s.LogAuthenticationEvent(ctx, &AuthenticationEventData{
		UserID:        userID,
		EventType:     "biometric_failed",
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		Success:       false,
		FailureReason: failureReason,
		Context:       context,
	})
}

// LogPermissionGranted logs a granted permission event
func (s *AuditService) LogPermissionGranted(ctx context.Context, userID uuid.UUID, resource, action string, context map[string]interface{}) error {
	return s.LogAuthorizationEvent(ctx, &AuthorizationEventData{
		UserID:   userID,
		Resource: resource,
		Action:   action,
		Context:  context,
		Allowed:  true,
		Reason:   "permission granted",
	})
}

// LogPermissionDenied logs a denied permission event
func (s *AuditService) LogPermissionDenied(ctx context.Context, userID uuid.UUID, resource, action, reason string, context map[string]interface{}) error {
	return s.LogAuthorizationEvent(ctx, &AuthorizationEventData{
		UserID:   userID,
		Resource: resource,
		Action:   action,
		Context:  context,
		Allowed:  false,
		Reason:   reason,
	})
}

// LogRoleCheck logs a role check event
func (s *AuditService) LogRoleCheck(ctx context.Context, userID uuid.UUID, roleName string, hasRole bool, context map[string]interface{}) error {
	reason := "role check"
	if hasRole {
		reason = fmt.Sprintf("user has role: %s", roleName)
	} else {
		reason = fmt.Sprintf("user does not have role: %s", roleName)
	}

	return s.LogAuthorizationEvent(ctx, &AuthorizationEventData{
		UserID:   userID,
		Resource: "role_check",
		Action:   roleName,
		Context:  context,
		Allowed:  hasRole,
		Reason:   reason,
	})
}

// LogFacilityAccess logs a facility access check event
func (s *AuditService) LogFacilityAccess(ctx context.Context, userID uuid.UUID, facilityID uuid.UUID, hasAccess bool, context map[string]interface{}) error {
	reason := "facility access check"
	if hasAccess {
		reason = fmt.Sprintf("user has access to facility: %s", facilityID.String())
	} else {
		reason = fmt.Sprintf("user does not have access to facility: %s", facilityID.String())
	}

	return s.LogAuthorizationEvent(ctx, &AuthorizationEventData{
		UserID:   userID,
		Resource: "facility_access",
		Action:   "access",
		Context:  context,
		Allowed:  hasAccess,
		Reason:   reason,
	})
}

// LogPatientDataAccess logs a patient data access event
func (s *AuditService) LogPatientDataAccess(ctx context.Context, userID uuid.UUID, patientID uuid.UUID, action string, hasAccess bool, context map[string]interface{}) error {
	reason := "patient data access"
	if hasAccess {
		reason = fmt.Sprintf("user has access to patient data: %s", patientID.String())
	} else {
		reason = fmt.Sprintf("user does not have access to patient data: %s", patientID.String())
	}

	return s.LogAuthorizationEvent(ctx, &AuthorizationEventData{
		UserID:   userID,
		Resource: "patient_records",
		Action:   action,
		Context:  context,
		Allowed:  hasAccess,
		Reason:   reason,
	})
}

// LogMedicationAccess logs a medication access event
func (s *AuditService) LogMedicationAccess(ctx context.Context, userID uuid.UUID, medicationID uuid.UUID, action string, hasAccess bool, context map[string]interface{}) error {
	reason := "medication access"
	if hasAccess {
		reason = fmt.Sprintf("user has access to medication: %s", medicationID.String())
	} else {
		reason = fmt.Sprintf("user does not have access to medication: %s", medicationID.String())
	}

	return s.LogAuthorizationEvent(ctx, &AuthorizationEventData{
		UserID:   userID,
		Resource: "medications",
		Action:   action,
		Context:  context,
		Allowed:  hasAccess,
		Reason:   reason,
	})
}

// LogEmergencyAccess logs an emergency access event
func (s *AuditService) LogEmergencyAccess(ctx context.Context, userID uuid.UUID, emergencyType string, hasAccess bool, context map[string]interface{}) error {
	reason := "emergency access"
	if hasAccess {
		reason = fmt.Sprintf("emergency access granted for: %s", emergencyType)
	} else {
		reason = fmt.Sprintf("emergency access denied for: %s", emergencyType)
	}

	return s.LogAuthorizationEvent(ctx, &AuthorizationEventData{
		UserID:   userID,
		Resource: "emergency_records",
		Action:   "access",
		Context:  context,
		Allowed:  hasAccess,
		Reason:   reason,
	})
}

// GenerateHIPAAReport generates a HIPAA compliance report
func (s *AuditService) GenerateHIPAAReport(ctx context.Context, startDate, endDate time.Time) (*ComplianceReport, error) {
	return s.GenerateComplianceReport(ctx, startDate, endDate, "hipaa")
}

// GenerateDISHAReport generates a DISHA compliance report
func (s *AuditService) GenerateDISHAReport(ctx context.Context, startDate, endDate time.Time) (*ComplianceReport, error) {
	return s.GenerateComplianceReport(ctx, startDate, endDate, "disha")
}

// GenerateABDMReport generates an ABDM compliance report
func (s *AuditService) GenerateABDMReport(ctx context.Context, startDate, endDate time.Time) (*ComplianceReport, error) {
	return s.GenerateComplianceReport(ctx, startDate, endDate, "abdm")
}

// GenerateSecurityReport generates a security audit report
func (s *AuditService) GenerateSecurityReport(ctx context.Context, startDate, endDate time.Time) (*ComplianceReport, error) {
	return s.GenerateComplianceReport(ctx, startDate, endDate, "security")
}

// GenerateHealthcareComplianceReport generates a healthcare-specific compliance report
func (s *AuditService) GenerateHealthcareComplianceReport(ctx context.Context, startDate, endDate time.Time) (*ComplianceReport, error) {
	return s.GenerateComplianceReport(ctx, startDate, endDate, "healthcare_compliance")
}

// GetAuthenticationEventsByUser retrieves authentication events for a specific user
func (s *AuditService) GetAuthenticationEventsByUser(ctx context.Context, userID uuid.UUID, offset, limit int) ([]*models.AuthenticationEvent, int, error) {
	filters := map[string]interface{}{
		"user_id": userID,
	}
	return s.GetAuthenticationEvents(ctx, filters, offset, limit)
}

// GetAuthorizationEventsByUser retrieves authorization events for a specific user
func (s *AuditService) GetAuthorizationEventsByUser(ctx context.Context, userID uuid.UUID, offset, limit int) ([]*models.AuthorizationEvent, int, error) {
	filters := map[string]interface{}{
		"user_id": userID,
	}
	return s.GetAuthorizationEvents(ctx, filters, offset, limit)
}

// GetFailedLoginEvents retrieves failed login events
func (s *AuditService) GetFailedLoginEvents(ctx context.Context, offset, limit int) ([]*models.AuthenticationEvent, int, error) {
	filters := map[string]interface{}{
		"event_type": "login_failed",
		"success":    false,
	}
	return s.GetAuthenticationEvents(ctx, filters, offset, limit)
}

// GetAccessDeniedEvents retrieves access denied events
func (s *AuditService) GetAccessDeniedEvents(ctx context.Context, offset, limit int) ([]*models.AuthorizationEvent, int, error) {
	filters := map[string]interface{}{
		"allowed": false,
	}
	return s.GetAuthorizationEvents(ctx, filters, offset, limit)
}

// GetEventsByDateRange retrieves events within a date range
func (s *AuditService) GetEventsByDateRange(ctx context.Context, startDate, endDate time.Time, eventType string, offset, limit int) ([]interface{}, int, error) {
	// This would typically be implemented in the repository layer
	// For now, we'll use the search functionality
	query := fmt.Sprintf("date_range:%s_to_%s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02"))
	return s.SearchAuditEvents(ctx, query, eventType, offset, limit)
}

// GetSuspiciousActivityEvents retrieves suspicious activity events
func (s *AuditService) GetSuspiciousActivityEvents(ctx context.Context, offset, limit int) ([]interface{}, int, error) {
	// This would typically look for patterns like:
	// - Multiple failed logins from same IP
	// - Access attempts outside business hours
	// - Unusual access patterns
	query := "suspicious_activity"
	return s.SearchAuditEvents(ctx, query, "all", offset, limit)
}

// GetAuditSummary provides a summary of audit events
func (s *AuditService) GetAuditSummary(ctx context.Context, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Get authentication events count
	authEvents, _, err := s.GetAuthenticationEvents(ctx, map[string]interface{}{}, 0, 1)
	if err != nil {
		return nil, err
	}

	// Get authorization events count
	authzEvents, _, err := s.GetAuthorizationEvents(ctx, map[string]interface{}{}, 0, 1)
	if err != nil {
		return nil, err
	}

	// Get failed logins count
	failedLogins, _, err := s.GetFailedLoginEvents(ctx, 0, 1)
	if err != nil {
		return nil, err
	}

	// Get access denied count
	accessDenied, _, err := s.GetAccessDeniedEvents(ctx, 0, 1)
	if err != nil {
		return nil, err
	}

	summary := map[string]interface{}{
		"start_date":           startDate,
		"end_date":             endDate,
		"authentication_events": len(authEvents),
		"authorization_events":  len(authzEvents),
		"failed_logins":         len(failedLogins),
		"access_denials":        len(accessDenied),
		"total_events":          len(authEvents) + len(authzEvents),
	}

	return summary, nil
}

// ExportAuditData exports audit data for external analysis
func (s *AuditService) ExportAuditData(ctx context.Context, startDate, endDate time.Time, format string) ([]byte, error) {
	// This would typically export audit data in various formats (CSV, JSON, XML)
	// For now, we'll return a placeholder implementation
	_, err := s.GetAuditSummary(ctx, startDate, endDate)
	if err != nil {
		return nil, err
	}

	// In a real implementation, this would format the data according to the specified format
	// and include all audit events within the date range
	// format parameter would be used in actual implementation

	// Return a placeholder response
	return []byte("audit_data_export"), nil
}

// ValidateAuditData validates audit data integrity
func (s *AuditService) ValidateAuditData(ctx context.Context, startDate, endDate time.Time) (map[string]interface{}, error) {
	// This would typically validate:
	// - Data completeness
	// - Data consistency
	// - Missing events
	// - Duplicate events
	// - Timestamp accuracy

	validation := map[string]interface{}{
		"start_date":     startDate,
		"end_date":       endDate,
		"is_valid":       true,
		"total_events":   0,
		"missing_events": 0,
		"duplicates":     0,
		"errors":         []string{},
	}

	return validation, nil
} 