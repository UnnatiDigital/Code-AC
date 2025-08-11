package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"
)

// MockAuditRepository is a mock implementation of AuditRepository
type MockAuditRepository struct {
	mock.Mock
}

func (m *MockAuditRepository) CreateAuthenticationEvent(ctx context.Context, event *models.AuthenticationEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockAuditRepository) CreateAuthorizationEvent(ctx context.Context, event *models.AuthorizationEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockAuditRepository) GetAuthenticationEvents(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]*models.AuthenticationEvent, int, error) {
	args := m.Called(ctx, filters, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.AuthenticationEvent), args.Int(1), args.Error(2)
}

func (m *MockAuditRepository) GetAuthorizationEvents(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]*models.AuthorizationEvent, int, error) {
	args := m.Called(ctx, filters, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.AuthorizationEvent), args.Int(1), args.Error(2)
}

func (m *MockAuditRepository) SearchAuditEvents(ctx context.Context, query string, eventType string, offset, limit int) ([]interface{}, int, error) {
	args := m.Called(ctx, query, eventType, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]interface{}), args.Int(1), args.Error(2)
}

func (m *MockAuditRepository) GetComplianceReport(ctx context.Context, startDate, endDate time.Time, reportType string) (*services.ComplianceReport, error) {
	args := m.Called(ctx, startDate, endDate, reportType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.ComplianceReport), args.Error(1)
}

func (m *MockAuditRepository) CleanupOldAuditData(ctx context.Context, retentionDays int) error {
	args := m.Called(ctx, retentionDays)
	return args.Error(0)
}

func (m *MockAuditRepository) GetAuditEventByID(ctx context.Context, eventID uuid.UUID, eventType string) (interface{}, error) {
	args := m.Called(ctx, eventID, eventType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0), args.Error(1)
}

// TestAuditService_AuthenticationEventLogging tests authentication event logging
func TestAuditService_AuthenticationEventLogging(t *testing.T) {
	mockAuditRepo := new(MockAuditRepository)
	auditService := services.NewAuditService(mockAuditRepo)

	ctx := context.Background()

	t.Run("log successful login", func(t *testing.T) {
		userID := uuid.New()
		ipAddress := "192.168.1.100"
		userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthenticationEvent", ctx, mock.AnythingOfType("*models.AuthenticationEvent")).Return(nil)

		// Log authentication event
		err := auditService.LogAuthenticationEvent(ctx, &services.AuthenticationEventData{
			UserID:      userID,
			EventType:   "login_success",
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			Success:     true,
			FailureReason: "",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log failed login", func(t *testing.T) {
		userID := uuid.New()
		ipAddress := "192.168.1.100"
		userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
		failureReason := "invalid_credentials"

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthenticationEvent", ctx, mock.AnythingOfType("*models.AuthenticationEvent")).Return(nil)

		// Log authentication event
		err := auditService.LogAuthenticationEvent(ctx, &services.AuthenticationEventData{
			UserID:      userID,
			EventType:   "login_failed",
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			Success:     false,
			FailureReason: failureReason,
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log logout event", func(t *testing.T) {
		userID := uuid.New()
		ipAddress := "192.168.1.100"
		userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthenticationEvent", ctx, mock.AnythingOfType("*models.AuthenticationEvent")).Return(nil)

		// Log authentication event
		err := auditService.LogAuthenticationEvent(ctx, &services.AuthenticationEventData{
			UserID:      userID,
			EventType:   "logout",
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			Success:     true,
			FailureReason: "",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log password change", func(t *testing.T) {
		userID := uuid.New()
		ipAddress := "192.168.1.100"
		userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthenticationEvent", ctx, mock.AnythingOfType("*models.AuthenticationEvent")).Return(nil)

		// Log authentication event
		err := auditService.LogAuthenticationEvent(ctx, &services.AuthenticationEventData{
			UserID:      userID,
			EventType:   "password_change",
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			Success:     true,
			FailureReason: "",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log MFA event", func(t *testing.T) {
		userID := uuid.New()
		ipAddress := "192.168.1.100"
		userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthenticationEvent", ctx, mock.AnythingOfType("*models.AuthenticationEvent")).Return(nil)

		// Log authentication event
		err := auditService.LogAuthenticationEvent(ctx, &services.AuthenticationEventData{
			UserID:      userID,
			EventType:   "mfa_success",
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			Success:     true,
			FailureReason: "",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log biometric authentication", func(t *testing.T) {
		userID := uuid.New()
		ipAddress := "192.168.1.100"
		userAgent := "Mobile App v1.0"

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthenticationEvent", ctx, mock.AnythingOfType("*models.AuthenticationEvent")).Return(nil)

		// Log authentication event
		err := auditService.LogAuthenticationEvent(ctx, &services.AuthenticationEventData{
			UserID:      userID,
			EventType:   "biometric_success",
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			Success:     true,
			FailureReason: "",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})
}

// TestAuditService_AuthorizationEventLogging tests authorization event logging
func TestAuditService_AuthorizationEventLogging(t *testing.T) {
	mockAuditRepo := new(MockAuditRepository)
	auditService := services.NewAuditService(mockAuditRepo)

	ctx := context.Background()

	t.Run("log permission granted", func(t *testing.T) {
		userID := uuid.New()
		resource := "patients"
		action := "read"
		context := map[string]interface{}{
			"patient_id": uuid.New().String(),
			"facility_id": uuid.New().String(),
		}

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(nil)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  resource,
			Action:    action,
			Context:   context,
			Allowed:   true,
			Reason:    "user has required permission",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log permission denied", func(t *testing.T) {
		userID := uuid.New()
		resource := "admin_panel"
		action := "access"
		context := map[string]interface{}{
			"ip_address": "192.168.1.100",
		}

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(nil)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  resource,
			Action:    action,
			Context:   context,
			Allowed:   false,
			Reason:    "insufficient permissions",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log role check", func(t *testing.T) {
		userID := uuid.New()
		resource := "role_check"
		action := "doctor"
		context := map[string]interface{}{
			"facility_id": uuid.New().String(),
		}

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(nil)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  resource,
			Action:    action,
			Context:   context,
			Allowed:   true,
			Reason:    "user has doctor role",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log facility access check", func(t *testing.T) {
		userID := uuid.New()
		resource := "facility_access"
		action := "access"
		context := map[string]interface{}{
			"facility_id": uuid.New().String(),
			"location": "emergency_room",
		}

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(nil)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  resource,
			Action:    action,
			Context:   context,
			Allowed:   true,
			Reason:    "user has access to facility",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log context-based authorization", func(t *testing.T) {
		userID := uuid.New()
		resource := "patient_records"
		action := "read"
		context := map[string]interface{}{
			"patient_id": uuid.New().String(),
			"time_of_day": "business_hours",
			"location": "hospital_premises",
		}

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(nil)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  resource,
			Action:    action,
			Context:   context,
			Allowed:   true,
			Reason:    "context-based authorization passed",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})
}

// TestAuditService_AuditEventFilteringAndSearch tests audit event filtering and search
func TestAuditService_AuditEventFilteringAndSearch(t *testing.T) {
	mockAuditRepo := new(MockAuditRepository)
	auditService := services.NewAuditService(mockAuditRepo)

	ctx := context.Background()

	t.Run("get authentication events with filters", func(t *testing.T) {
		// Create test events
		events := []*models.AuthenticationEvent{
			{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				EventType: "login_success",
				IPAddress: "192.168.1.100",
				Success:   true,
				Timestamp: time.Now(),
			},
			{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				EventType: "login_failed",
				IPAddress: "192.168.1.101",
				Success:   false,
				Timestamp: time.Now(),
			},
		}

		filters := map[string]interface{}{
			"event_type": "login_success",
			"success":    true,
		}

		// Setup mock expectations
		mockAuditRepo.On("GetAuthenticationEvents", ctx, filters, 0, 10).Return(events, 2, nil)

		// Get authentication events
		result, total, err := auditService.GetAuthenticationEvents(ctx, filters, 0, 10)

		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, 2, total)

		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("get authorization events with filters", func(t *testing.T) {
		// Create test events
		events := []*models.AuthorizationEvent{
			{
				ID:       uuid.New(),
				UserID:   uuid.New(),
				Resource: "patients",
				Action:   "read",
				Allowed:  true,
				Timestamp: time.Now(),
			},
			{
				ID:       uuid.New(),
				UserID:   uuid.New(),
				Resource: "admin_panel",
				Action:   "access",
				Allowed:  false,
				Timestamp: time.Now(),
			},
		}

		filters := map[string]interface{}{
			"resource": "patients",
			"allowed":  true,
		}

		// Setup mock expectations
		mockAuditRepo.On("GetAuthorizationEvents", ctx, filters, 0, 10).Return(events, 2, nil)

		// Get authorization events
		result, total, err := auditService.GetAuthorizationEvents(ctx, filters, 0, 10)

		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, 2, total)

		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("search audit events", func(t *testing.T) {
		query := "doctor"
		eventType := "authorization"

		// Create test events
		events := []interface{}{
			&models.AuthorizationEvent{
				ID:       uuid.New(),
				UserID:   uuid.New(),
				Resource: "doctor_records",
				Action:   "read",
				Allowed:  true,
				Timestamp: time.Now(),
			},
		}

		// Setup mock expectations
		mockAuditRepo.On("SearchAuditEvents", ctx, query, eventType, 0, 10).Return(events, 1, nil)

		// Search audit events
		result, total, err := auditService.SearchAuditEvents(ctx, query, eventType, 0, 10)

		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, 1, total)

		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("search all audit events", func(t *testing.T) {
		query := "failed"
		eventType := "all"

		// Create test events
		events := []interface{}{
			&models.AuthenticationEvent{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				EventType: "login_failed",
				Success:   false,
				Timestamp: time.Now(),
			},
			&models.AuthorizationEvent{
				ID:       uuid.New(),
				UserID:   uuid.New(),
				Resource: "admin_panel",
				Action:   "access",
				Allowed:  false,
				Timestamp: time.Now(),
			},
		}

		// Setup mock expectations
		mockAuditRepo.On("SearchAuditEvents", ctx, query, eventType, 0, 10).Return(events, 2, nil)

		// Search audit events
		result, total, err := auditService.SearchAuditEvents(ctx, query, eventType, 0, 10)

		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, 2, total)

		mockAuditRepo.AssertExpectations(t)
	})
}

// TestAuditService_ComplianceReporting tests compliance reporting
func TestAuditService_ComplianceReporting(t *testing.T) {
	mockAuditRepo := new(MockAuditRepository)
	auditService := services.NewAuditService(mockAuditRepo)

	ctx := context.Background()

	t.Run("generate HIPAA compliance report", func(t *testing.T) {
		startDate := time.Now().AddDate(0, -1, 0) // 1 month ago
		endDate := time.Now()
		reportType := "hipaa"

		// Create test compliance report
		report := &services.ComplianceReport{
			ReportType:  "hipaa",
			StartDate:   startDate,
			EndDate:     endDate,
			TotalEvents: 150,
			Summary: map[string]interface{}{
				"authentication_events": 100,
				"authorization_events":  50,
				"failed_logins":         10,
				"access_denials":        5,
			},
			Details: []interface{}{
				&models.AuthenticationEvent{
					ID:        uuid.New(),
					UserID:    uuid.New(),
					EventType: "login_success",
					Success:   true,
					Timestamp: time.Now(),
				},
			},
		}

		// Setup mock expectations
		mockAuditRepo.On("GetComplianceReport", ctx, startDate, endDate, reportType).Return(report, nil)

		// Generate compliance report
		result, err := auditService.GenerateComplianceReport(ctx, startDate, endDate, reportType)

		require.NoError(t, err)
		assert.Equal(t, reportType, result.ReportType)
		assert.Equal(t, 150, result.TotalEvents)
		assert.Len(t, result.Details, 1)

		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("generate DISHA compliance report", func(t *testing.T) {
		startDate := time.Now().AddDate(0, -1, 0) // 1 month ago
		endDate := time.Now()
		reportType := "disha"

		// Create test compliance report
		report := &services.ComplianceReport{
			ReportType:  "disha",
			StartDate:   startDate,
			EndDate:     endDate,
			TotalEvents: 200,
			Summary: map[string]interface{}{
				"authentication_events": 120,
				"authorization_events":  80,
				"failed_logins":         15,
				"access_denials":        8,
			},
			Details: []interface{}{
				&models.AuthorizationEvent{
					ID:       uuid.New(),
					UserID:   uuid.New(),
					Resource: "patient_records",
					Action:   "read",
					Allowed:  true,
					Timestamp: time.Now(),
				},
			},
		}

		// Setup mock expectations
		mockAuditRepo.On("GetComplianceReport", ctx, startDate, endDate, reportType).Return(report, nil)

		// Generate compliance report
		result, err := auditService.GenerateComplianceReport(ctx, startDate, endDate, reportType)

		require.NoError(t, err)
		assert.Equal(t, reportType, result.ReportType)
		assert.Equal(t, 200, result.TotalEvents)
		assert.Len(t, result.Details, 1)

		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("generate ABDM compliance report", func(t *testing.T) {
		startDate := time.Now().AddDate(0, -1, 0) // 1 month ago
		endDate := time.Now()
		reportType := "abdm"

		// Create test compliance report
		report := &services.ComplianceReport{
			ReportType:  "abdm",
			StartDate:   startDate,
			EndDate:     endDate,
			TotalEvents: 180,
			Summary: map[string]interface{}{
				"authentication_events": 110,
				"authorization_events":  70,
				"failed_logins":         12,
				"access_denials":        6,
			},
			Details: []interface{}{
				&models.AuthenticationEvent{
					ID:        uuid.New(),
					UserID:    uuid.New(),
					EventType: "biometric_success",
					Success:   true,
					Timestamp: time.Now(),
				},
			},
		}

		// Setup mock expectations
		mockAuditRepo.On("GetComplianceReport", ctx, startDate, endDate, reportType).Return(report, nil)

		// Generate compliance report
		result, err := auditService.GenerateComplianceReport(ctx, startDate, endDate, reportType)

		require.NoError(t, err)
		assert.Equal(t, reportType, result.ReportType)
		assert.Equal(t, 180, result.TotalEvents)
		assert.Len(t, result.Details, 1)

		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("generate security audit report", func(t *testing.T) {
		startDate := time.Now().AddDate(0, -1, 0) // 1 month ago
		endDate := time.Now()
		reportType := "security"

		// Create test compliance report
		report := &services.ComplianceReport{
			ReportType:  "security",
			StartDate:   startDate,
			EndDate:     endDate,
			TotalEvents: 300,
			Summary: map[string]interface{}{
				"authentication_events": 180,
				"authorization_events":  120,
				"failed_logins":         25,
				"access_denials":        15,
				"suspicious_activities": 5,
			},
			Details: []interface{}{
				&models.AuthenticationEvent{
					ID:        uuid.New(),
					UserID:    uuid.New(),
					EventType: "login_failed",
					Success:   false,
					Timestamp: time.Now(),
				},
			},
		}

		// Setup mock expectations
		mockAuditRepo.On("GetComplianceReport", ctx, startDate, endDate, reportType).Return(report, nil)

		// Generate compliance report
		result, err := auditService.GenerateComplianceReport(ctx, startDate, endDate, reportType)

		require.NoError(t, err)
		assert.Equal(t, reportType, result.ReportType)
		assert.Equal(t, 300, result.TotalEvents)
		assert.Len(t, result.Details, 1)

		mockAuditRepo.AssertExpectations(t)
	})
}

// TestAuditService_AuditDataRetention tests audit data retention
func TestAuditService_AuditDataRetention(t *testing.T) {
	mockAuditRepo := new(MockAuditRepository)
	auditService := services.NewAuditService(mockAuditRepo)

	ctx := context.Background()

	t.Run("cleanup old audit data", func(t *testing.T) {
		retentionDays := 90

		// Setup mock expectations
		mockAuditRepo.On("CleanupOldAuditData", ctx, retentionDays).Return(nil)

		// Cleanup old audit data
		err := auditService.CleanupOldAuditData(ctx, retentionDays)

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("cleanup with different retention periods", func(t *testing.T) {
		testCases := []int{30, 60, 90, 180, 365}

		for _, retentionDays := range testCases {
			t.Run(fmt.Sprintf("retention_%d_days", retentionDays), func(t *testing.T) {
				// Setup mock expectations
				mockAuditRepo.On("CleanupOldAuditData", ctx, retentionDays).Return(nil)

				// Cleanup old audit data
				err := auditService.CleanupOldAuditData(ctx, retentionDays)

				require.NoError(t, err)
				mockAuditRepo.AssertExpectations(t)
			})
		}
	})

	t.Run("cleanup error handling", func(t *testing.T) {
		retentionDays := 90

		// Setup mock expectations
		mockAuditRepo.On("CleanupOldAuditData", ctx, retentionDays).Return(assert.AnError)

		// Cleanup old audit data
		err := auditService.CleanupOldAuditData(ctx, retentionDays)

		require.Error(t, err)
		mockAuditRepo.AssertExpectations(t)
	})
}

// TestAuditService_GetAuditEventByID tests getting audit events by ID
func TestAuditService_GetAuditEventByID(t *testing.T) {
	mockAuditRepo := new(MockAuditRepository)
	auditService := services.NewAuditService(mockAuditRepo)

	ctx := context.Background()

	t.Run("get authentication event by ID", func(t *testing.T) {
		eventID := uuid.New()
		eventType := "authentication"

		// Create test event
		event := &models.AuthenticationEvent{
			ID:        eventID,
			UserID:    uuid.New(),
			EventType: "login_success",
			IPAddress: "192.168.1.100",
			Success:   true,
			Timestamp: time.Now(),
		}

		// Setup mock expectations
		mockAuditRepo.On("GetAuditEventByID", ctx, eventID, eventType).Return(event, nil)

		// Get audit event by ID
		result, err := auditService.GetAuditEventByID(ctx, eventID, eventType)

		require.NoError(t, err)
		assert.Equal(t, eventID, result.(*models.AuthenticationEvent).ID)

		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("get authorization event by ID", func(t *testing.T) {
		eventID := uuid.New()
		eventType := "authorization"

		// Create test event
		event := &models.AuthorizationEvent{
			ID:       eventID,
			UserID:   uuid.New(),
			Resource: "patients",
			Action:   "read",
			Allowed:  true,
			Timestamp: time.Now(),
		}

		// Setup mock expectations
		mockAuditRepo.On("GetAuditEventByID", ctx, eventID, eventType).Return(event, nil)

		// Get audit event by ID
		result, err := auditService.GetAuditEventByID(ctx, eventID, eventType)

		require.NoError(t, err)
		assert.Equal(t, eventID, result.(*models.AuthorizationEvent).ID)

		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("get non-existent event", func(t *testing.T) {
		eventID := uuid.New()
		eventType := "authentication"

		// Setup mock expectations
		mockAuditRepo.On("GetAuditEventByID", ctx, eventID, eventType).Return(nil, assert.AnError)

		// Get audit event by ID
		result, err := auditService.GetAuditEventByID(ctx, eventID, eventType)

		require.Error(t, err)
		assert.Nil(t, result)

		mockAuditRepo.AssertExpectations(t)
	})
}

// TestAuditService_HealthcareSpecificFeatures tests healthcare-specific audit features
func TestAuditService_HealthcareSpecificFeatures(t *testing.T) {
	mockAuditRepo := new(MockAuditRepository)
	auditService := services.NewAuditService(mockAuditRepo)

	ctx := context.Background()

	t.Run("log patient data access", func(t *testing.T) {
		userID := uuid.New()
		patientID := uuid.New()
		resource := "patient_records"
		action := "read"
		context := map[string]interface{}{
			"patient_id":  patientID.String(),
			"facility_id": uuid.New().String(),
			"access_type": "clinical",
		}

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(nil)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  resource,
			Action:    action,
			Context:   context,
			Allowed:   true,
			Reason:    "doctor accessing patient records for clinical care",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log medication access", func(t *testing.T) {
		userID := uuid.New()
		resource := "medications"
		action := "prescribe"
		context := map[string]interface{}{
			"patient_id":  uuid.New().String(),
			"medication_id": uuid.New().String(),
			"facility_id": uuid.New().String(),
		}

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(nil)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  resource,
			Action:    action,
			Context:   context,
			Allowed:   true,
			Reason:    "doctor prescribing medication",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log emergency access", func(t *testing.T) {
		userID := uuid.New()
		resource := "emergency_records"
		action := "access"
		context := map[string]interface{}{
			"patient_id":  uuid.New().String(),
			"emergency_type": "cardiac_arrest",
			"facility_id": uuid.New().String(),
			"time_of_day": "after_hours",
		}

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(nil)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  resource,
			Action:    action,
			Context:   context,
			Allowed:   true,
			Reason:    "emergency access granted for patient care",
		})

		require.NoError(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("log healthcare compliance report", func(t *testing.T) {
		startDate := time.Now().AddDate(0, -1, 0) // 1 month ago
		endDate := time.Now()
		reportType := "healthcare_compliance"

		// Create test compliance report
		report := &services.ComplianceReport{
			ReportType:  "healthcare_compliance",
			StartDate:   startDate,
			EndDate:     endDate,
			TotalEvents: 500,
			Summary: map[string]interface{}{
				"patient_data_access":    200,
				"medication_access":      150,
				"emergency_access":       50,
				"clinical_notes_access": 100,
			},
			Details: []interface{}{
				&models.AuthorizationEvent{
					ID:       uuid.New(),
					UserID:   uuid.New(),
					Resource: "patient_records",
					Action:   "read",
					Allowed:  true,
					Timestamp: time.Now(),
				},
			},
		}

		// Setup mock expectations
		mockAuditRepo.On("GetComplianceReport", ctx, startDate, endDate, reportType).Return(report, nil)

		// Generate compliance report
		result, err := auditService.GenerateComplianceReport(ctx, startDate, endDate, reportType)

		require.NoError(t, err)
		assert.Equal(t, reportType, result.ReportType)
		assert.Equal(t, 500, result.TotalEvents)
		assert.Len(t, result.Details, 1)

		mockAuditRepo.AssertExpectations(t)
	})
}

// TestAuditService_ErrorHandling tests error handling scenarios
func TestAuditService_ErrorHandling(t *testing.T) {
	mockAuditRepo := new(MockAuditRepository)
	auditService := services.NewAuditService(mockAuditRepo)

	ctx := context.Background()

	t.Run("authentication event logging error", func(t *testing.T) {
		userID := uuid.New()

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthenticationEvent", ctx, mock.AnythingOfType("*models.AuthenticationEvent")).Return(assert.AnError)

		// Log authentication event
		err := auditService.LogAuthenticationEvent(ctx, &services.AuthenticationEventData{
			UserID:      userID,
			EventType:   "login_success",
			IPAddress:   "192.168.1.100",
			UserAgent:   "test-agent",
			Success:     true,
			FailureReason: "",
		})

		require.Error(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("authorization event logging error", func(t *testing.T) {
		userID := uuid.New()

		// Setup mock expectations
		mockAuditRepo.On("CreateAuthorizationEvent", ctx, mock.AnythingOfType("*models.AuthorizationEvent")).Return(assert.AnError)

		// Log authorization event
		err := auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
			UserID:    userID,
			Resource:  "patients",
			Action:    "read",
			Context:   map[string]interface{}{},
			Allowed:   true,
			Reason:    "test reason",
		})

		require.Error(t, err)
		mockAuditRepo.AssertExpectations(t)
	})

	t.Run("compliance report generation error", func(t *testing.T) {
		startDate := time.Now().AddDate(0, -1, 0)
		endDate := time.Now()
		reportType := "hipaa"

		// Setup mock expectations
		mockAuditRepo.On("GetComplianceReport", ctx, startDate, endDate, reportType).Return(nil, assert.AnError)

		// Generate compliance report
		result, err := auditService.GenerateComplianceReport(ctx, startDate, endDate, reportType)

		require.Error(t, err)
		assert.Nil(t, result)

		mockAuditRepo.AssertExpectations(t)
	})
} 