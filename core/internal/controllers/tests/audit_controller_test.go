package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/controllers"
	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"
)

// MockAuditService is a mock implementation of AuditService
type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) LogAuthenticationEvent(ctx context.Context, data *services.AuthenticationEventData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockAuditService) LogAuthorizationEvent(ctx context.Context, data *services.AuthorizationEventData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockAuditService) GetAuthenticationEvents(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]*models.AuthenticationEvent, int, error) {
	args := m.Called(ctx, filters, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.AuthenticationEvent), args.Int(1), args.Error(2)
}

func (m *MockAuditService) GetAuthorizationEvents(ctx context.Context, filters map[string]interface{}, offset, limit int) ([]*models.AuthorizationEvent, int, error) {
	args := m.Called(ctx, filters, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.AuthorizationEvent), args.Int(1), args.Error(2)
}

func (m *MockAuditService) SearchAuditEvents(ctx context.Context, query string, eventType string, offset, limit int) ([]interface{}, int, error) {
	args := m.Called(ctx, query, eventType, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]interface{}), args.Int(1), args.Error(2)
}

func (m *MockAuditService) GenerateComplianceReport(ctx context.Context, startDate, endDate time.Time, reportType string) (*services.ComplianceReport, error) {
	args := m.Called(ctx, startDate, endDate, reportType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.ComplianceReport), args.Error(1)
}

func (m *MockAuditService) CleanupOldAuditData(ctx context.Context, retentionDays int) error {
	args := m.Called(ctx, retentionDays)
	return args.Error(0)
}

func (m *MockAuditService) GetAuditEventByID(ctx context.Context, eventID uuid.UUID, eventType string) (interface{}, error) {
	args := m.Called(ctx, eventID, eventType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0), args.Error(1)
}

// TestAuditController_LogAuthenticationEvent tests authentication event logging
func TestAuditController_LogAuthenticationEvent(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("log successful login", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		requestBody := `{
			"user_id": "` + uuid.New().String() + `",
			"event_type": "login_success",
			"ip_address": "192.168.1.100",
			"user_agent": "Mozilla/5.0",
			"success": true
		}`

		c.Request = httptest.NewRequest("POST", "/audit/authentication", strings.NewReader(requestBody))
		c.Request.Header.Set("Content-Type", "application/json")

		mockAuditService.On("LogAuthenticationEvent", mock.Anything, mock.AnythingOfType("*services.AuthenticationEventData")).Return(nil)

		auditController.LogAuthenticationEvent(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})

	t.Run("log failed login", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		requestBody := `{
			"user_id": "` + uuid.New().String() + `",
			"event_type": "login_failed",
			"ip_address": "192.168.1.100",
			"user_agent": "Mozilla/5.0",
			"success": false,
			"failure_reason": "invalid_credentials"
		}`

		c.Request = httptest.NewRequest("POST", "/audit/authentication", strings.NewReader(requestBody))
		c.Request.Header.Set("Content-Type", "application/json")

		mockAuditService.On("LogAuthenticationEvent", mock.Anything, mock.AnythingOfType("*services.AuthenticationEventData")).Return(nil)

		auditController.LogAuthenticationEvent(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})
}

// TestAuditController_LogAuthorizationEvent tests authorization event logging
func TestAuditController_LogAuthorizationEvent(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("log permission granted", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		requestBody := `{
			"user_id": "` + uuid.New().String() + `",
			"resource": "patients",
			"action": "read",
			"allowed": true,
			"reason": "user has required permission"
		}`

		c.Request = httptest.NewRequest("POST", "/audit/authorization", strings.NewReader(requestBody))
		c.Request.Header.Set("Content-Type", "application/json")

		mockAuditService.On("LogAuthorizationEvent", mock.Anything, mock.AnythingOfType("*services.AuthorizationEventData")).Return(nil)

		auditController.LogAuthorizationEvent(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})

	t.Run("log permission denied", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		requestBody := `{
			"user_id": "` + uuid.New().String() + `",
			"resource": "admin_panel",
			"action": "access",
			"allowed": false,
			"reason": "insufficient permissions"
		}`

		c.Request = httptest.NewRequest("POST", "/audit/authorization", strings.NewReader(requestBody))
		c.Request.Header.Set("Content-Type", "application/json")

		mockAuditService.On("LogAuthorizationEvent", mock.Anything, mock.AnythingOfType("*services.AuthorizationEventData")).Return(nil)

		auditController.LogAuthorizationEvent(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})
}

// TestAuditController_GetAuthenticationEvents tests authentication event retrieval
func TestAuditController_GetAuthenticationEvents(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("get authentication events", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		events := []*models.AuthenticationEvent{
			{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				EventType: "login_success",
				Success:   true,
				Timestamp: time.Now(),
			},
		}

		c.Request = httptest.NewRequest("GET", "/audit/authentication?offset=0&limit=10", nil)

		mockAuditService.On("GetAuthenticationEvents", mock.Anything, mock.Anything, 0, 10).Return(events, 1, nil)

		auditController.GetAuthenticationEvents(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})
}

// TestAuditController_GetAuthorizationEvents tests authorization event retrieval
func TestAuditController_GetAuthorizationEvents(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("get authorization events", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		events := []*models.AuthorizationEvent{
			{
				ID:       uuid.New(),
				UserID:   uuid.New(),
				Resource: "patients",
				Action:   "read",
				Allowed:  true,
				Timestamp: time.Now(),
			},
		}

		c.Request = httptest.NewRequest("GET", "/audit/authorization?offset=0&limit=10", nil)

		mockAuditService.On("GetAuthorizationEvents", mock.Anything, mock.Anything, 0, 10).Return(events, 1, nil)

		auditController.GetAuthorizationEvents(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})
}

// TestAuditController_SearchAuditEvents tests audit event search
func TestAuditController_SearchAuditEvents(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("search audit events", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		events := []interface{}{
			&models.AuthenticationEvent{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				EventType: "login_success",
				Success:   true,
				Timestamp: time.Now(),
			},
		}

		c.Request = httptest.NewRequest("GET", "/audit/search?q=login&event_type=authentication&offset=0&limit=10", nil)

		mockAuditService.On("SearchAuditEvents", mock.Anything, "login", "authentication", 0, 10).Return(events, 1, nil)

		auditController.SearchAuditEvents(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})
}

// TestAuditController_GenerateComplianceReport tests compliance report generation
func TestAuditController_GenerateComplianceReport(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("generate HIPAA report", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		report := &services.ComplianceReport{
			ReportType:  "hipaa",
			StartDate:   time.Now().AddDate(0, -1, 0),
			EndDate:     time.Now(),
			TotalEvents: 150,
			Summary: map[string]interface{}{
				"authentication_events": 100,
				"authorization_events":  50,
			},
		}

		c.Request = httptest.NewRequest("GET", "/audit/compliance/hipaa?start_date=2024-01-01&end_date=2024-01-31", nil)

		mockAuditService.On("GenerateComplianceReport", mock.Anything, mock.Anything, mock.Anything, "hipaa").Return(report, nil)

		auditController.GenerateComplianceReport(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})
}

// TestAuditController_CleanupOldAuditData tests audit data cleanup
func TestAuditController_CleanupOldAuditData(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("cleanup old audit data", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		requestBody := `{
			"retention_days": 90
		}`

		c.Request = httptest.NewRequest("POST", "/audit/cleanup", strings.NewReader(requestBody))
		c.Request.Header.Set("Content-Type", "application/json")

		mockAuditService.On("CleanupOldAuditData", mock.Anything, 90).Return(nil)

		auditController.CleanupOldAuditData(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})
}

// TestAuditController_GetAuditEventByID tests getting audit event by ID
func TestAuditController_GetAuditEventByID(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("get authentication event by ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		eventID := uuid.New()
		event := &models.AuthenticationEvent{
			ID:        eventID,
			UserID:    uuid.New(),
			EventType: "login_success",
			Success:   true,
			Timestamp: time.Now(),
		}

		c.Request = httptest.NewRequest("GET", "/audit/events/authentication/"+eventID.String(), nil)

		mockAuditService.On("GetAuditEventByID", mock.Anything, eventID, "authentication").Return(event, nil)

		auditController.GetAuditEventByID(c)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuditService.AssertExpectations(t)
	})
}

// TestAuditController_ErrorHandling tests error handling scenarios
func TestAuditController_ErrorHandling(t *testing.T) {
	mockAuditService := new(MockAuditService)
	auditController := controllers.NewAuditController(mockAuditService)

	gin.SetMode(gin.TestMode)

	t.Run("invalid request body", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		requestBody := `{
			"invalid": "json"
		}`

		c.Request = httptest.NewRequest("POST", "/audit/authentication", strings.NewReader(requestBody))
		c.Request.Header.Set("Content-Type", "application/json")

		auditController.LogAuthenticationEvent(c)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		requestBody := `{
			"user_id": "` + uuid.New().String() + `",
			"event_type": "login_success",
			"ip_address": "192.168.1.100",
			"user_agent": "Mozilla/5.0",
			"success": true
		}`

		c.Request = httptest.NewRequest("POST", "/audit/authentication", strings.NewReader(requestBody))
		c.Request.Header.Set("Content-Type", "application/json")

		mockAuditService.On("LogAuthenticationEvent", mock.Anything, mock.AnythingOfType("*services.AuthenticationEventData")).Return(assert.AnError)

		auditController.LogAuthenticationEvent(c)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockAuditService.AssertExpectations(t)
	})
} 