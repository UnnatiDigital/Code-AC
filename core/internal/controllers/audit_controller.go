package controllers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuditController handles audit-related HTTP requests
type AuditController struct {
	auditService services.AuditService
}

// NewAuditController creates a new audit controller
func NewAuditController(auditService services.AuditService) *AuditController {
	return &AuditController{
		auditService: auditService,
	}
}

// LogAuthenticationEventRequest represents the authentication event logging request
type LogAuthenticationEventRequest struct {
	UserID        string                 `json:"user_id" binding:"required"`
	EventType     string                 `json:"event_type" binding:"required"`
	IPAddress     string                 `json:"ip_address" binding:"required"`
	UserAgent     string                 `json:"user_agent" binding:"required"`
	Success       bool                   `json:"success"`
	FailureReason string                 `json:"failure_reason,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty"`
}

// LogAuthenticationEventResponse represents the authentication event logging response
type LogAuthenticationEventResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// LogAuthorizationEventRequest represents the authorization event logging request
type LogAuthorizationEventRequest struct {
	UserID   string                 `json:"user_id" binding:"required"`
	Resource string                 `json:"resource" binding:"required"`
	Action   string                 `json:"action" binding:"required"`
	Context  map[string]interface{} `json:"context,omitempty"`
	Allowed  bool                   `json:"allowed"`
	Reason   string                 `json:"reason" binding:"required"`
}

// LogAuthorizationEventResponse represents the authorization event logging response
type LogAuthorizationEventResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// GetAuthenticationEventsResponse represents the authentication events response
type GetAuthenticationEventsResponse struct {
	Success bool                    `json:"success"`
	Events  []interface{}           `json:"events"`
	Total   int                     `json:"total"`
	Offset  int                     `json:"offset"`
	Limit   int                     `json:"limit"`
	Error   string                  `json:"error,omitempty"`
	ErrorCode string                `json:"error_code,omitempty"`
}

// GetAuthorizationEventsResponse represents the authorization events response
type GetAuthorizationEventsResponse struct {
	Success bool                    `json:"success"`
	Events  []interface{}           `json:"events"`
	Total   int                     `json:"total"`
	Offset  int                     `json:"offset"`
	Limit   int                     `json:"limit"`
	Error   string                  `json:"error,omitempty"`
	ErrorCode string                `json:"error_code,omitempty"`
}

// SearchAuditEventsResponse represents the audit events search response
type SearchAuditEventsResponse struct {
	Success bool                    `json:"success"`
	Events  []interface{}           `json:"events"`
	Total   int                     `json:"total"`
	Query   string                  `json:"query"`
	Offset  int                     `json:"offset"`
	Limit   int                     `json:"limit"`
	Error   string                  `json:"error,omitempty"`
	ErrorCode string                `json:"error_code,omitempty"`
}

// GenerateComplianceReportResponse represents the compliance report response
type GenerateComplianceReportResponse struct {
	Success bool                    `json:"success"`
	Report  *services.ComplianceReport `json:"report,omitempty"`
	Error   string                  `json:"error,omitempty"`
	ErrorCode string                `json:"error_code,omitempty"`
}

// CleanupOldAuditDataRequest represents the audit data cleanup request
type CleanupOldAuditDataRequest struct {
	RetentionDays int `json:"retention_days" binding:"required,min=1,max=3650"`
}

// CleanupOldAuditDataResponse represents the audit data cleanup response
type CleanupOldAuditDataResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// GetAuditEventByIDResponse represents the audit event by ID response
type GetAuditEventByIDResponse struct {
	Success bool        `json:"success"`
	Event   interface{} `json:"event,omitempty"`
	Error   string      `json:"error,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
}

// LogAuthenticationEvent handles authentication event logging requests
func (c *AuditController) LogAuthenticationEvent(ctx *gin.Context) {
	var req LogAuthenticationEventRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, LogAuthenticationEventResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse user ID
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, LogAuthenticationEventResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Log authentication event
	err = c.auditService.LogAuthenticationEvent(ctx, &services.AuthenticationEventData{
		UserID:        userID,
		EventType:     req.EventType,
		IPAddress:     req.IPAddress,
		UserAgent:     req.UserAgent,
		Success:       req.Success,
		FailureReason: req.FailureReason,
		Context:       req.Context,
	})

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, LogAuthenticationEventResponse{
			Success:   false,
			Error:     "failed to log authentication event",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, LogAuthenticationEventResponse{
		Success: true,
		Message: "Authentication event logged successfully",
	})
}

// LogAuthorizationEvent handles authorization event logging requests
func (c *AuditController) LogAuthorizationEvent(ctx *gin.Context) {
	var req LogAuthorizationEventRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, LogAuthorizationEventResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse user ID
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, LogAuthorizationEventResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Log authorization event
	err = c.auditService.LogAuthorizationEvent(ctx, &services.AuthorizationEventData{
		UserID:   userID,
		Resource: req.Resource,
		Action:   req.Action,
		Context:  req.Context,
		Allowed:  req.Allowed,
		Reason:   req.Reason,
	})

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, LogAuthorizationEventResponse{
			Success:   false,
			Error:     "failed to log authorization event",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, LogAuthorizationEventResponse{
		Success: true,
		Message: "Authorization event logged successfully",
	})
}

// GetAuthenticationEvents handles authentication events retrieval requests
func (c *AuditController) GetAuthenticationEvents(ctx *gin.Context) {
	// Parse query parameters
	offsetStr := ctx.DefaultQuery("offset", "0")
	limitStr := ctx.DefaultQuery("limit", "10")
	eventType := ctx.Query("event_type")
	success := ctx.Query("success")
	userID := ctx.Query("user_id")

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 10
	}

	// Build filters
	filters := make(map[string]interface{})
	if eventType != "" {
		filters["event_type"] = eventType
	}
	if success != "" {
		if success == "true" {
			filters["success"] = true
		} else if success == "false" {
			filters["success"] = false
		}
	}
	if userID != "" {
		if parsedUserID, err := uuid.Parse(userID); err == nil {
			filters["user_id"] = parsedUserID
		}
	}

	// Get authentication events
	events, total, err := c.auditService.GetAuthenticationEvents(ctx, filters, offset, limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, GetAuthenticationEventsResponse{
			Success:   false,
			Error:     "failed to get authentication events",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	// Convert events to interface slice
	eventInterfaces := make([]interface{}, len(events))
	for i, event := range events {
		eventInterfaces[i] = event
	}

	ctx.JSON(http.StatusOK, GetAuthenticationEventsResponse{
		Success: true,
		Events:  eventInterfaces,
		Total:   total,
		Offset:  offset,
		Limit:   limit,
	})
}

// GetAuthorizationEvents handles authorization events retrieval requests
func (c *AuditController) GetAuthorizationEvents(ctx *gin.Context) {
	// Parse query parameters
	offsetStr := ctx.DefaultQuery("offset", "0")
	limitStr := ctx.DefaultQuery("limit", "10")
	resource := ctx.Query("resource")
	action := ctx.Query("action")
	allowed := ctx.Query("allowed")
	userID := ctx.Query("user_id")

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 10
	}

	// Build filters
	filters := make(map[string]interface{})
	if resource != "" {
		filters["resource"] = resource
	}
	if action != "" {
		filters["action"] = action
	}
	if allowed != "" {
		if allowed == "true" {
			filters["allowed"] = true
		} else if allowed == "false" {
			filters["allowed"] = false
		}
	}
	if userID != "" {
		if parsedUserID, err := uuid.Parse(userID); err == nil {
			filters["user_id"] = parsedUserID
		}
	}

	// Get authorization events
	events, total, err := c.auditService.GetAuthorizationEvents(ctx, filters, offset, limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, GetAuthorizationEventsResponse{
			Success:   false,
			Error:     "failed to get authorization events",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	// Convert events to interface slice
	eventInterfaces := make([]interface{}, len(events))
	for i, event := range events {
		eventInterfaces[i] = event
	}

	ctx.JSON(http.StatusOK, GetAuthorizationEventsResponse{
		Success: true,
		Events:  eventInterfaces,
		Total:   total,
		Offset:  offset,
		Limit:   limit,
	})
}

// SearchAuditEvents handles audit events search requests
func (c *AuditController) SearchAuditEvents(ctx *gin.Context) {
	// Parse query parameters
	query := ctx.Query("q")
	if query == "" {
		ctx.JSON(http.StatusBadRequest, SearchAuditEventsResponse{
			Success:   false,
			Error:     "search query is required",
			ErrorCode: "MISSING_QUERY",
		})
		return
	}

	eventType := ctx.DefaultQuery("event_type", "all")
	offsetStr := ctx.DefaultQuery("offset", "0")
	limitStr := ctx.DefaultQuery("limit", "10")

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 10
	}

	// Search audit events
	events, total, err := c.auditService.SearchAuditEvents(ctx, query, eventType, offset, limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, SearchAuditEventsResponse{
			Success:   false,
			Error:     "failed to search audit events",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, SearchAuditEventsResponse{
		Success: true,
		Events:  events,
		Total:   total,
		Query:   query,
		Offset:  offset,
		Limit:   limit,
	})
}

// GenerateComplianceReport handles compliance report generation requests
func (c *AuditController) GenerateComplianceReport(ctx *gin.Context) {
	// Get report type from URL parameter
	reportType := ctx.Param("type")
	if reportType == "" {
		ctx.JSON(http.StatusBadRequest, GenerateComplianceReportResponse{
			Success:   false,
			Error:     "report type is required",
			ErrorCode: "MISSING_REPORT_TYPE",
		})
		return
	}

	// Parse date parameters
	startDateStr := ctx.DefaultQuery("start_date", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endDateStr := ctx.DefaultQuery("end_date", time.Now().Format("2006-01-02"))

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, GenerateComplianceReportResponse{
			Success:   false,
			Error:     "invalid start date format, expected YYYY-MM-DD",
			ErrorCode: "INVALID_START_DATE",
		})
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, GenerateComplianceReportResponse{
			Success:   false,
			Error:     "invalid end date format, expected YYYY-MM-DD",
			ErrorCode: "INVALID_END_DATE",
		})
		return
	}

	// Generate compliance report
	report, err := c.auditService.GenerateComplianceReport(ctx, startDate, endDate, reportType)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, GenerateComplianceReportResponse{
			Success:   false,
			Error:     "failed to generate compliance report",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, GenerateComplianceReportResponse{
		Success: true,
		Report:  report,
	})
}

// CleanupOldAuditData handles audit data cleanup requests
func (c *AuditController) CleanupOldAuditData(ctx *gin.Context) {
	var req CleanupOldAuditDataRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, CleanupOldAuditDataResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Cleanup old audit data
	err := c.auditService.CleanupOldAuditData(ctx, req.RetentionDays)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, CleanupOldAuditDataResponse{
			Success:   false,
			Error:     "failed to cleanup old audit data",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, CleanupOldAuditDataResponse{
		Success: true,
		Message: "Old audit data cleaned up successfully",
	})
}

// GetAuditEventByID handles audit event retrieval by ID requests
func (c *AuditController) GetAuditEventByID(ctx *gin.Context) {
	// Get event ID and type from URL parameters
	eventIDStr := ctx.Param("id")
	eventType := ctx.Param("type")

	if eventIDStr == "" {
		ctx.JSON(http.StatusBadRequest, GetAuditEventByIDResponse{
			Success:   false,
			Error:     "event ID is required",
			ErrorCode: "MISSING_EVENT_ID",
		})
		return
	}

	if eventType == "" {
		ctx.JSON(http.StatusBadRequest, GetAuditEventByIDResponse{
			Success:   false,
			Error:     "event type is required",
			ErrorCode: "MISSING_EVENT_TYPE",
		})
		return
	}

	// Parse event ID
	eventID, err := uuid.Parse(eventIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, GetAuditEventByIDResponse{
			Success:   false,
			Error:     "invalid event ID format",
			ErrorCode: "INVALID_EVENT_ID",
		})
		return
	}

	// Get audit event by ID
	event, err := c.auditService.GetAuditEventByID(ctx, eventID, eventType)
	if err != nil {
		ctx.JSON(http.StatusNotFound, GetAuditEventByIDResponse{
			Success:   false,
			Error:     "audit event not found",
			ErrorCode: "EVENT_NOT_FOUND",
		})
		return
	}

	ctx.JSON(http.StatusOK, GetAuditEventByIDResponse{
		Success: true,
		Event:   event,
	})
}

// GetAuditSummary handles audit summary requests
func (c *AuditController) GetAuditSummary(ctx *gin.Context) {
	// Parse date parameters
	startDateStr := ctx.DefaultQuery("start_date", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endDateStr := ctx.DefaultQuery("end_date", time.Now().Format("2006-01-02"))

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"success":    false,
			"error":      "invalid start date format, expected YYYY-MM-DD",
			"error_code": "INVALID_START_DATE",
		})
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"success":    false,
			"error":      "invalid end date format, expected YYYY-MM-DD",
			"error_code": "INVALID_END_DATE",
		})
		return
	}

	// Get audit summary
	summary, err := c.auditService.GetAuditSummary(ctx, startDate, endDate)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success":    false,
			"error":      "failed to get audit summary",
			"error_code": "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"success": true,
		"summary": summary,
	})
}

// ExportAuditData handles audit data export requests
func (c *AuditController) ExportAuditData(ctx *gin.Context) {
	// Parse date parameters
	startDateStr := ctx.DefaultQuery("start_date", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endDateStr := ctx.DefaultQuery("end_date", time.Now().Format("2006-01-02"))
	format := ctx.DefaultQuery("format", "json")

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"success":    false,
			"error":      "invalid start date format, expected YYYY-MM-DD",
			"error_code": "INVALID_START_DATE",
		})
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"success":    false,
			"error":      "invalid end date format, expected YYYY-MM-DD",
			"error_code": "INVALID_END_DATE",
		})
		return
	}

	// Export audit data
	data, err := c.auditService.ExportAuditData(ctx, startDate, endDate, format)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success":    false,
			"error":      "failed to export audit data",
			"error_code": "SERVICE_ERROR",
		})
		return
	}

	// Set response headers for file download
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("Content-Disposition", "attachment; filename=audit_data_"+startDate.Format("2006-01-02")+"_to_"+endDate.Format("2006-01-02")+"."+format)
	ctx.Data(http.StatusOK, "application/octet-stream", data)
}

// ValidateAuditData handles audit data validation requests
func (c *AuditController) ValidateAuditData(ctx *gin.Context) {
	// Parse date parameters
	startDateStr := ctx.DefaultQuery("start_date", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endDateStr := ctx.DefaultQuery("end_date", time.Now().Format("2006-01-02"))

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"success":    false,
			"error":      "invalid start date format, expected YYYY-MM-DD",
			"error_code": "INVALID_START_DATE",
		})
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"success":    false,
			"error":      "invalid end date format, expected YYYY-MM-DD",
			"error_code": "INVALID_END_DATE",
		})
		return
	}

	// Validate audit data
	validation, err := c.auditService.ValidateAuditData(ctx, startDate, endDate)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success":    false,
			"error":      "failed to validate audit data",
			"error_code": "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"success":    true,
		"validation": validation,
	})
} 