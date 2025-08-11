package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/google/uuid"
)

// NotificationService provides notification functionality
type NotificationService struct {
	auditService services.AuditService
	httpClient   *http.Client
	config       *NotificationConfig
}

// NotificationConfig holds notification configuration
type NotificationConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMSProvider  string
	SMSAPIKey    string
	PushProvider string
	PushAPIKey   string
	WebhookURL   string
}

// NotificationType represents the type of notification
type NotificationType string

const (
	NotificationTypeEmail    NotificationType = "email"
	NotificationTypeSMS      NotificationType = "sms"
	NotificationTypePush     NotificationType = "push"
	NotificationTypeWebhook  NotificationType = "webhook"
	NotificationTypeInApp    NotificationType = "in_app"
)

// NotificationPriority represents the priority of a notification
type NotificationPriority string

const (
	NotificationPriorityLow      NotificationPriority = "low"
	NotificationPriorityNormal   NotificationPriority = "normal"
	NotificationPriorityHigh     NotificationPriority = "high"
	NotificationPriorityCritical NotificationPriority = "critical"
)

// NotificationStatus represents the status of a notification
type NotificationStatus string

const (
	NotificationStatusPending   NotificationStatus = "pending"
	NotificationStatusSent      NotificationStatus = "sent"
	NotificationStatusDelivered NotificationStatus = "delivered"
	NotificationStatusFailed    NotificationStatus = "failed"
	NotificationStatusRead      NotificationStatus = "read"
)

// Notification represents a notification
type Notification struct {
	ID          uuid.UUID           `json:"id"`
	Type        NotificationType    `json:"type"`
	Priority    NotificationPriority `json:"priority"`
	Status      NotificationStatus  `json:"status"`
	Recipient   string              `json:"recipient"`
	Subject     string              `json:"subject"`
	Message     string              `json:"message"`
	Template    string              `json:"template"`
	Data        map[string]interface{} `json:"data"`
	CreatedAt   time.Time           `json:"created_at"`
	SentAt      *time.Time          `json:"sent_at,omitempty"`
	DeliveredAt *time.Time          `json:"delivered_at,omitempty"`
	ReadAt      *time.Time          `json:"read_at,omitempty"`
	RetryCount  int                 `json:"retry_count"`
	MaxRetries  int                 `json:"max_retries"`
	Error       string              `json:"error,omitempty"`
}

// HealthcareNotificationType represents healthcare-specific notification types
type HealthcareNotificationType string

const (
	HealthcareNotificationAppointmentReminder    HealthcareNotificationType = "appointment_reminder"
	HealthcareNotificationTestResults            HealthcareNotificationType = "test_results"
	HealthcareNotificationMedicationReminder     HealthcareNotificationType = "medication_reminder"
	HealthcareNotificationEmergencyAlert         HealthcareNotificationType = "emergency_alert"
	HealthcareNotificationHealthUpdate           HealthcareNotificationType = "health_update"
	HealthcareNotificationInsuranceUpdate        HealthcareNotificationType = "insurance_update"
	HealthcareNotificationBillingReminder        HealthcareNotificationType = "billing_reminder"
	HealthcareNotificationVaccinationReminder    HealthcareNotificationType = "vaccination_reminder"
	HealthcareNotificationFollowUpReminder       HealthcareNotificationType = "follow_up_reminder"
	HealthcareNotificationPrescriptionReady      HealthcareNotificationType = "prescription_ready"
)

// NewNotificationService creates a new notification service
func NewNotificationService(auditService services.AuditService, config *NotificationConfig) *NotificationService {
	return &NotificationService{
		auditService: auditService,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		config:       config,
	}
}

// SendNotification sends a notification
func (s *NotificationService) SendNotification(ctx context.Context, notification *Notification) error {
	// Validate notification
	if err := s.validateNotification(notification); err != nil {
		return fmt.Errorf("invalid notification: %w", err)
	}

	// Set default values
	if notification.ID == uuid.Nil {
		notification.ID = uuid.New()
	}
	if notification.CreatedAt.IsZero() {
		notification.CreatedAt = time.Now()
	}
	if notification.Status == "" {
		notification.Status = NotificationStatusPending
	}
	if notification.MaxRetries == 0 {
		notification.MaxRetries = 3
	}

	// Send notification based on type
	var err error
	switch notification.Type {
	case NotificationTypeEmail:
		err = s.sendEmailNotification(ctx, notification)
	case NotificationTypeSMS:
		err = s.sendSMSNotification(ctx, notification)
	case NotificationTypePush:
		err = s.sendPushNotification(ctx, notification)
	case NotificationTypeWebhook:
		err = s.sendWebhookNotification(ctx, notification)
	case NotificationTypeInApp:
		err = s.sendInAppNotification(ctx, notification)
	default:
		return fmt.Errorf("unsupported notification type: %s", notification.Type)
	}

	// Update notification status
	if err != nil {
		notification.Status = NotificationStatusFailed
		notification.Error = err.Error()
		notification.RetryCount++
	} else {
		now := time.Now()
		notification.Status = NotificationStatusSent
		notification.SentAt = &now
	}

	// Log notification event
	s.logNotificationEvent(ctx, notification)

	return err
}

// SendHealthcareNotification sends a healthcare-specific notification
func (s *NotificationService) SendHealthcareNotification(ctx context.Context, notificationType HealthcareNotificationType, recipient string, data map[string]interface{}) error {
	// Create notification based on type
	notification := s.createHealthcareNotification(notificationType, recipient, data)
	
	return s.SendNotification(ctx, notification)
}

// SendAppointmentReminder sends an appointment reminder notification
func (s *NotificationService) SendAppointmentReminder(ctx context.Context, recipient string, appointmentData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationAppointmentReminder, recipient, appointmentData)
}

// SendTestResults sends test results notification
func (s *NotificationService) SendTestResults(ctx context.Context, recipient string, testData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationTestResults, recipient, testData)
}

// SendMedicationReminder sends a medication reminder notification
func (s *NotificationService) SendMedicationReminder(ctx context.Context, recipient string, medicationData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationMedicationReminder, recipient, medicationData)
}

// SendEmergencyAlert sends an emergency alert notification
func (s *NotificationService) SendEmergencyAlert(ctx context.Context, recipient string, emergencyData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationEmergencyAlert, recipient, emergencyData)
}

// SendHealthUpdate sends a health update notification
func (s *NotificationService) SendHealthUpdate(ctx context.Context, recipient string, healthData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationHealthUpdate, recipient, healthData)
}

// SendBillingReminder sends a billing reminder notification
func (s *NotificationService) SendBillingReminder(ctx context.Context, recipient string, billingData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationBillingReminder, recipient, billingData)
}

// SendVaccinationReminder sends a vaccination reminder notification
func (s *NotificationService) SendVaccinationReminder(ctx context.Context, recipient string, vaccinationData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationVaccinationReminder, recipient, vaccinationData)
}

// SendFollowUpReminder sends a follow-up reminder notification
func (s *NotificationService) SendFollowUpReminder(ctx context.Context, recipient string, followUpData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationFollowUpReminder, recipient, followUpData)
}

// SendPrescriptionReady sends a prescription ready notification
func (s *NotificationService) SendPrescriptionReady(ctx context.Context, recipient string, prescriptionData map[string]interface{}) error {
	return s.SendHealthcareNotification(ctx, HealthcareNotificationPrescriptionReady, recipient, prescriptionData)
}

// SendBulkNotifications sends multiple notifications
func (s *NotificationService) SendBulkNotifications(ctx context.Context, notifications []*Notification) error {
	var errors []error
	
	for _, notification := range notifications {
		if err := s.SendNotification(ctx, notification); err != nil {
			errors = append(errors, fmt.Errorf("failed to send notification %s: %w", notification.ID, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("bulk notification errors: %v", errors)
	}
	
	return nil
}

// RetryFailedNotifications retries failed notifications
func (s *NotificationService) RetryFailedNotifications(ctx context.Context) error {
	// This would typically query a database for failed notifications
	// For now, we'll return a placeholder implementation
	return nil
}

// GetNotificationStatus gets the status of a notification
func (s *NotificationService) GetNotificationStatus(ctx context.Context, notificationID uuid.UUID) (*Notification, error) {
	// This would typically query a database
	// For now, we'll return a placeholder implementation
	return nil, fmt.Errorf("not implemented")
}

// MarkNotificationAsRead marks a notification as read
func (s *NotificationService) MarkNotificationAsRead(ctx context.Context, notificationID uuid.UUID) error {
	// This would typically update a database
	// For now, we'll return a placeholder implementation
	return nil
}

// Helper methods

// validateNotification validates a notification
func (s *NotificationService) validateNotification(notification *Notification) error {
	if notification.Recipient == "" {
		return fmt.Errorf("recipient is required")
	}
	if notification.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if notification.Message == "" {
		return fmt.Errorf("message is required")
	}
	if notification.Type == "" {
		return fmt.Errorf("type is required")
	}
	
	return nil
}

// createHealthcareNotification creates a healthcare-specific notification
func (s *NotificationService) createHealthcareNotification(notificationType HealthcareNotificationType, recipient string, data map[string]interface{}) *Notification {
	notification := &Notification{
		Type:      NotificationTypeEmail, // Default to email
		Priority:  NotificationPriorityNormal,
		Recipient: recipient,
		Data:      data,
	}

	switch notificationType {
	case HealthcareNotificationAppointmentReminder:
		notification.Subject = "Appointment Reminder"
		notification.Message = s.generateAppointmentReminderMessage(data)
		notification.Template = "appointment_reminder"
		notification.Priority = NotificationPriorityNormal

	case HealthcareNotificationTestResults:
		notification.Subject = "Test Results Available"
		notification.Message = s.generateTestResultsMessage(data)
		notification.Template = "test_results"
		notification.Priority = NotificationPriorityHigh

	case HealthcareNotificationMedicationReminder:
		notification.Subject = "Medication Reminder"
		notification.Message = s.generateMedicationReminderMessage(data)
		notification.Template = "medication_reminder"
		notification.Priority = NotificationPriorityHigh

	case HealthcareNotificationEmergencyAlert:
		notification.Subject = "Emergency Alert"
		notification.Message = s.generateEmergencyAlertMessage(data)
		notification.Template = "emergency_alert"
		notification.Priority = NotificationPriorityCritical

	case HealthcareNotificationHealthUpdate:
		notification.Subject = "Health Update"
		notification.Message = s.generateHealthUpdateMessage(data)
		notification.Template = "health_update"
		notification.Priority = NotificationPriorityNormal

	case HealthcareNotificationBillingReminder:
		notification.Subject = "Billing Reminder"
		notification.Message = s.generateBillingReminderMessage(data)
		notification.Template = "billing_reminder"
		notification.Priority = NotificationPriorityNormal

	case HealthcareNotificationVaccinationReminder:
		notification.Subject = "Vaccination Reminder"
		notification.Message = s.generateVaccinationReminderMessage(data)
		notification.Template = "vaccination_reminder"
		notification.Priority = NotificationPriorityNormal

	case HealthcareNotificationFollowUpReminder:
		notification.Subject = "Follow-up Reminder"
		notification.Message = s.generateFollowUpReminderMessage(data)
		notification.Template = "follow_up_reminder"
		notification.Priority = NotificationPriorityNormal

	case HealthcareNotificationPrescriptionReady:
		notification.Subject = "Prescription Ready"
		notification.Message = s.generatePrescriptionReadyMessage(data)
		notification.Template = "prescription_ready"
		notification.Priority = NotificationPriorityNormal
	}

	return notification
}

// Message generation methods

func (s *NotificationService) generateAppointmentReminderMessage(data map[string]interface{}) string {
	// This would use a template engine to generate the message
	return fmt.Sprintf("Reminder: You have an appointment scheduled for %s at %s", 
		data["date"], data["time"])
}

func (s *NotificationService) generateTestResultsMessage(data map[string]interface{}) string {
	return fmt.Sprintf("Your test results for %s are now available. Please log in to your patient portal to view them.", 
		data["test_name"])
}

func (s *NotificationService) generateMedicationReminderMessage(data map[string]interface{}) string {
	return fmt.Sprintf("Reminder: Please take %s %s as prescribed by your doctor.", 
		data["medication_name"], data["dosage"])
}

func (s *NotificationService) generateEmergencyAlertMessage(data map[string]interface{}) string {
	return fmt.Sprintf("EMERGENCY ALERT: %s. Please contact emergency services immediately.", 
		data["alert_message"])
}

func (s *NotificationService) generateHealthUpdateMessage(data map[string]interface{}) string {
	return fmt.Sprintf("Health Update: %s", data["update_message"])
}

func (s *NotificationService) generateBillingReminderMessage(data map[string]interface{}) string {
	return fmt.Sprintf("Billing Reminder: You have an outstanding balance of %s. Please log in to your patient portal to make a payment.", 
		data["amount"])
}

func (s *NotificationService) generateVaccinationReminderMessage(data map[string]interface{}) string {
	return fmt.Sprintf("Vaccination Reminder: You are due for %s. Please schedule an appointment.", 
		data["vaccination_name"])
}

func (s *NotificationService) generateFollowUpReminderMessage(data map[string]interface{}) string {
	return fmt.Sprintf("Follow-up Reminder: Please schedule a follow-up appointment for %s.", 
		data["condition"])
}

func (s *NotificationService) generatePrescriptionReadyMessage(data map[string]interface{}) string {
	return fmt.Sprintf("Your prescription for %s is ready for pickup at %s.", 
		data["medication_name"], data["pharmacy_name"])
}

// Notification sending methods

func (s *NotificationService) sendEmailNotification(ctx context.Context, notification *Notification) error {
	// This would integrate with an email service (SMTP, SendGrid, etc.)
	// For now, we'll return a placeholder implementation
	return nil
}

func (s *NotificationService) sendSMSNotification(ctx context.Context, notification *Notification) error {
	// This would integrate with an SMS service (Twilio, AWS SNS, etc.)
	// For now, we'll return a placeholder implementation
	return nil
}

func (s *NotificationService) sendPushNotification(ctx context.Context, notification *Notification) error {
	// This would integrate with a push notification service (FCM, APNS, etc.)
	// For now, we'll return a placeholder implementation
	return nil
}

func (s *NotificationService) sendWebhookNotification(ctx context.Context, notification *Notification) error {
	// This would send a webhook to a configured URL
	// For now, we'll return a placeholder implementation
	return nil
}

func (s *NotificationService) sendInAppNotification(ctx context.Context, notification *Notification) error {
	// This would store the notification in a database for in-app display
	// For now, we'll return a placeholder implementation
	return nil
}

// logNotificationEvent logs notification events for audit
func (s *NotificationService) logNotificationEvent(ctx context.Context, notification *Notification) {
	// Log notification event for audit purposes
	// This would typically log to the audit service
	_ = notification
} 