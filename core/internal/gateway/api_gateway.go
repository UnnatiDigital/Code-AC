package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/bmad-method/hmis-core/internal/cache"
	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// APIGateway provides API gateway functionality
type APIGateway struct {
	authService    services.AuthenticationService
	authzService   services.AuthorizationService
	auditService   services.AuditService
	redisCache     *cache.RedisCache
	serviceRoutes  map[string]*ServiceRoute
	healthChecker  *HealthChecker
}

// ServiceRoute defines a service route configuration
type ServiceRoute struct {
	Name           string
	UpstreamURL    string
	HealthCheckURL string
	Weight         int
	Timeout        time.Duration
	Retries        int
	CircuitBreaker *CircuitBreaker
}

// CircuitBreaker provides circuit breaker functionality
type CircuitBreaker struct {
	FailureThreshold int
	RecoveryTimeout  time.Duration
	FailureCount     int
	LastFailureTime  time.Time
	State            CircuitBreakerState
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState string

const (
	CircuitBreakerClosed   CircuitBreakerState = "closed"
	CircuitBreakerOpen     CircuitBreakerState = "open"
	CircuitBreakerHalfOpen CircuitBreakerState = "half_open"
)

// HealthChecker provides health checking functionality
type HealthChecker struct {
	checkInterval time.Duration
	timeout       time.Duration
}

// NewAPIGateway creates a new API gateway
func NewAPIGateway(authService services.AuthenticationService, authzService services.AuthorizationService, auditService services.AuditService, redisCache *cache.RedisCache) *APIGateway {
	gateway := &APIGateway{
		authService:   authService,
		authzService:  authzService,
		auditService:  auditService,
		redisCache:    redisCache,
		serviceRoutes: make(map[string]*ServiceRoute),
		healthChecker: &HealthChecker{
			checkInterval: 30 * time.Second,
			timeout:       5 * time.Second,
		},
	}

	// Initialize service routes
	gateway.initializeServiceRoutes()

	return gateway
}

// initializeServiceRoutes initializes the service routes
func (g *APIGateway) initializeServiceRoutes() {
	// Patient Management Service
	g.serviceRoutes["patient"] = &ServiceRoute{
		Name:           "patient-service",
		UpstreamURL:    "http://patient-service:8081",
		HealthCheckURL: "http://patient-service:8081/health",
		Weight:         1,
		Timeout:        30 * time.Second,
		Retries:        3,
		CircuitBreaker: &CircuitBreaker{
			FailureThreshold: 5,
			RecoveryTimeout:  60 * time.Second,
			State:            CircuitBreakerClosed,
		},
	}

	// Medical Records Service
	g.serviceRoutes["medical"] = &ServiceRoute{
		Name:           "medical-service",
		UpstreamURL:    "http://medical-service:8082",
		HealthCheckURL: "http://medical-service:8082/health",
		Weight:         1,
		Timeout:        30 * time.Second,
		Retries:        3,
		CircuitBreaker: &CircuitBreaker{
			FailureThreshold: 5,
			RecoveryTimeout:  60 * time.Second,
			State:            CircuitBreakerClosed,
		},
	}

	// Pharmacy Service
	g.serviceRoutes["pharmacy"] = &ServiceRoute{
		Name:           "pharmacy-service",
		UpstreamURL:    "http://pharmacy-service:8083",
		HealthCheckURL: "http://pharmacy-service:8083/health",
		Weight:         1,
		Timeout:        30 * time.Second,
		Retries:        3,
		CircuitBreaker: &CircuitBreaker{
			FailureThreshold: 5,
			RecoveryTimeout:  60 * time.Second,
			State:            CircuitBreakerClosed,
		},
	}

	// Laboratory Service
	g.serviceRoutes["lab"] = &ServiceRoute{
		Name:           "lab-service",
		UpstreamURL:    "http://lab-service:8084",
		HealthCheckURL: "http://lab-service:8084/health",
		Weight:         1,
		Timeout:        30 * time.Second,
		Retries:        3,
		CircuitBreaker: &CircuitBreaker{
			FailureThreshold: 5,
			RecoveryTimeout:  60 * time.Second,
			State:            CircuitBreakerClosed,
		},
	}

	// Billing Service
	g.serviceRoutes["billing"] = &ServiceRoute{
		Name:           "billing-service",
		UpstreamURL:    "http://billing-service:8085",
		HealthCheckURL: "http://billing-service:8085/health",
		Weight:         1,
		Timeout:        30 * time.Second,
		Retries:        3,
		CircuitBreaker: &CircuitBreaker{
			FailureThreshold: 5,
			RecoveryTimeout:  60 * time.Second,
			State:            CircuitBreakerClosed,
		},
	}

	// Notification Service
	g.serviceRoutes["notification"] = &ServiceRoute{
		Name:           "notification-service",
		UpstreamURL:    "http://notification-service:8086",
		HealthCheckURL: "http://notification-service:8086/health",
		Weight:         1,
		Timeout:        30 * time.Second,
		Retries:        3,
		CircuitBreaker: &CircuitBreaker{
			FailureThreshold: 5,
			RecoveryTimeout:  60 * time.Second,
			State:            CircuitBreakerClosed,
		},
	}
}

// SetupRoutes sets up the API gateway routes
func (g *APIGateway) SetupRoutes(router *gin.Engine) {
	// Health check endpoint
	router.GET("/health", g.healthCheckHandler)

	// Service discovery endpoint
	router.GET("/services", g.serviceDiscoveryHandler)

	// API routes with authentication and authorization
	api := router.Group("/api/v1")
	{
		// Patient Management Service
		patient := api.Group("/patients")
		patient.Use(g.authenticateMiddleware(), g.authorizeMiddleware("patients", "read"))
		{
			patient.Any("/*path", g.proxyHandler("patient"))
		}

		// Medical Records Service
		medical := api.Group("/medical")
		medical.Use(g.authenticateMiddleware(), g.authorizeMiddleware("medical", "read"))
		{
			medical.Any("/*path", g.proxyHandler("medical"))
		}

		// Pharmacy Service
		pharmacy := api.Group("/pharmacy")
		pharmacy.Use(g.authenticateMiddleware(), g.authorizeMiddleware("pharmacy", "read"))
		{
			pharmacy.Any("/*path", g.proxyHandler("pharmacy"))
		}

		// Laboratory Service
		lab := api.Group("/lab")
		lab.Use(g.authenticateMiddleware(), g.authorizeMiddleware("lab", "read"))
		{
			lab.Any("/*path", g.proxyHandler("lab"))
		}

		// Billing Service
		billing := api.Group("/billing")
		billing.Use(g.authenticateMiddleware(), g.authorizeMiddleware("billing", "read"))
		{
			billing.Any("/*path", g.proxyHandler("billing"))
		}

		// Notification Service
		notification := api.Group("/notifications")
		notification.Use(g.authenticateMiddleware(), g.authorizeMiddleware("notifications", "read"))
		{
			notification.Any("/*path", g.proxyHandler("notification"))
		}
	}

	// Start health checking
	go g.startHealthChecking()
}

// healthCheckHandler handles health check requests
func (g *APIGateway) healthCheckHandler(c *gin.Context) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"services":  make(map[string]interface{}),
	}

	// Check each service health
	for serviceName, route := range g.serviceRoutes {
		serviceHealth := map[string]interface{}{
			"status": "healthy",
		}

		if route.CircuitBreaker.State == CircuitBreakerOpen {
			serviceHealth["status"] = "unhealthy"
			serviceHealth["reason"] = "circuit_breaker_open"
		}

		health["services"].(map[string]interface{})[serviceName] = serviceHealth
	}

	c.JSON(http.StatusOK, health)
}

// serviceDiscoveryHandler handles service discovery requests
func (g *APIGateway) serviceDiscoveryHandler(c *gin.Context) {
	services := make(map[string]interface{})

	for serviceName, route := range g.serviceRoutes {
		serviceInfo := map[string]interface{}{
			"name":        route.Name,
			"upstream_url": route.UpstreamURL,
			"weight":      route.Weight,
			"timeout":     route.Timeout.Seconds(),
			"retries":     route.Retries,
			"status":      "healthy",
		}

		if route.CircuitBreaker.State == CircuitBreakerOpen {
			serviceInfo["status"] = "unhealthy"
		}

		services[serviceName] = serviceInfo
	}

	c.JSON(http.StatusOK, gin.H{
		"services": services,
	})
}

// authenticateMiddleware provides authentication middleware
func (g *APIGateway) authenticateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":    false,
				"error":      "authorization header required",
				"error_code": "MISSING_AUTHORIZATION",
			})
			c.Abort()
			return
		}

		// Extract token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":    false,
				"error":      "invalid authorization header format",
				"error_code": "INVALID_AUTHORIZATION_FORMAT",
			})
			c.Abort()
			return
		}

		// Validate token
		userID, err := g.authService.ValidateToken(c, token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":    false,
				"error":      "invalid or expired token",
				"error_code": "INVALID_TOKEN",
			})
			c.Abort()
			return
		}

		// Set user ID in context
		c.Set("user_id", userID)
		c.Next()
	}
}

// authorizeMiddleware provides authorization middleware
func (g *APIGateway) authorizeMiddleware(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDInterface, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":    false,
				"error":      "user not authenticated",
				"error_code": "UNAUTHORIZED",
			})
			c.Abort()
			return
		}

		userID, ok := userIDInterface.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "invalid user ID in context",
				"error_code": "INTERNAL_ERROR",
			})
			c.Abort()
			return
		}

		// Check permission
		hasPermission, err := g.authzService.HasPermission(c, userID, resource, action)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "authorization service error",
				"error_code": "SERVICE_ERROR",
			})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"success":    false,
				"error":      "insufficient permissions",
				"error_code": "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// proxyHandler handles proxy requests to backend services
func (g *APIGateway) proxyHandler(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		route, exists := g.serviceRoutes[serviceName]
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"success":    false,
				"error":      "service not found",
				"error_code": "SERVICE_NOT_FOUND",
			})
			return
		}

		// Check circuit breaker
		if route.CircuitBreaker.State == CircuitBreakerOpen {
			if time.Since(route.CircuitBreaker.LastFailureTime) < route.CircuitBreaker.RecoveryTimeout {
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"success":    false,
					"error":      "service temporarily unavailable",
					"error_code": "SERVICE_UNAVAILABLE",
				})
				return
			}
			// Try to recover
			route.CircuitBreaker.State = CircuitBreakerHalfOpen
		}

		// Create proxy
		targetURL, err := url.Parse(route.UpstreamURL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "invalid upstream URL",
				"error_code": "INVALID_UPSTREAM_URL",
			})
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.Transport = &http.Transport{
			ResponseHeaderTimeout: route.Timeout,
		}

		// Modify request
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			
			// Add gateway headers
			req.Header.Set("X-Gateway-Service", serviceName)
			req.Header.Set("X-Request-ID", c.GetString("request_id"))
			req.Header.Set("X-User-ID", c.GetString("user_id"))
			
			// Forward original path
			path := c.Param("path")
			if path != "" {
				req.URL.Path = "/" + path
			}
		}

		// Handle proxy errors
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			// Record failure
			g.recordServiceFailure(route, err)

			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(gin.H{
				"success":    false,
				"error":      "upstream service error",
				"error_code": "UPSTREAM_ERROR",
			})
		}

		// Log request
		g.logRequest(c, serviceName)

		// Serve request
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

// recordServiceFailure records a service failure for circuit breaker
func (g *APIGateway) recordServiceFailure(route *ServiceRoute, err error) {
	route.CircuitBreaker.FailureCount++
	route.CircuitBreaker.LastFailureTime = time.Now()

	if route.CircuitBreaker.FailureCount >= route.CircuitBreaker.FailureThreshold {
		route.CircuitBreaker.State = CircuitBreakerOpen
	}
}

// logRequest logs the request for audit purposes
func (g *APIGateway) logRequest(c *gin.Context, serviceName string) {
	userIDInterface, exists := c.Get("user_id")
	if !exists {
		return
	}

	userID, ok := userIDInterface.(uuid.UUID)
	if !ok {
		return
	}

	// Log service access
	g.auditService.LogAuthorizationEvent(c, &services.AuthorizationEventData{
		UserID:   userID,
		Resource: serviceName,
		Action:   "access",
		Context: map[string]interface{}{
			"service_name": serviceName,
			"path":         c.Request.URL.Path,
			"method":       c.Request.Method,
			"ip_address":   c.ClientIP(),
		},
		Allowed: true,
		Reason:  "service access through gateway",
	})
}

// startHealthChecking starts the health checking process
func (g *APIGateway) startHealthChecking() {
	ticker := time.NewTicker(g.healthChecker.checkInterval)
	defer ticker.Stop()

	for range ticker.C {
		for serviceName, route := range g.serviceRoutes {
			go g.checkServiceHealth(serviceName, route)
		}
	}
}

// checkServiceHealth checks the health of a service
func (g *APIGateway) checkServiceHealth(serviceName string, route *ServiceRoute) {
	ctx, cancel := context.WithTimeout(context.Background(), g.healthChecker.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", route.HealthCheckURL, nil)
	if err != nil {
		g.recordServiceFailure(route, err)
		return
	}

	client := &http.Client{Timeout: g.healthChecker.timeout}
	resp, err := client.Do(req)
	if err != nil {
		g.recordServiceFailure(route, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		g.recordServiceFailure(route, fmt.Errorf("service returned status %d", resp.StatusCode))
	} else {
		// Reset circuit breaker on success
		if route.CircuitBreaker.State == CircuitBreakerHalfOpen {
			route.CircuitBreaker.State = CircuitBreakerClosed
			route.CircuitBreaker.FailureCount = 0
		}
	}
}

// GetServiceStatus returns the status of all services
func (g *APIGateway) GetServiceStatus() map[string]interface{} {
	status := make(map[string]interface{})

	for serviceName, route := range g.serviceRoutes {
		serviceStatus := map[string]interface{}{
			"name":             route.Name,
			"upstream_url":     route.UpstreamURL,
			"circuit_breaker":  route.CircuitBreaker.State,
			"failure_count":    route.CircuitBreaker.FailureCount,
			"last_failure":     route.CircuitBreaker.LastFailureTime,
			"failure_threshold": route.CircuitBreaker.FailureThreshold,
			"recovery_timeout": route.CircuitBreaker.RecoveryTimeout.Seconds(),
		}

		status[serviceName] = serviceStatus
	}

	return status
}

// UpdateServiceRoute updates a service route configuration
func (g *APIGateway) UpdateServiceRoute(serviceName string, route *ServiceRoute) {
	g.serviceRoutes[serviceName] = route
}

// RemoveServiceRoute removes a service route
func (g *APIGateway) RemoveServiceRoute(serviceName string) {
	delete(g.serviceRoutes, serviceName)
} 