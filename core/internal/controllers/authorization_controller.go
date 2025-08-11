package controllers

import (
	"net/http"
	"time"

	"github.com/bmad-method/hmis-core/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthorizationController handles authorization-related HTTP requests
type AuthorizationController struct {
	authService services.AuthorizationService
}

// NewAuthorizationController creates a new authorization controller
func NewAuthorizationController(authService services.AuthorizationService) *AuthorizationController {
	return &AuthorizationController{
		authService: authService,
	}
}

// PermissionCheckRequest represents the permission check request payload
type PermissionCheckRequest struct {
	Resource string `json:"resource" binding:"required"`
	Action   string `json:"action" binding:"required"`
}

// PermissionCheckResponse represents the permission check response payload
type PermissionCheckResponse struct {
	Success      bool   `json:"success"`
	HasPermission bool   `json:"has_permission"`
	Error        string `json:"error,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// PermissionCheckWithContextRequest represents the permission check with context request payload
type PermissionCheckWithContextRequest struct {
	Resource string                 `json:"resource" binding:"required"`
	Action   string                 `json:"action" binding:"required"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// RoleCheckRequest represents the role check request payload
type RoleCheckRequest struct {
	RoleName string `json:"role_name" binding:"required"`
}

// RoleCheckResponse represents the role check response payload
type RoleCheckResponse struct {
	Success  bool   `json:"success"`
	HasRole  bool   `json:"has_role"`
	Error    string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// FacilityAccessRequest represents the facility access check request payload
type FacilityAccessRequest struct {
	FacilityID string `json:"facility_id" binding:"required"`
}

// FacilityAccessResponse represents the facility access check response payload
type FacilityAccessResponse struct {
	Success   bool   `json:"success"`
	HasAccess bool   `json:"has_access"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// UserPermissionsResponse represents the user permissions response payload
type UserPermissionsResponse struct {
	Success     bool     `json:"success"`
	Permissions []string `json:"permissions"`
	Error       string   `json:"error,omitempty"`
	ErrorCode   string   `json:"error_code,omitempty"`
}

// UserRolesResponse represents the user roles response payload
type UserRolesResponse struct {
	Success bool     `json:"success"`
	Roles   []string `json:"roles"`
	Error   string   `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// AssignRoleRequest represents the role assignment request payload
type AssignRoleRequest struct {
	UserID     string  `json:"user_id" binding:"required"`
	RoleID     string  `json:"role_id" binding:"required"`
	FacilityID *string `json:"facility_id,omitempty"`
	AssignedBy string  `json:"assigned_by" binding:"required"`
	ExpiresAt  *string `json:"expires_at,omitempty"`
}

// AssignRoleResponse represents the role assignment response payload
type AssignRoleResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// RevokeRoleRequest represents the role revocation request payload
type RevokeRoleRequest struct {
	UserID string `json:"user_id" binding:"required"`
	RoleID string `json:"role_id" binding:"required"`
}

// RevokeRoleResponse represents the role revocation response payload
type RevokeRoleResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// GrantPermissionRequest represents the permission grant request payload
type GrantPermissionRequest struct {
	RoleID       string  `json:"role_id" binding:"required"`
	PermissionID string  `json:"permission_id" binding:"required"`
	GrantedBy    string  `json:"granted_by" binding:"required"`
}

// GrantPermissionResponse represents the permission grant response payload
type GrantPermissionResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// RevokePermissionRequest represents the permission revocation request payload
type RevokePermissionRequest struct {
	RoleID       string `json:"role_id" binding:"required"`
	PermissionID string `json:"permission_id" binding:"required"`
}

// RevokePermissionResponse represents the permission revocation response payload
type RevokePermissionResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// CheckPermission handles permission checking requests
func (c *AuthorizationController) CheckPermission(ctx *gin.Context) {
	var req PermissionCheckRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, PermissionCheckResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userIDInterface, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, PermissionCheckResponse{
			Success:   false,
			Error:     "user not authenticated",
			ErrorCode: "UNAUTHORIZED",
		})
		return
	}

	userID, ok := userIDInterface.(uuid.UUID)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, PermissionCheckResponse{
			Success:   false,
			Error:     "invalid user ID in context",
			ErrorCode: "INTERNAL_ERROR",
		})
		return
	}

	// Check permission
	hasPermission, err := c.authService.HasPermission(ctx, userID, req.Resource, req.Action)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, PermissionCheckResponse{
			Success:   false,
			Error:     "authorization service error",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, PermissionCheckResponse{
		Success:      true,
		HasPermission: hasPermission,
	})
}

// CheckPermissionWithContext handles permission checking with context
func (c *AuthorizationController) CheckPermissionWithContext(ctx *gin.Context) {
	var req PermissionCheckWithContextRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, PermissionCheckResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userIDInterface, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, PermissionCheckResponse{
			Success:   false,
			Error:     "user not authenticated",
			ErrorCode: "UNAUTHORIZED",
		})
		return
	}

	userID, ok := userIDInterface.(uuid.UUID)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, PermissionCheckResponse{
			Success:   false,
			Error:     "invalid user ID in context",
			ErrorCode: "INTERNAL_ERROR",
		})
		return
	}

	// Check permission with context
	hasPermission, err := c.authService.HasPermissionWithContext(ctx, userID, req.Resource, req.Action, req.Context)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, PermissionCheckResponse{
			Success:   false,
			Error:     "authorization service error",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, PermissionCheckResponse{
		Success:      true,
		HasPermission: hasPermission,
	})
}

// CheckRole handles role checking requests
func (c *AuthorizationController) CheckRole(ctx *gin.Context) {
	var req RoleCheckRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, RoleCheckResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userIDInterface, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, RoleCheckResponse{
			Success:   false,
			Error:     "user not authenticated",
			ErrorCode: "UNAUTHORIZED",
		})
		return
	}

	userID, ok := userIDInterface.(uuid.UUID)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, RoleCheckResponse{
			Success:   false,
			Error:     "invalid user ID in context",
			ErrorCode: "INTERNAL_ERROR",
		})
		return
	}

	// Check role
	hasRole, err := c.authService.HasRole(ctx, userID, req.RoleName)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, RoleCheckResponse{
			Success:   false,
			Error:     "authorization service error",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, RoleCheckResponse{
		Success: true,
		HasRole: hasRole,
	})
}

// CheckFacilityAccess handles facility access checking requests
func (c *AuthorizationController) CheckFacilityAccess(ctx *gin.Context) {
	var req FacilityAccessRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, FacilityAccessResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse facility ID
	facilityID, err := uuid.Parse(req.FacilityID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, FacilityAccessResponse{
			Success:   false,
			Error:     "invalid facility ID format",
			ErrorCode: "INVALID_FACILITY_ID",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userIDInterface, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, FacilityAccessResponse{
			Success:   false,
			Error:     "user not authenticated",
			ErrorCode: "UNAUTHORIZED",
		})
		return
	}

	userID, ok := userIDInterface.(uuid.UUID)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, FacilityAccessResponse{
			Success:   false,
			Error:     "invalid user ID in context",
			ErrorCode: "INTERNAL_ERROR",
		})
		return
	}

	// Check facility access
	hasAccess, err := c.authService.HasFacilityAccess(ctx, userID, facilityID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, FacilityAccessResponse{
			Success:   false,
			Error:     "authorization service error",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, FacilityAccessResponse{
		Success:   true,
		HasAccess: hasAccess,
	})
}

// GetUserPermissions handles user permissions retrieval requests
func (c *AuthorizationController) GetUserPermissions(ctx *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userIDInterface, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, UserPermissionsResponse{
			Success:   false,
			Error:     "user not authenticated",
			ErrorCode: "UNAUTHORIZED",
		})
		return
	}

	userID, ok := userIDInterface.(uuid.UUID)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, UserPermissionsResponse{
			Success:   false,
			Error:     "invalid user ID in context",
			ErrorCode: "INTERNAL_ERROR",
		})
		return
	}

	// Get user permissions
	permissions, err := c.authService.GetUserPermissions(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, UserPermissionsResponse{
			Success:   false,
			Error:     "failed to get user permissions",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, UserPermissionsResponse{
		Success:     true,
		Permissions: permissions,
	})
}

// GetUserRoles handles user roles retrieval requests
func (c *AuthorizationController) GetUserRoles(ctx *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userIDInterface, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, UserRolesResponse{
			Success:   false,
			Error:     "user not authenticated",
			ErrorCode: "UNAUTHORIZED",
		})
		return
	}

	userID, ok := userIDInterface.(uuid.UUID)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, UserRolesResponse{
			Success:   false,
			Error:     "invalid user ID in context",
			ErrorCode: "INTERNAL_ERROR",
		})
		return
	}

	// Get user roles
	roles, err := c.authService.GetUserRoles(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, UserRolesResponse{
			Success:   false,
			Error:     "failed to get user roles",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, UserRolesResponse{
		Success: true,
		Roles:   roles,
	})
}

// AssignRole handles role assignment requests
func (c *AuthorizationController) AssignRole(ctx *gin.Context) {
	var req AssignRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, AssignRoleResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse user ID
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, AssignRoleResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Parse role ID
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, AssignRoleResponse{
			Success:   false,
			Error:     "invalid role ID format",
			ErrorCode: "INVALID_ROLE_ID",
		})
		return
	}

	// Parse assigned by ID
	assignedBy, err := uuid.Parse(req.AssignedBy)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, AssignRoleResponse{
			Success:   false,
			Error:     "invalid assigned by ID format",
			ErrorCode: "INVALID_ASSIGNED_BY_ID",
		})
		return
	}

	// Parse facility ID if provided
	var facilityID *uuid.UUID
	if req.FacilityID != nil {
		parsedFacilityID, err := uuid.Parse(*req.FacilityID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, AssignRoleResponse{
				Success:   false,
				Error:     "invalid facility ID format",
				ErrorCode: "INVALID_FACILITY_ID",
			})
			return
		}
		facilityID = &parsedFacilityID
	}

	// Parse expires at if provided
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		parsedExpiresAt, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, AssignRoleResponse{
				Success:   false,
				Error:     "invalid expires at format, expected RFC3339",
				ErrorCode: "INVALID_EXPIRES_AT",
			})
			return
		}
		expiresAt = &parsedExpiresAt
	}

	// Assign role
	err = c.authService.AssignRole(ctx, userID, roleID, facilityID, &assignedBy, expiresAt)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, AssignRoleResponse{
			Success:   false,
			Error:     "failed to assign role",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, AssignRoleResponse{
		Success: true,
	})
}

// RevokeRole handles role revocation requests
func (c *AuthorizationController) RevokeRole(ctx *gin.Context) {
	var req RevokeRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, RevokeRoleResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse user ID
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, RevokeRoleResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Parse role ID
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, RevokeRoleResponse{
			Success:   false,
			Error:     "invalid role ID format",
			ErrorCode: "INVALID_ROLE_ID",
		})
		return
	}

	// Revoke role
	err = c.authService.RevokeRole(ctx, userID, roleID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, RevokeRoleResponse{
			Success:   false,
			Error:     "failed to revoke role",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, RevokeRoleResponse{
		Success: true,
	})
}

// GrantPermission handles permission granting requests
func (c *AuthorizationController) GrantPermission(ctx *gin.Context) {
	var req GrantPermissionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, GrantPermissionResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse role ID
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, GrantPermissionResponse{
			Success:   false,
			Error:     "invalid role ID format",
			ErrorCode: "INVALID_ROLE_ID",
		})
		return
	}

	// Parse permission ID
	permissionID, err := uuid.Parse(req.PermissionID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, GrantPermissionResponse{
			Success:   false,
			Error:     "invalid permission ID format",
			ErrorCode: "INVALID_PERMISSION_ID",
		})
		return
	}

	// Parse granted by ID
	grantedBy, err := uuid.Parse(req.GrantedBy)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, GrantPermissionResponse{
			Success:   false,
			Error:     "invalid granted by ID format",
			ErrorCode: "INVALID_GRANTED_BY_ID",
		})
		return
	}

	// Grant permission
	err = c.authService.GrantPermission(ctx, roleID, permissionID, &grantedBy)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, GrantPermissionResponse{
			Success:   false,
			Error:     "failed to grant permission",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, GrantPermissionResponse{
		Success: true,
	})
}

// RevokePermission handles permission revocation requests
func (c *AuthorizationController) RevokePermission(ctx *gin.Context) {
	var req RevokePermissionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, RevokePermissionResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse role ID
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, RevokePermissionResponse{
			Success:   false,
			Error:     "invalid role ID format",
			ErrorCode: "INVALID_ROLE_ID",
		})
		return
	}

	// Parse permission ID
	permissionID, err := uuid.Parse(req.PermissionID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, RevokePermissionResponse{
			Success:   false,
			Error:     "invalid permission ID format",
			ErrorCode: "INVALID_PERMISSION_ID",
		})
		return
	}

	// Revoke permission
	err = c.authService.RevokePermission(ctx, roleID, permissionID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, RevokePermissionResponse{
			Success:   false,
			Error:     "failed to revoke permission",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, RevokePermissionResponse{
		Success: true,
	})
}

// AuthorizationMiddleware provides authorization middleware for protecting routes
func (c *AuthorizationController) AuthorizationMiddleware(resource, action string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userIDInterface, exists := ctx.Get("user_id")
		if !exists {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"success":    false,
				"error":      "user not authenticated",
				"error_code": "UNAUTHORIZED",
			})
			ctx.Abort()
			return
		}

		userID, ok := userIDInterface.(uuid.UUID)
		if !ok {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "invalid user ID in context",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		// Check permission
		hasPermission, err := c.authService.HasPermission(ctx, userID, resource, action)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "authorization service error",
				"error_code": "SERVICE_ERROR",
			})
			ctx.Abort()
			return
		}

		if !hasPermission {
			ctx.JSON(http.StatusForbidden, gin.H{
				"success":    false,
				"error":      "insufficient permissions",
				"error_code": "INSUFFICIENT_PERMISSIONS",
			})
			ctx.Abort()
			return
		}

		// Permission granted, continue
		ctx.Next()
	}
}

// AuthorizationMiddlewareWithContext provides authorization middleware with context
func (c *AuthorizationController) AuthorizationMiddlewareWithContext(resource, action string, contextExtractor func(*gin.Context) map[string]interface{}) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userIDInterface, exists := ctx.Get("user_id")
		if !exists {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"success":    false,
				"error":      "user not authenticated",
				"error_code": "UNAUTHORIZED",
			})
			ctx.Abort()
			return
		}

		userID, ok := userIDInterface.(uuid.UUID)
		if !ok {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "invalid user ID in context",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		// Extract context
		context := contextExtractor(ctx)

		// Check permission with context
		hasPermission, err := c.authService.HasPermissionWithContext(ctx, userID, resource, action, context)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "authorization service error",
				"error_code": "SERVICE_ERROR",
			})
			ctx.Abort()
			return
		}

		if !hasPermission {
			ctx.JSON(http.StatusForbidden, gin.H{
				"success":    false,
				"error":      "insufficient permissions or context restrictions",
				"error_code": "CONTEXT_RESTRICTION",
			})
			ctx.Abort()
			return
		}

		// Permission granted, continue
		ctx.Next()
	}
}

// RoleMiddleware provides role-based authorization middleware
func (c *AuthorizationController) RoleMiddleware(roleName string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userIDInterface, exists := ctx.Get("user_id")
		if !exists {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"success":    false,
				"error":      "user not authenticated",
				"error_code": "UNAUTHORIZED",
			})
			ctx.Abort()
			return
		}

		userID, ok := userIDInterface.(uuid.UUID)
		if !ok {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "invalid user ID in context",
				"error_code": "INTERNAL_ERROR",
			})
			ctx.Abort()
			return
		}

		// Check role
		hasRole, err := c.authService.HasRole(ctx, userID, roleName)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success":    false,
				"error":      "authorization service error",
				"error_code": "SERVICE_ERROR",
			})
			ctx.Abort()
			return
		}

		if !hasRole {
			ctx.JSON(http.StatusForbidden, gin.H{
				"success":    false,
				"error":      "insufficient role permissions",
				"error_code": "INSUFFICIENT_ROLE",
			})
			ctx.Abort()
			return
		}

		// Role granted, continue
		ctx.Next()
	}
} 