package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/repositories"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// UserManagementController handles user management-related HTTP requests
type UserManagementController struct {
	userRepo repositories.UserRepository
	roleRepo repositories.RoleRepository
}

// NewUserManagementController creates a new user management controller
func NewUserManagementController(userRepo repositories.UserRepository, roleRepo repositories.RoleRepository) *UserManagementController {
	return &UserManagementController{
		userRepo: userRepo,
		roleRepo: roleRepo,
	}
}

// CreateUserRequest represents the user creation request payload
type CreateUserRequest struct {
	Username  string `json:"username" binding:"required,min=3,max=50"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required,min=1,max=50"`
	LastName  string `json:"last_name" binding:"required,min=1,max=50"`
	Phone     string `json:"phone,omitempty"`
	Status    string `json:"status,omitempty"`
}

// CreateUserResponse represents the user creation response payload
type CreateUserResponse struct {
	Success bool   `json:"success"`
	UserID  string `json:"user_id,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// GetUserResponse represents the user retrieval response payload
type GetUserResponse struct {
	Success bool        `json:"success"`
	User    *models.User `json:"user,omitempty"`
	Error   string      `json:"error,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
}

// UpdateUserRequest represents the user update request payload
type UpdateUserRequest struct {
	Email     string `json:"email,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Phone     string `json:"phone,omitempty"`
	Status    string `json:"status,omitempty"`
}

// UpdateUserResponse represents the user update response payload
type UpdateUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// DeleteUserResponse represents the user deletion response payload
type DeleteUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// ListUsersResponse represents the user listing response payload
type ListUsersResponse struct {
	Success bool          `json:"success"`
	Users   []*models.User `json:"users"`
	Total   int           `json:"total"`
	Offset  int           `json:"offset"`
	Limit   int           `json:"limit"`
	Error   string        `json:"error,omitempty"`
	ErrorCode string      `json:"error_code,omitempty"`
}

// SearchUsersResponse represents the user search response payload
type SearchUsersResponse struct {
	Success bool          `json:"success"`
	Users   []*models.User `json:"users"`
	Total   int           `json:"total"`
	Query   string        `json:"query"`
	Offset  int           `json:"offset"`
	Limit   int           `json:"limit"`
	Error   string        `json:"error,omitempty"`
	ErrorCode string      `json:"error_code,omitempty"`
}

// AssignUserRoleRequest represents the user role assignment request payload
type AssignUserRoleRequest struct {
	UserID     string  `json:"user_id" binding:"required"`
	RoleID     string  `json:"role_id" binding:"required"`
	FacilityID *string `json:"facility_id,omitempty"`
	AssignedBy string  `json:"assigned_by" binding:"required"`
	ExpiresAt  *string `json:"expires_at,omitempty"`
}

// AssignUserRoleResponse represents the user role assignment response payload
type AssignUserRoleResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// RevokeUserRoleRequest represents the user role revocation request payload
type RevokeUserRoleRequest struct {
	RoleID string `json:"role_id" binding:"required"`
}

// RevokeUserRoleResponse represents the user role revocation response payload
type RevokeUserRoleResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// ActivateUserResponse represents the user activation response payload
type ActivateUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// DeactivateUserResponse represents the user deactivation response payload
type DeactivateUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// LockUserRequest represents the user lock request payload
type LockUserRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// LockUserResponse represents the user lock response payload
type LockUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// UnlockUserResponse represents the user unlock response payload
type UnlockUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// CreateUser handles user creation requests
func (c *UserManagementController) CreateUser(ctx *gin.Context) {
	var req CreateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, CreateUserResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Check if username already exists
	existingUser, err := c.userRepo.GetByUsername(ctx, req.Username)
	if err == nil && existingUser != nil {
		ctx.JSON(http.StatusConflict, CreateUserResponse{
			Success:   false,
			Error:     "username already exists",
			ErrorCode: "USERNAME_EXISTS",
		})
		return
	}

	// Check if email already exists
	existingUser, err = c.userRepo.GetByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		ctx.JSON(http.StatusConflict, CreateUserResponse{
			Success:   false,
			Error:     "email already exists",
			ErrorCode: "EMAIL_EXISTS",
		})
		return
	}

	// Create user object
	user := &models.User{
		ID:        uuid.New(),
		Username:  req.Username,
		Email:     req.Email,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Set password
	if err := user.SetPassword(req.Password); err != nil {
		ctx.JSON(http.StatusInternalServerError, CreateUserResponse{
			Success:   false,
			Error:     "failed to hash password",
			ErrorCode: "PASSWORD_HASH_ERROR",
		})
		return
	}

	// Set status if provided
	if req.Status != "" {
		switch req.Status {
		case "active":
			user.IsActive = true
			user.IsLocked = false
		case "inactive":
			user.IsActive = false
			user.IsLocked = false
		case "locked":
			user.IsActive = false
			user.IsLocked = true
		default:
			ctx.JSON(http.StatusBadRequest, CreateUserResponse{
				Success:   false,
				Error:     "invalid status value",
				ErrorCode: "INVALID_STATUS",
			})
			return
		}
	}

	// Save user to database
	if err := c.userRepo.Create(ctx, user); err != nil {
		ctx.JSON(http.StatusInternalServerError, CreateUserResponse{
			Success:   false,
			Error:     "failed to create user",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusCreated, CreateUserResponse{
		Success: true,
		UserID:  user.ID.String(),
		Message: "User created successfully",
	})
}

// GetUser handles user retrieval requests
func (c *UserManagementController) GetUser(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, GetUserResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Get user from database
	user, err := c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, GetUserResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	ctx.JSON(http.StatusOK, GetUserResponse{
		Success: true,
		User:    user,
	})
}

// UpdateUser handles user update requests
func (c *UserManagementController) UpdateUser(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, UpdateUserResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	var req UpdateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, UpdateUserResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Get existing user
	user, err := c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, UpdateUserResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	// Update fields if provided
	if req.Email != "" {
		// Check if email already exists for another user
		existingUser, err := c.userRepo.GetByEmail(ctx, req.Email)
		if err == nil && existingUser != nil && existingUser.ID != userID {
			ctx.JSON(http.StatusConflict, UpdateUserResponse{
				Success:   false,
				Error:     "email already exists",
				ErrorCode: "EMAIL_EXISTS",
			})
			return
		}
		user.Email = req.Email
	}

	// Note: User model doesn't have FirstName, LastName, or Phone fields
	// These fields are not part of the User model structure

	if req.Status != "" {
		switch req.Status {
		case "active":
			user.IsActive = true
			user.IsLocked = false
		case "inactive":
			user.IsActive = false
			user.IsLocked = false
		case "locked":
			user.IsActive = false
			user.IsLocked = true
		default:
			ctx.JSON(http.StatusBadRequest, UpdateUserResponse{
				Success:   false,
				Error:     "invalid status value",
				ErrorCode: "INVALID_STATUS",
			})
			return
		}
	}

	user.UpdatedAt = time.Now()

	// Save updated user
	if err := c.userRepo.Update(ctx, user); err != nil {
		ctx.JSON(http.StatusInternalServerError, UpdateUserResponse{
			Success:   false,
			Error:     "failed to update user",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, UpdateUserResponse{
		Success: true,
		Message: "User updated successfully",
	})
}

// DeleteUser handles user deletion requests
func (c *UserManagementController) DeleteUser(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, DeleteUserResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Check if user exists
	_, err = c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, DeleteUserResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	// Delete user
	if err := c.userRepo.Delete(ctx, userID); err != nil {
		ctx.JSON(http.StatusInternalServerError, DeleteUserResponse{
			Success:   false,
			Error:     "failed to delete user",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, DeleteUserResponse{
		Success: true,
		Message: "User deleted successfully",
	})
}

// ListUsers handles user listing requests
func (c *UserManagementController) ListUsers(ctx *gin.Context) {
	// Parse query parameters
	offsetStr := ctx.DefaultQuery("offset", "0")
	limitStr := ctx.DefaultQuery("limit", "10")
	status := ctx.Query("status")
	role := ctx.Query("role")
	facilityID := ctx.Query("facility_id")

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
	if status != "" {
		filters["status"] = status
	}
	if role != "" {
		filters["role"] = role
	}
	if facilityID != "" {
		if parsedFacilityID, err := uuid.Parse(facilityID); err == nil {
			filters["facility_id"] = parsedFacilityID
		}
	}

	// Get users from database
	users, total, err := c.userRepo.List(ctx, offset, limit, filters)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, ListUsersResponse{
			Success:   false,
			Error:     "failed to list users",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, ListUsersResponse{
		Success: true,
		Users:   users,
		Total:   total,
		Offset:  offset,
		Limit:   limit,
	})
}

// SearchUsers handles user search requests
func (c *UserManagementController) SearchUsers(ctx *gin.Context) {
	// Parse query parameters
	query := ctx.Query("q")
	if query == "" {
		ctx.JSON(http.StatusBadRequest, SearchUsersResponse{
			Success:   false,
			Error:     "search query is required",
			ErrorCode: "MISSING_QUERY",
		})
		return
	}

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

	// Search users
	users, total, err := c.userRepo.Search(ctx, query, offset, limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, SearchUsersResponse{
			Success:   false,
			Error:     "failed to search users",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, SearchUsersResponse{
		Success: true,
		Users:   users,
		Total:   total,
		Query:   query,
		Offset:  offset,
		Limit:   limit,
	})
}

// AssignUserRole handles user role assignment requests
func (c *UserManagementController) AssignUserRole(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, AssignUserRoleResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	var req AssignUserRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, AssignUserRoleResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse role ID
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, AssignUserRoleResponse{
			Success:   false,
			Error:     "invalid role ID format",
			ErrorCode: "INVALID_ROLE_ID",
		})
		return
	}

	// Parse assigned by ID
	_, err = uuid.Parse(req.AssignedBy)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, AssignUserRoleResponse{
			Success:   false,
			Error:     "invalid assigned by ID format",
			ErrorCode: "INVALID_ASSIGNED_BY_ID",
		})
		return
	}

	// Check if user exists
	_, err = c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, AssignUserRoleResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	// Check if role exists
	_, err = c.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, AssignUserRoleResponse{
			Success:   false,
			Error:     "role not found",
			ErrorCode: "ROLE_NOT_FOUND",
		})
		return
	}

	// Parse facility ID if provided
	if req.FacilityID != nil {
		_, err := uuid.Parse(*req.FacilityID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, AssignUserRoleResponse{
				Success:   false,
				Error:     "invalid facility ID format",
				ErrorCode: "INVALID_FACILITY_ID",
			})
			return
		}
	}

	// Parse expires at if provided
	if req.ExpiresAt != nil {
		_, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, AssignUserRoleResponse{
				Success:   false,
				Error:     "invalid expires at format, expected RFC3339",
				ErrorCode: "INVALID_EXPIRES_AT",
			})
			return
		}
	}

	// TODO: Implement role assignment using UserRoleRepository
	// For now, return success without actual assignment
	ctx.JSON(http.StatusInternalServerError, AssignUserRoleResponse{
		Success:   false,
		Error:     "role assignment not implemented yet",
		ErrorCode: "NOT_IMPLEMENTED",
	})
	return

	ctx.JSON(http.StatusOK, AssignUserRoleResponse{
		Success: true,
		Message: "Role assigned successfully",
	})
}

// RevokeUserRole handles user role revocation requests
func (c *UserManagementController) RevokeUserRole(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, RevokeUserRoleResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	var req RevokeUserRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, RevokeUserRoleResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Parse role ID
	_, err = uuid.Parse(req.RoleID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, RevokeUserRoleResponse{
			Success:   false,
			Error:     "invalid role ID format",
			ErrorCode: "INVALID_ROLE_ID",
		})
		return
	}

	// Check if user exists
	_, err = c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, RevokeUserRoleResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	// TODO: Implement role revocation using UserRoleRepository
	// For now, return success without actual revocation
	ctx.JSON(http.StatusInternalServerError, RevokeUserRoleResponse{
		Success:   false,
		Error:     "role revocation not implemented yet",
		ErrorCode: "NOT_IMPLEMENTED",
	})
	return

	ctx.JSON(http.StatusOK, RevokeUserRoleResponse{
		Success: true,
		Message: "Role revoked successfully",
	})
}

// ActivateUser handles user activation requests
func (c *UserManagementController) ActivateUser(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ActivateUserResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Get user
	user, err := c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, ActivateUserResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	// Check if user is already active
	if user.IsActive {
		ctx.JSON(http.StatusBadRequest, ActivateUserResponse{
			Success:   false,
			Error:     "user is already active",
			ErrorCode: "USER_ALREADY_ACTIVE",
		})
		return
	}

	// Activate user
	user.IsActive = true
	user.IsLocked = false
	user.UpdatedAt = time.Now()

	if err := c.userRepo.Update(ctx, user); err != nil {
		ctx.JSON(http.StatusInternalServerError, ActivateUserResponse{
			Success:   false,
			Error:     "failed to activate user",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, ActivateUserResponse{
		Success: true,
		Message: "User activated successfully",
	})
}

// DeactivateUser handles user deactivation requests
func (c *UserManagementController) DeactivateUser(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, DeactivateUserResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Get user
	user, err := c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, DeactivateUserResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	// Check if user is already inactive
	if !user.IsActive {
		ctx.JSON(http.StatusBadRequest, DeactivateUserResponse{
			Success:   false,
			Error:     "user is already inactive",
			ErrorCode: "USER_ALREADY_INACTIVE",
		})
		return
	}

	// Deactivate user
	user.IsActive = false
	user.UpdatedAt = time.Now()

	if err := c.userRepo.Update(ctx, user); err != nil {
		ctx.JSON(http.StatusInternalServerError, DeactivateUserResponse{
			Success:   false,
			Error:     "failed to deactivate user",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, DeactivateUserResponse{
		Success: true,
		Message: "User deactivated successfully",
	})
}

// LockUser handles user account locking requests
func (c *UserManagementController) LockUser(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, LockUserResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	var req LockUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, LockUserResponse{
			Success:   false,
			Error:     "invalid request body: " + err.Error(),
			ErrorCode: "INVALID_REQUEST",
		})
		return
	}

	// Check if user exists
	user, err := c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, LockUserResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	// Check if user is already locked
	if user.IsLocked {
		ctx.JSON(http.StatusBadRequest, LockUserResponse{
			Success:   false,
			Error:     "user account is already locked",
			ErrorCode: "USER_ALREADY_LOCKED",
		})
		return
	}

	// Lock user account
	if err := c.userRepo.LockAccount(ctx, userID, 24*time.Hour); err != nil {
		ctx.JSON(http.StatusInternalServerError, LockUserResponse{
			Success:   false,
			Error:     "failed to lock user account",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, LockUserResponse{
		Success: true,
		Message: "User account locked successfully",
	})
}

// UnlockUser handles user account unlocking requests
func (c *UserManagementController) UnlockUser(ctx *gin.Context) {
	// Get user ID from URL parameter
	userIDStr := ctx.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, UnlockUserResponse{
			Success:   false,
			Error:     "invalid user ID format",
			ErrorCode: "INVALID_USER_ID",
		})
		return
	}

	// Check if user exists
	user, err := c.userRepo.GetByID(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, UnlockUserResponse{
			Success:   false,
			Error:     "user not found",
			ErrorCode: "USER_NOT_FOUND",
		})
		return
	}

	// Check if user is not locked
	if !user.IsLocked {
		ctx.JSON(http.StatusBadRequest, UnlockUserResponse{
			Success:   false,
			Error:     "user account is not locked",
			ErrorCode: "USER_NOT_LOCKED",
		})
		return
	}

	// Unlock user account
	if err := c.userRepo.UnlockAccount(ctx, userID); err != nil {
		ctx.JSON(http.StatusInternalServerError, UnlockUserResponse{
			Success:   false,
			Error:     "failed to unlock user account",
			ErrorCode: "SERVICE_ERROR",
		})
		return
	}

	ctx.JSON(http.StatusOK, UnlockUserResponse{
		Success: true,
		Message: "User account unlocked successfully",
	})
}

// Helper functions

// validatePassword validates password strength
func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password too short")
	}
	
	// Check for at least one uppercase letter
	if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	
	// Check for at least one lowercase letter
	if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	
	// Check for at least one digit
	if !strings.ContainsAny(password, "0123456789") {
		return fmt.Errorf("password must contain at least one digit")
	}
	
	return nil
} 