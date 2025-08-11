package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/bmad-method/hmis-core/internal/repositories"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// UserRepository implements repositories.UserRepository for PostgreSQL
type UserRepository struct {
	db *sqlx.DB
}

// NewUserRepository creates a new UserRepository instance
func NewUserRepository(db *sqlx.DB) repositories.UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	if err := user.BeforeCreate(); err != nil {
		return fmt.Errorf("failed to prepare user for creation: %w", err)
	}

	query := `
		INSERT INTO users (
			id, username, email, password_hash, password_salt, is_active, is_locked,
			failed_login_attempts, last_login_at, locked_until, created_at, updated_at,
			created_by, updated_by
		) VALUES (
			:id, :username, :email, :password_hash, :password_salt, :is_active, :is_locked,
			:failed_login_attempts, :last_login_at, :locked_until, :created_at, :updated_at,
			:created_by, :updated_by
		)
	`

	_, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	query := `SELECT * FROM users WHERE id = $1`

	err := r.db.GetContext(ctx, &user, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	query := `SELECT * FROM users WHERE username = $1`

	err := r.db.GetContext(ctx, &user, query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", username)
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	query := `SELECT * FROM users WHERE email = $1`

	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", email)
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// Update updates an existing user
func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	if err := user.BeforeUpdate(); err != nil {
		return fmt.Errorf("failed to prepare user for update: %w", err)
	}

	query := `
		UPDATE users SET
			username = :username, email = :email, password_hash = :password_hash,
			password_salt = :password_salt, is_active = :is_active, is_locked = :is_locked,
			failed_login_attempts = :failed_login_attempts, last_login_at = :last_login_at,
			locked_until = :locked_until, updated_at = :updated_at, updated_by = :updated_by
		WHERE id = :id
	`

	result, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", user.ID)
	}

	return nil
}

// Delete deletes a user by ID
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", id)
	}

	return nil
}

// List retrieves a list of users with pagination and filters
func (r *UserRepository) List(ctx context.Context, offset, limit int, filters map[string]interface{}) ([]*models.User, int, error) {
	// Build WHERE clause from filters
	whereClause := "WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if isActive, exists := filters["is_active"]; exists {
		whereClause += fmt.Sprintf(" AND is_active = $%d", argIndex)
		args = append(args, isActive)
		argIndex++
	}

	if isLocked, exists := filters["is_locked"]; exists {
		whereClause += fmt.Sprintf(" AND is_locked = $%d", argIndex)
		args = append(args, isLocked)
		argIndex++
	}

	// Count total records
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", whereClause)
	var total int
	err := r.db.GetContext(ctx, &total, countQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT * FROM users %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, limit, offset)

	var users []*models.User
	err = r.db.SelectContext(ctx, &users, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	return users, total, nil
}

// GetWithRoles retrieves a user with their roles
func (r *UserRepository) GetWithRoles(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Get user roles
	query := `
		SELECT ur.*, r.* FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		WHERE ur.user_id = $1 AND ur.is_active = true
	`

	var userRoles []models.UserRole
	err = r.db.SelectContext(ctx, &userRoles, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	user.Roles = userRoles
	return user, nil
}

// GetWithPermissions retrieves a user with their permissions
func (r *UserRepository) GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := r.GetWithRoles(ctx, id)
	if err != nil {
		return nil, err
	}

	// For each role, get its permissions
	for i := range user.Roles {
		permissionsQuery := `
			SELECT p.* FROM permissions p
			JOIN role_permissions rp ON p.id = rp.permission_id
			WHERE rp.role_id = $1
		`
		var permissions []models.Permission
		err = r.db.SelectContext(ctx, &permissions, permissionsQuery, user.Roles[i].RoleID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role permissions: %w", err)
		}

		// Create role permissions
		var rolePermissions []models.RolePermission
		for _, perm := range permissions {
			rolePermissions = append(rolePermissions, models.RolePermission{
				RoleID:       user.Roles[i].RoleID,
				PermissionID: perm.ID,
				Permission:   &perm,
			})
		}

		if user.Roles[i].Role != nil {
			user.Roles[i].Role.Permissions = rolePermissions
		}
	}

	return user, nil
}

// UpdateLastLogin updates the last login timestamp
func (r *UserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users SET
			last_login_at = $1,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", id)
	}

	return nil
}

// IncrementFailedLoginAttempts increments the failed login counter
func (r *UserRepository) IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users SET
			failed_login_attempts = failed_login_attempts + 1,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to increment failed login attempts: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", id)
	}

	return nil
}

// ResetFailedLoginAttempts resets the failed login counter
func (r *UserRepository) ResetFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users SET
			failed_login_attempts = 0,
			is_locked = false,
			locked_until = NULL,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to reset failed login attempts: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", id)
	}

	return nil
}

// LockAccount locks the user account
func (r *UserRepository) LockAccount(ctx context.Context, id uuid.UUID, duration time.Duration) error {
	lockTime := time.Now().Add(duration)
	query := `
		UPDATE users SET
			is_locked = true,
			locked_until = $1,
			updated_at = $2
		WHERE id = $3
	`

	result, err := r.db.ExecContext(ctx, query, lockTime, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", id)
	}

	return nil
}

// UnlockAccount unlocks the user account
func (r *UserRepository) UnlockAccount(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users SET
			is_locked = false,
			locked_until = NULL,
			updated_at = $1
		WHERE id = $2
	`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found: %s", id)
	}

	return nil
}

// Search searches for users by query
func (r *UserRepository) Search(ctx context.Context, query string, offset, limit int) ([]*models.User, int, error) {
	searchQuery := "%" + strings.ToLower(query) + "%"
	
	// Count total records
	countQuery := `
		SELECT COUNT(*) FROM users 
		WHERE LOWER(username) LIKE $1 OR LOWER(email) LIKE $1
	`
	var total int
	err := r.db.GetContext(ctx, &total, countQuery, searchQuery)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Get paginated results
	query = `
		SELECT * FROM users 
		WHERE LOWER(username) LIKE $1 OR LOWER(email) LIKE $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	var users []*models.User
	err = r.db.SelectContext(ctx, &users, query, searchQuery, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}

	return users, total, nil
}

// GetByFacility retrieves users by facility
func (r *UserRepository) GetByFacility(ctx context.Context, facilityID uuid.UUID, offset, limit int) ([]*models.User, int, error) {
	// Count total records
	countQuery := `
		SELECT COUNT(DISTINCT u.id) FROM users u
		JOIN user_roles ur ON u.id = ur.user_id
		WHERE ur.facility_id = $1
	`
	var total int
	err := r.db.GetContext(ctx, &total, countQuery, facilityID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users by facility: %w", err)
	}

	// Get paginated results
	query := `
		SELECT DISTINCT u.* FROM users u
		JOIN user_roles ur ON u.id = ur.user_id
		WHERE ur.facility_id = $1
		ORDER BY u.created_at DESC
		LIMIT $2 OFFSET $3
	`

	var users []*models.User
	err = r.db.SelectContext(ctx, &users, query, facilityID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get users by facility: %w", err)
	}

	return users, total, nil
}

// GetByRole retrieves users by role
func (r *UserRepository) GetByRole(ctx context.Context, roleID uuid.UUID, offset, limit int) ([]*models.User, int, error) {
	// Count total records
	countQuery := `
		SELECT COUNT(DISTINCT u.id) FROM users u
		JOIN user_roles ur ON u.id = ur.user_id
		WHERE ur.role_id = $1 AND ur.is_active = true
	`
	var total int
	err := r.db.GetContext(ctx, &total, countQuery, roleID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users by role: %w", err)
	}

	// Get paginated results
	query := `
		SELECT DISTINCT u.* FROM users u
		JOIN user_roles ur ON u.id = ur.user_id
		WHERE ur.role_id = $1 AND ur.is_active = true
		ORDER BY u.created_at DESC
		LIMIT $2 OFFSET $3
	`

	var users []*models.User
	err = r.db.SelectContext(ctx, &users, query, roleID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get users by role: %w", err)
	}

	return users, total, nil
} 