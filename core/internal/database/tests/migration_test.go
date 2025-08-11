package tests

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabase represents the test database configuration
type TestDatabase struct {
	DB   *sql.DB
	Name string
}

// setupTestDatabase creates a test database and returns cleanup function
func setupTestDatabase(t *testing.T) (*TestDatabase, func()) {
	// Use test database configuration
	dbHost := getEnvOrDefault("TEST_DB_HOST", "localhost")
	dbPort := getEnvOrDefault("TEST_DB_PORT", "5432")
	dbUser := getEnvOrDefault("TEST_DB_USER", "hmis_user")
	dbPassword := getEnvOrDefault("TEST_DB_PASSWORD", "hmis_password")
	dbName := getEnvOrDefault("TEST_DB_NAME", "hmis_test")

	// Create unique test database name
	testDBName := fmt.Sprintf("%s_%d", dbName, time.Now().Unix())

	// Connect to default database to create test database
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=postgres sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword)
	
	defaultDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer defaultDB.Close()

	// Create test database
	_, err = defaultDB.Exec(fmt.Sprintf("CREATE DATABASE %s", testDBName))
	require.NoError(t, err)

	// Connect to test database
	testDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, testDBName)
	
	testDB, err := sql.Open("postgres", testDSN)
	require.NoError(t, err)

	// Return test database and cleanup function
	return &TestDatabase{
		DB:   testDB,
		Name: testDBName,
	}, func() {
		testDB.Close()
		_, err := defaultDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", testDBName))
		if err != nil {
			t.Logf("Failed to drop test database: %v", err)
		}
		defaultDB.Close()
	}
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TestUserTableCreation tests the users table creation and constraints
func TestUserTableCreation(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create users table
	createUsersTable := `
	CREATE TABLE users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255),
		password_salt VARCHAR(255),
		is_active BOOLEAN DEFAULT true,
		is_locked BOOLEAN DEFAULT false,
		failed_login_attempts INTEGER DEFAULT 0,
		last_login_at TIMESTAMP,
		locked_until TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		created_by UUID REFERENCES users(id),
		updated_by UUID REFERENCES users(id)
	);`

	_, err := db.DB.Exec(createUsersTable)
	require.NoError(t, err, "Failed to create users table")

	// Test table exists
	var tableName string
	err = db.DB.QueryRow(`
		SELECT table_name 
		FROM information_schema.tables 
		WHERE table_schema = 'public' AND table_name = 'users'
	`).Scan(&tableName)
	require.NoError(t, err)
	assert.Equal(t, "users", tableName)

	// Test unique constraints
	_, err = db.DB.Exec("INSERT INTO users (username, email) VALUES ('testuser1', 'test1@example.com')")
	require.NoError(t, err)

	// Should fail due to unique constraint
	_, err = db.DB.Exec("INSERT INTO users (username, email) VALUES ('testuser1', 'test2@example.com')")
	assert.Error(t, err, "Should fail due to username unique constraint")

	_, err = db.DB.Exec("INSERT INTO users (username, email) VALUES ('testuser2', 'test1@example.com')")
	assert.Error(t, err, "Should fail due to email unique constraint")

	// Test default values
	var isActive, isLocked bool
	var failedAttempts int
	err = db.DB.QueryRow("SELECT is_active, is_locked, failed_login_attempts FROM users WHERE username = 'testuser1'").Scan(&isActive, &isLocked, &failedAttempts)
	require.NoError(t, err)
	assert.True(t, isActive, "is_active should default to true")
	assert.False(t, isLocked, "is_locked should default to false")
	assert.Equal(t, 0, failedAttempts, "failed_login_attempts should default to 0")
}

// TestRolePermissionTables tests role and permission table relationships
func TestRolePermissionTables(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create roles table
	createRolesTable := `
	CREATE TABLE roles (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(100) UNIQUE NOT NULL,
		description TEXT,
		is_system_role BOOLEAN DEFAULT false,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.DB.Exec(createRolesTable)
	require.NoError(t, err, "Failed to create roles table")

	// Create permissions table
	createPermissionsTable := `
	CREATE TABLE permissions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(100) UNIQUE NOT NULL,
		description TEXT,
		resource VARCHAR(100) NOT NULL,
		action VARCHAR(100) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(resource, action)
	);`

	_, err = db.DB.Exec(createPermissionsTable)
	require.NoError(t, err, "Failed to create permissions table")

	// Create role_permissions table
	createRolePermissionsTable := `
	CREATE TABLE role_permissions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
		permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
		granted_by UUID,
		granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(role_id, permission_id)
	);`

	_, err = db.DB.Exec(createRolePermissionsTable)
	require.NoError(t, err, "Failed to create role_permissions table")

	// Test inserting roles
	_, err = db.DB.Exec("INSERT INTO roles (name, description) VALUES ('doctor', 'Medical Doctor')")
	require.NoError(t, err)

	_, err = db.DB.Exec("INSERT INTO roles (name, description) VALUES ('nurse', 'Nurse')")
	require.NoError(t, err)

	// Test inserting permissions
	_, err = db.DB.Exec("INSERT INTO permissions (name, description, resource, action) VALUES ('view_patients', 'View patients', 'patients', 'read')")
	require.NoError(t, err)

	_, err = db.DB.Exec("INSERT INTO permissions (name, description, resource, action) VALUES ('create_patients', 'Create patients', 'patients', 'create')")
	require.NoError(t, err)

	// Test unique constraint on resource+action
	_, err = db.DB.Exec("INSERT INTO permissions (name, description, resource, action) VALUES ('view_patients_alt', 'View patients alt', 'patients', 'read')")
	assert.Error(t, err, "Should fail due to unique constraint on resource+action")

	// Test role-permission relationship
	var roleID, permissionID string
	err = db.DB.QueryRow("SELECT id FROM roles WHERE name = 'doctor'").Scan(&roleID)
	require.NoError(t, err)

	err = db.DB.QueryRow("SELECT id FROM permissions WHERE name = 'view_patients'").Scan(&permissionID)
	require.NoError(t, err)

	_, err = db.DB.Exec("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)", roleID, permissionID)
	require.NoError(t, err)

	// Test cascade delete
	_, err = db.DB.Exec("DELETE FROM roles WHERE name = 'doctor'")
	require.NoError(t, err)

	// Check that role_permissions entry was deleted
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM role_permissions WHERE role_id = $1", roleID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "Role permissions should be deleted when role is deleted")
}

// TestSessionOTPTables tests session and OTP device table functionality
func TestSessionOTPTables(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create users table first (required for foreign key)
	createUsersTable := `
	CREATE TABLE users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL
	);`
	_, err := db.DB.Exec(createUsersTable)
	require.NoError(t, err)

	// Create user_sessions table
	createUserSessionsTable := `
	CREATE TABLE user_sessions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		session_token VARCHAR(255) UNIQUE NOT NULL,
		refresh_token VARCHAR(255) UNIQUE NOT NULL,
		ip_address INET,
		user_agent TEXT,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.DB.Exec(createUserSessionsTable)
	require.NoError(t, err, "Failed to create user_sessions table")

	// Create user_otp_devices table
	createUserOTPDevicesTable := `
	CREATE TABLE user_otp_devices (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		device_type VARCHAR(50) NOT NULL,
		device_identifier VARCHAR(255) NOT NULL,
		secret_key VARCHAR(255),
		is_verified BOOLEAN DEFAULT false,
		is_active BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		verified_at TIMESTAMP,
		UNIQUE(user_id, device_type, device_identifier)
	);`

	_, err = db.DB.Exec(createUserOTPDevicesTable)
	require.NoError(t, err, "Failed to create user_otp_devices table")

	// Insert test user
	_, err = db.DB.Exec("INSERT INTO users (username, email) VALUES ('testuser', 'test@example.com')")
	require.NoError(t, err)

	var userID string
	err = db.DB.QueryRow("SELECT id FROM users WHERE username = 'testuser'").Scan(&userID)
	require.NoError(t, err)

	// Test session creation
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = db.DB.Exec(`
		INSERT INTO user_sessions (user_id, session_token, refresh_token, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, "session_token_123", "refresh_token_456", expiresAt)
	require.NoError(t, err)

	// Test OTP device creation
	_, err = db.DB.Exec(`
		INSERT INTO user_otp_devices (user_id, device_type, device_identifier, secret_key)
		VALUES ($1, $2, $3, $4)
	`, userID, "sms", "+1234567890", "secret_key_123")
	require.NoError(t, err)

	// Test unique constraint on user+device_type+device_identifier
	_, err = db.DB.Exec(`
		INSERT INTO user_otp_devices (user_id, device_type, device_identifier, secret_key)
		VALUES ($1, $2, $3, $4)
	`, userID, "sms", "+1234567890", "secret_key_456")
	assert.Error(t, err, "Should fail due to unique constraint")

	// Test cascade delete
	_, err = db.DB.Exec("DELETE FROM users WHERE id = $1", userID)
	require.NoError(t, err)

	// Check that sessions and OTP devices were deleted
	var sessionCount, otpCount int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM user_sessions WHERE user_id = $1", userID).Scan(&sessionCount)
	require.NoError(t, err)
	assert.Equal(t, 0, sessionCount, "Sessions should be deleted when user is deleted")

	err = db.DB.QueryRow("SELECT COUNT(*) FROM user_otp_devices WHERE user_id = $1", userID).Scan(&otpCount)
	require.NoError(t, err)
	assert.Equal(t, 0, otpCount, "OTP devices should be deleted when user is deleted")
}

// TestAuditEventTables tests audit event table structure
func TestAuditEventTables(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create users table first (required for foreign key)
	createUsersTable := `
	CREATE TABLE users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL
	);`
	_, err := db.DB.Exec(createUsersTable)
	require.NoError(t, err)

	// Create authentication_events table
	createAuthEventsTable := `
	CREATE TABLE authentication_events (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID REFERENCES users(id),
		event_type VARCHAR(50) NOT NULL,
		authentication_method VARCHAR(50),
		ip_address INET,
		user_agent TEXT,
		success BOOLEAN NOT NULL,
		failure_reason TEXT,
		metadata JSONB,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.DB.Exec(createAuthEventsTable)
	require.NoError(t, err, "Failed to create authentication_events table")

	// Create authorization_events table
	createAuthzEventsTable := `
	CREATE TABLE authorization_events (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID REFERENCES users(id),
		resource VARCHAR(100) NOT NULL,
		action VARCHAR(100) NOT NULL,
		resource_id VARCHAR(255),
		facility_id UUID,
		granted BOOLEAN NOT NULL,
		reason TEXT,
		ip_address INET,
		user_agent TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.DB.Exec(createAuthzEventsTable)
	require.NoError(t, err, "Failed to create authorization_events table")

	// Insert test user
	_, err = db.DB.Exec("INSERT INTO users (username, email) VALUES ('testuser', 'test@example.com')")
	require.NoError(t, err)

	var userID string
	err = db.DB.QueryRow("SELECT id FROM users WHERE username = 'testuser'").Scan(&userID)
	require.NoError(t, err)

	// Test authentication event insertion
	_, err = db.DB.Exec(`
		INSERT INTO authentication_events (user_id, event_type, authentication_method, success, ip_address)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, "login", "password", true, "192.168.1.1")
	require.NoError(t, err)

	// Test authorization event insertion
	_, err = db.DB.Exec(`
		INSERT INTO authorization_events (user_id, resource, action, granted, ip_address)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, "patients", "read", true, "192.168.1.1")
	require.NoError(t, err)

	// Test JSONB metadata
	_, err = db.DB.Exec(`
		INSERT INTO authentication_events (user_id, event_type, success, metadata)
		VALUES ($1, $2, $3, $4)
	`, userID, "mfa_enabled", true, `{"device_type": "sms", "phone": "+1234567890"}`)
	require.NoError(t, err)

	// Verify events were created
	var authEventCount, authzEventCount int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM authentication_events WHERE user_id = $1", userID).Scan(&authEventCount)
	require.NoError(t, err)
	assert.Equal(t, 2, authEventCount, "Should have 2 authentication events")

	err = db.DB.QueryRow("SELECT COUNT(*) FROM authorization_events WHERE user_id = $1", userID).Scan(&authzEventCount)
	require.NoError(t, err)
	assert.Equal(t, 1, authzEventCount, "Should have 1 authorization event")
}

// TestDataMigrationScripts tests the data migration scripts for default roles and permissions
func TestDataMigrationScripts(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Create all required tables
	setupAllTables(t, db)

	// Insert default roles
	insertDefaultRoles := `
	INSERT INTO roles (name, description, is_system_role) VALUES
	('super_admin', 'Super Administrator with full system access', true),
	('facility_admin', 'Facility Administrator with facility-level access', true),
	('doctor', 'Medical Doctor with patient care access', true),
	('nurse', 'Nurse with patient care access', true),
	('receptionist', 'Receptionist with patient registration access', true),
	('patient', 'Patient with self-service access', true),
	('lab_technician', 'Laboratory Technician with lab access', true),
	('pharmacist', 'Pharmacist with pharmacy access', true);`

	_, err := db.DB.Exec(insertDefaultRoles)
	require.NoError(t, err, "Failed to insert default roles")

	// Insert default permissions
	insertDefaultPermissions := `
	INSERT INTO permissions (name, description, resource, action) VALUES
	('view_patients', 'View patient information', 'patients', 'read'),
	('create_patients', 'Create new patient records', 'patients', 'create'),
	('update_patients', 'Update patient information', 'patients', 'update'),
	('delete_patients', 'Delete patient records', 'patients', 'delete'),
	('view_medical_records', 'View medical records', 'medical_records', 'read'),
	('create_medical_records', 'Create medical records', 'medical_records', 'create'),
	('update_medical_records', 'Update medical records', 'medical_records', 'update'),
	('view_appointments', 'View appointments', 'appointments', 'read'),
	('create_appointments', 'Create appointments', 'appointments', 'create'),
	('update_appointments', 'Update appointments', 'appointments', 'update'),
	('delete_appointments', 'Delete appointments', 'appointments', 'delete'),
	('view_billing', 'View billing information', 'billing', 'read'),
	('create_billing', 'Create billing records', 'billing', 'create'),
	('update_billing', 'Update billing records', 'billing', 'update'),
	('view_users', 'View user accounts', 'users', 'read'),
	('create_users', 'Create user accounts', 'users', 'create'),
	('update_users', 'Update user accounts', 'users', 'update'),
	('delete_users', 'Delete user accounts', 'users', 'delete'),
	('view_system_logs', 'View system logs', 'system', 'read'),
	('manage_roles', 'Manage user roles and permissions', 'roles', 'manage'),
	('view_audit_trail', 'View audit trail', 'audit', 'read');`

	_, err = db.DB.Exec(insertDefaultPermissions)
	require.NoError(t, err, "Failed to insert default permissions")

	// Verify default roles were created
	var roleCount int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM roles").Scan(&roleCount)
	require.NoError(t, err)
	assert.Equal(t, 8, roleCount, "Should have 8 default roles")

	// Verify default permissions were created
	var permissionCount int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM permissions").Scan(&permissionCount)
	require.NoError(t, err)
	assert.Equal(t, 21, permissionCount, "Should have 21 default permissions")

	// Test role-permission assignments
	assignRolePermissions := `
	INSERT INTO role_permissions (role_id, permission_id)
	SELECT r.id, p.id FROM roles r, permissions p
	WHERE r.name = 'super_admin';`

	_, err = db.DB.Exec(assignRolePermissions)
	require.NoError(t, err, "Failed to assign permissions to super_admin role")

	// Verify super_admin has all permissions
	var superAdminPermissionCount int
	err = db.DB.QueryRow(`
		SELECT COUNT(*) FROM role_permissions rp
		JOIN roles r ON rp.role_id = r.id
		WHERE r.name = 'super_admin'
	`).Scan(&superAdminPermissionCount)
	require.NoError(t, err)
	assert.Equal(t, 21, superAdminPermissionCount, "Super admin should have all permissions")
}

// setupAllTables creates all tables needed for comprehensive testing
func setupAllTables(t *testing.T, db *TestDatabase) {
	// Create users table
	createUsersTable := `
	CREATE TABLE users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255),
		password_salt VARCHAR(255),
		is_active BOOLEAN DEFAULT true,
		is_locked BOOLEAN DEFAULT false,
		failed_login_attempts INTEGER DEFAULT 0,
		last_login_at TIMESTAMP,
		locked_until TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		created_by UUID REFERENCES users(id),
		updated_by UUID REFERENCES users(id)
	);`
	_, err := db.DB.Exec(createUsersTable)
	require.NoError(t, err)

	// Create roles table
	createRolesTable := `
	CREATE TABLE roles (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(100) UNIQUE NOT NULL,
		description TEXT,
		is_system_role BOOLEAN DEFAULT false,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = db.DB.Exec(createRolesTable)
	require.NoError(t, err)

	// Create permissions table
	createPermissionsTable := `
	CREATE TABLE permissions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(100) UNIQUE NOT NULL,
		description TEXT,
		resource VARCHAR(100) NOT NULL,
		action VARCHAR(100) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(resource, action)
	);`
	_, err = db.DB.Exec(createPermissionsTable)
	require.NoError(t, err)

	// Create role_permissions table
	createRolePermissionsTable := `
	CREATE TABLE role_permissions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
		permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
		granted_by UUID,
		granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(role_id, permission_id)
	);`
	_, err = db.DB.Exec(createRolePermissionsTable)
	require.NoError(t, err)
} 