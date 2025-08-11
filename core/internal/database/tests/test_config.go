package tests

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
)

// TestConfig holds test configuration
type TestConfig struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
}

// GetTestConfig returns test configuration from environment or defaults
func GetTestConfig() *TestConfig {
	return &TestConfig{
		DBHost:     getEnvOrDefault("TEST_DB_HOST", "localhost"),
		DBPort:     getEnvOrDefault("TEST_DB_PORT", "5432"),
		DBUser:     getEnvOrDefault("TEST_DB_USER", "hmis_user"),
		DBPassword: getEnvOrDefault("TEST_DB_PASSWORD", "hmis_password"),
		DBName:     getEnvOrDefault("TEST_DB_NAME", "hmis_test"),
	}
}

// SkipIfNoDatabase skips tests if database is not available
func SkipIfNoDatabase(t *testing.T) {
	config := GetTestConfig()
	
	// Check if we can connect to the database
	dsn := getDSN(config.DBHost, config.DBPort, config.DBUser, config.DBPassword, "postgres")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("Database not available: %v", err)
		return
	}
	defer db.Close()
	
	if err := db.Ping(); err != nil {
		t.Skipf("Cannot connect to database: %v", err)
	}
}

// getDSN returns database connection string
func getDSN(host, port, user, password, dbname string) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
}

// TestMain runs before all tests
func TestMain(m *testing.M) {
	// Set up any global test configuration here
	os.Exit(m.Run())
} 