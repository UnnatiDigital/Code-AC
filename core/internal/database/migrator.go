package database

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Migration represents a database migration
type Migration struct {
	Version     string
	Description string
	SQL         string
	Applied     bool
	AppliedAt   *time.Time
}

// Migrator handles database migrations
type Migrator struct {
	conn       *Connection
	migrations []Migration
}

// NewMigrator creates a new migration runner
func NewMigrator(conn *Connection) *Migrator {
	return &Migrator{
		conn:       conn,
		migrations: []Migration{},
	}
}

// LoadMigrations loads migration files from the migrations directory
func (m *Migrator) LoadMigrations(migrationsPath string) error {
	files, err := ioutil.ReadDir(migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}

		// Extract version from filename (e.g., "001_create_users_table.sql" -> "001")
		version := strings.Split(file.Name(), "_")[0]
		if len(version) == 0 {
			continue
		}

		// Read migration file
		content, err := ioutil.ReadFile(filepath.Join(migrationsPath, file.Name()))
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file.Name(), err)
		}

		// Extract description from SQL comment
		description := extractDescription(string(content))

		migration := Migration{
			Version:     version,
			Description: description,
			SQL:         string(content),
		}

		m.migrations = append(m.migrations, migration)
	}

	// Sort migrations by version
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})

	return nil
}

// extractDescription extracts description from SQL comment
func extractDescription(sql string) string {
	lines := strings.Split(sql, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-- Description:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "-- Description:"))
		}
	}
	return "No description"
}

// createMigrationsTable creates the migrations tracking table
func (m *Migrator) createMigrationsTable(ctx context.Context) error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS migrations (
		version VARCHAR(50) PRIMARY KEY,
		description TEXT,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := m.conn.ExecContext(ctx, createTableSQL)
	return err
}

// getAppliedMigrations gets list of applied migrations
func (m *Migrator) getAppliedMigrations(ctx context.Context) (map[string]time.Time, error) {
	applied := make(map[string]time.Time)

	// Check if migrations table exists first
	var tableExists bool
	err := m.conn.QueryRowContext(ctx, "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'migrations')").Scan(&tableExists)
	if err != nil {
		return applied, fmt.Errorf("failed to check if migrations table exists: %w", err)
	}

	if !tableExists {
		// Table doesn't exist, return empty map
		return applied, nil
	}

	rows, err := m.conn.QueryContext(ctx, "SELECT version, applied_at FROM migrations ORDER BY version")
	if err != nil {
		return applied, err
	}
	defer rows.Close()

	for rows.Next() {
		var version string
		var appliedAt time.Time
		if err := rows.Scan(&version, &appliedAt); err != nil {
			return applied, err
		}
		applied[version] = appliedAt
	}

	return applied, rows.Err()
}

// applyMigration applies a single migration
func (m *Migrator) applyMigration(ctx context.Context, migration Migration) error {
	// Start transaction
	tx, err := m.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute migration SQL
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return fmt.Errorf("failed to execute migration %s: %w", migration.Version, err)
	}

	// Record migration as applied
	insertSQL := "INSERT INTO migrations (version, description) VALUES ($1, $2)"
	if _, err := tx.ExecContext(ctx, insertSQL, migration.Version, migration.Description); err != nil {
		return fmt.Errorf("failed to record migration %s: %w", migration.Version, err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration %s: %w", migration.Version, err)
	}

	return nil
}

// Migrate runs all pending migrations
func (m *Migrator) Migrate(ctx context.Context) error {
	// Create migrations table if it doesn't exist
	if err := m.createMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get applied migrations
	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Apply pending migrations
	for _, migration := range m.migrations {
		if _, exists := applied[migration.Version]; exists {
			log.Printf("Migration %s already applied", migration.Version)
			continue
		}

		log.Printf("Applying migration %s: %s", migration.Version, migration.Description)
		if err := m.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}

		log.Printf("Successfully applied migration %s", migration.Version)
	}

	return nil
}

// Status returns the status of all migrations
func (m *Migrator) Status(ctx context.Context) error {
	// Create migrations table if it doesn't exist
	if err := m.createMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get applied migrations
	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	fmt.Printf("\nMigration Status:\n")
	fmt.Printf("%-10s %-50s %-20s\n", "Version", "Description", "Status")
	fmt.Printf("%s\n", strings.Repeat("-", 80))

	for _, migration := range m.migrations {
		status := "Pending"
		if appliedAt, exists := applied[migration.Version]; exists {
			status = fmt.Sprintf("Applied at %s", appliedAt.Format("2006-01-02 15:04:05"))
		}

		fmt.Printf("%-10s %-50s %-20s\n", migration.Version, migration.Description, status)
	}

	fmt.Printf("\nTotal migrations: %d\n", len(m.migrations))
	appliedCount := len(applied)
	fmt.Printf("Applied: %d\n", appliedCount)
	fmt.Printf("Pending: %d\n", len(m.migrations)-appliedCount)

	return nil
}

// Rollback rolls back the last migration (not implemented for safety)
func (m *Migrator) Rollback(ctx context.Context) error {
	return fmt.Errorf("rollback not implemented for safety reasons")
} 