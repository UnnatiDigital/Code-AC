package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

type Migration struct {
	ID       string
	Filename string
	SQL      string
}

func main() {
	// Load configuration
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("../config")
	viper.AddConfigPath("../../config")
	
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Could not read config file: %v", err)
		log.Println("Using default configuration...")
	}

	// Initialize database connection
	dbConfig := getDatabaseConfig()
	db, err := connectToDatabase(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create migrations table if it doesn't exist
	if err := createMigrationsTable(db); err != nil {
		log.Fatalf("Failed to create migrations table: %v", err)
	}

	// Get list of migration files
	migrations, err := getMigrationFiles()
	if err != nil {
		log.Fatalf("Failed to get migration files: %v", err)
	}

	// Get executed migrations
	executedMigrations, err := getExecutedMigrations(db)
	if err != nil {
		log.Fatalf("Failed to get executed migrations: %v", err)
	}

	// Find pending migrations
	pendingMigrations := getPendingMigrations(migrations, executedMigrations)

	if len(pendingMigrations) == 0 {
		log.Println("No pending migrations found.")
		return
	}

	log.Printf("Found %d pending migrations", len(pendingMigrations))

	// Execute pending migrations
	for _, migration := range pendingMigrations {
		log.Printf("Executing migration: %s", migration.Filename)
		
		if err := executeMigration(db, migration); err != nil {
			log.Fatalf("Failed to execute migration %s: %v", migration.Filename, err)
		}
		
		log.Printf("Successfully executed migration: %s", migration.Filename)
	}

	log.Println("All migrations completed successfully!")
}

func getDatabaseConfig() map[string]string {
	driver := viper.GetString("database.driver")
	if driver == "" {
		driver = "postgres"
	}

	config := map[string]string{
		"driver": driver,
	}

	if driver == "sqlite3" {
		config["path"] = viper.GetString("database.sqlite.path")
		if config["path"] == "" {
			config["path"] = "./hmis_dev.db"
		}
	} else {
		config["host"] = viper.GetString("database.postgres.host")
		config["port"] = viper.GetString("database.postgres.port")
		config["user"] = viper.GetString("database.postgres.user")
		config["password"] = viper.GetString("database.postgres.password")
		config["database"] = viper.GetString("database.postgres.name")
		config["sslmode"] = viper.GetString("database.postgres.sslmode")
	}

	return config
}

func connectToDatabase(config map[string]string) (*sql.DB, error) {
	var dsn string
	var driver string

	if config["driver"] == "sqlite3" {
		driver = "sqlite3"
		dsn = config["path"]
	} else {
		driver = "postgres"
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			config["host"], config["port"], config["user"], config["password"], config["database"], config["sslmode"])
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Printf("Connected to %s database", config["driver"])
	return db, nil
}

func createMigrationsTable(db *sql.DB) error {
	// First, check if the table exists and what structure it has
	checkQuery := `
	SELECT column_name, data_type 
	FROM information_schema.columns 
	WHERE table_name = 'migrations'`
	
	rows, err := db.Query(checkQuery)
	if err != nil {
		// Table doesn't exist, create it
		query := `
		CREATE TABLE IF NOT EXISTS migrations (
			id VARCHAR(255) PRIMARY KEY,
			filename VARCHAR(255) NOT NULL,
			executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`
		_, err := db.Exec(query)
		return err
	}
	defer rows.Close()
	
	// Table exists, check if it has the right structure
	hasID := false
	hasFilename := false
	
	for rows.Next() {
		var columnName, dataType string
		if err := rows.Scan(&columnName, &dataType); err != nil {
			return err
		}
		if columnName == "id" {
			hasID = true
		}
		if columnName == "filename" {
			hasFilename = true
		}
	}
	
	// If the table doesn't have the right structure, recreate it
	if !hasID || !hasFilename {
		log.Println("Recreating migrations table with correct structure...")
		
		// Drop the existing table
		_, err := db.Exec("DROP TABLE IF EXISTS migrations")
		if err != nil {
			return err
		}
		
		// Create the table with correct structure
		query := `
		CREATE TABLE migrations (
			id VARCHAR(255) PRIMARY KEY,
			filename VARCHAR(255) NOT NULL,
			executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`
		_, err = db.Exec(query)
		return err
	}
	
	return nil
}

func getMigrationFiles() ([]Migration, error) {
	migrationsDir := "./internal/database/migrations"
	if _, err := os.Stat(migrationsDir); os.IsNotExist(err) {
		migrationsDir = "../internal/database/migrations"
	}
	if _, err := os.Stat(migrationsDir); os.IsNotExist(err) {
		migrationsDir = "../../internal/database/migrations"
	}

	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, err
	}

	var migrations []Migration
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}

		// Extract migration ID from filename (e.g., "001_create_users_table.sql" -> "001")
		parts := strings.Split(file.Name(), "_")
		if len(parts) < 2 {
			continue
		}
		migrationID := parts[0]

		// Read migration file content
		content, err := os.ReadFile(filepath.Join(migrationsDir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", file.Name(), err)
		}

		migrations = append(migrations, Migration{
			ID:       migrationID,
			Filename: file.Name(),
			SQL:      string(content),
		})
	}

	// Sort migrations by ID
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].ID < migrations[j].ID
	})

	return migrations, nil
}

func getExecutedMigrations(db *sql.DB) (map[string]bool, error) {
	query := `SELECT id FROM migrations`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	executed := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		executed[id] = true
	}

	return executed, nil
}

func getPendingMigrations(migrations []Migration, executed map[string]bool) []Migration {
	var pending []Migration
	for _, migration := range migrations {
		if !executed[migration.ID] {
			pending = append(pending, migration)
		}
	}
	return pending
}

func executeMigration(db *sql.DB, migration Migration) error {
	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Execute migration SQL
	if _, err := tx.Exec(migration.SQL); err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Record migration as executed
	recordQuery := `INSERT INTO migrations (id, filename) VALUES ($1, $2)`
	if _, err := tx.Exec(recordQuery, migration.ID, migration.Filename); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	return tx.Commit()
} 