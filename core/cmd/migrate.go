package main

import (
	"context"
	"log"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/bmad-method/hmis-core/internal/database"
)

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
	dbConfig := database.NewConfig()
	dbConn, err := database.NewConnection(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbConn.Close()

	// Create migrator
	migrator := database.NewMigrator(dbConn)

	// Load migrations
	migrationsPath := filepath.Join("internal", "database", "migrations")
	if err := migrator.LoadMigrations(migrationsPath); err != nil {
		log.Fatalf("Failed to load migrations: %v", err)
	}

	// Run migrations
	ctx := context.Background()
	if err := migrator.Migrate(ctx); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	log.Println("Database migrations completed successfully!")
} 