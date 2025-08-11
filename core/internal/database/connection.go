package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

// Config holds database configuration
type Config struct {
	Driver          string
	Host            string
	Port            string
	User            string
	Password        string
	Database        string
	SSLMode         string
	SQLitePath      string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// Connection represents a database connection
type Connection struct {
	DB     *sql.DB
	Config *Config
}

// NewConfig creates a new database configuration from environment
func NewConfig() *Config {
	driver := viper.GetString("database.driver")
	if driver == "" {
		driver = "postgres" // default to postgres
	}

	config := &Config{
		Driver:          driver,
		MaxOpenConns:    viper.GetInt("database.max_open_conns"),
		MaxIdleConns:    viper.GetInt("database.max_idle_conns"),
		ConnMaxLifetime: viper.GetDuration("database.conn_max_lifetime"),
		ConnMaxIdleTime: viper.GetDuration("database.conn_max_idle_time"),
	}

	if driver == "sqlite3" {
		config.SQLitePath = viper.GetString("database.sqlite.path")
		if config.SQLitePath == "" {
			config.SQLitePath = "./hmis_dev.db"
		}
	} else {
		// PostgreSQL configuration
		config.Host = viper.GetString("database.postgres.host")
		config.Port = viper.GetString("database.postgres.port")
		config.User = viper.GetString("database.postgres.user")
		config.Password = viper.GetString("database.postgres.password")
		config.Database = viper.GetString("database.postgres.name")
		config.SSLMode = viper.GetString("database.postgres.sslmode")
	}

	return config
}

// NewConnection creates a new database connection
func NewConnection(config *Config) (*Connection, error) {
	var dsn string
	var driver string

	if config.Driver == "sqlite3" {
		driver = "sqlite3"
		dsn = config.SQLitePath
	} else {
		driver = "postgres"
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			config.Host, config.Port, config.User, config.Password, config.Database, config.SSLMode)
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Printf("Connected to %s database", config.Driver)

	return &Connection{
		DB:     db,
		Config: config,
	}, nil
}

// Close closes the database connection
func (c *Connection) Close() error {
	if c.DB != nil {
		return c.DB.Close()
	}
	return nil
}

// Ping checks if the database is accessible
func (c *Connection) Ping(ctx context.Context) error {
	return c.DB.PingContext(ctx)
}

// Stats returns database connection statistics
func (c *Connection) Stats() sql.DBStats {
	return c.DB.Stats()
}

// Begin starts a new transaction
func (c *Connection) Begin() (*sql.Tx, error) {
	return c.DB.Begin()
}

// BeginTx starts a new transaction with context
func (c *Connection) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return c.DB.BeginTx(ctx, opts)
}

// Exec executes a query without returning any rows
func (c *Connection) Exec(query string, args ...interface{}) (sql.Result, error) {
	return c.DB.Exec(query, args...)
}

// ExecContext executes a query without returning any rows with context
func (c *Connection) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return c.DB.ExecContext(ctx, query, args...)
}

// Query executes a query that returns rows
func (c *Connection) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return c.DB.Query(query, args...)
}

// QueryContext executes a query that returns rows with context
func (c *Connection) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return c.DB.QueryContext(ctx, query, args...)
}

// QueryRow executes a query that returns a single row
func (c *Connection) QueryRow(query string, args ...interface{}) *sql.Row {
	return c.DB.QueryRow(query, args...)
}

// QueryRowContext executes a query that returns a single row with context
func (c *Connection) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return c.DB.QueryRowContext(ctx, query, args...)
}

// Prepare creates a prepared statement
func (c *Connection) Prepare(query string) (*sql.Stmt, error) {
	return c.DB.Prepare(query)
}

// PrepareContext creates a prepared statement with context
func (c *Connection) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return c.DB.PrepareContext(ctx, query)
}

// LogStats logs database connection statistics
func (c *Connection) LogStats() {
	stats := c.Stats()
	log.Printf("Database Stats - Open: %d, InUse: %d, Idle: %d, WaitCount: %d, WaitDuration: %v, MaxIdleClosed: %d, MaxLifetimeClosed: %d",
		stats.OpenConnections, stats.InUse, stats.Idle, stats.WaitCount, stats.WaitDuration, stats.MaxIdleClosed, stats.MaxLifetimeClosed)
} 