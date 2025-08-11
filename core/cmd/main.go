package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/bmad-method/hmis-core/internal/controllers"
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

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Configure CORS
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{
		"http://localhost:3000",
		"http://localhost:3001",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:3001",
	}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{
		"Origin",
		"Content-Type",
		"Accept",
		"Authorization",
		"X-Requested-With",
	}
	corsConfig.AllowCredentials = true
	corsConfig.MaxAge = 12 * time.Hour

	router.Use(cors.New(corsConfig))

	// Initialize controllers
	patientController := controllers.NewPatientController(dbConn)

	// Run database migrations
	migrator := database.NewMigrator(dbConn)
	if err := migrator.LoadMigrations("./internal/database/migrations"); err != nil {
		log.Printf("Warning: Could not load migrations: %v", err)
	} else {
		ctx := context.Background()
		if err := migrator.Migrate(ctx); err != nil {
			log.Printf("Warning: Could not run migrations: %v", err)
		} else {
			log.Println("Database migrations completed successfully")
		}
	}

	// Setup basic routes
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "BMad-Method Healthcare HMIS Core Platform",
			"version": "1.0.0",
			"status":  "running",
		})
	})

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
			"version":   "1.0.0",
		})
	})

	// API status endpoint
	router.GET("/api/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "HMIS Core Platform",
			"status":  "operational",
			"time":    time.Now().Format(time.RFC3339),
		})
	})

	// API routes group
	api := router.Group("/api")
	{
		// Patient routes
		patients := api.Group("/patients")
		{
			patients.POST("/register", patientController.RegisterPatient)
			patients.GET("/:id", patientController.GetPatient)
			patients.GET("/uhid/:uhid", patientController.GetPatientByUHID)
			patients.POST("/search", patientController.SearchPatients)
			patients.PUT("/:id", patientController.UpdatePatient)
			patients.DELETE("/:id", patientController.DeletePatient)
			
			// Patient addresses
			patients.GET("/:id/addresses", patientController.GetPatientAddresses)
			
			// Patient allergies
			patients.GET("/:id/allergies", patientController.GetPatientAllergies)
			
			// Patient insurance
			patients.GET("/:id/insurance", patientController.GetPatientInsurance)
			
			// Biometric routes
			patients.POST("/:id/biometric", patientController.RegisterBiometricData)
		}

		// Biometric search
		api.POST("/patients/search/biometric", patientController.SearchByBiometric)

		// Duplicate check
		api.POST("/patients/check-duplicate", patientController.CheckDuplicatePatient)

		// Dashboard
		api.GET("/dashboard", patientController.GetDashboardData)

		// Statistics
		api.GET("/statistics/patients", patientController.GetPatientStatistics)

		// Utility routes
		utils := api.Group("/utils")
		{
			utils.GET("/validate/:type", patientController.ValidateDocument)
		}
	}

	// Get server configuration
	serverAddr := viper.GetString("server.address")
	if serverAddr == "" {
		serverAddr = ":8082"
	}

	log.Printf("Starting HMIS Core Platform server on %s", serverAddr)
	log.Printf("Health check available at: http://localhost%s/health", serverAddr)
	log.Printf("API status available at: http://localhost%s/api/status", serverAddr)
	log.Printf("Frontend should be accessible at: http://localhost:3000")

	// Start the server
	if err := router.Run(serverAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
} 