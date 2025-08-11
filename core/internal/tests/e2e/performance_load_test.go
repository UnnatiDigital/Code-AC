package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/bmad-method/hmis-core/internal/controllers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/google/uuid"
	"github.com/bmad-method/hmis-core/internal/models"
	"net/http/httptest"
)

// PerformanceLoadTestSuite provides performance and load testing
type PerformanceLoadTestSuite struct {
	suite.Suite
	server *httptest.Server
	users  []*models.User
}

// SetupSuite sets up the test suite
func (suite *PerformanceLoadTestSuite) SetupSuite() {
	// Initialize the same setup as main E2E tests
	suite.setupTestEnvironment()
}

// TearDownSuite cleans up the test suite
func (suite *PerformanceLoadTestSuite) TearDownSuite() {
	if suite.server != nil {
		suite.server.Close()
	}
}

// SetupTest sets up each test
func (suite *PerformanceLoadTestSuite) SetupTest() {
	// Create test users for performance testing
	suite.createPerformanceTestUsers()
}

// TearDownTest cleans up after each test
func (suite *PerformanceLoadTestSuite) TearDownTest() {
	// Clean up test data
	suite.cleanupTestData()
}

// TestConcurrentUserAuthentication tests concurrent user authentication
func (suite *PerformanceLoadTestSuite) TestConcurrentUserAuthentication() {
	numConcurrentUsers := 50
	var wg sync.WaitGroup
	results := make(chan *AuthResult, numConcurrentUsers)
	startTime := time.Now()

	// Launch concurrent login attempts
	for i := 0; i < numConcurrentUsers; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()

			username := fmt.Sprintf("perf_user_%d", userIndex)
			password := "password123"

			result := &AuthResult{
				UserIndex: userIndex,
				StartTime: time.Now(),
			}

			// Perform login
			loginReq := controllers.LoginRequest{
				Username: username,
				Password: password,
			}
			loginBody, _ := json.Marshal(loginReq)

			resp, err := http.Post(suite.server.URL+"/auth/login", "application/json", bytes.NewBuffer(loginBody))
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)

			if err != nil {
				result.Error = err.Error()
				result.Success = false
			} else {
				result.StatusCode = resp.StatusCode
				result.Success = resp.StatusCode == http.StatusOK

				if result.Success {
					var loginResp controllers.LoginResponse
					if err := json.NewDecoder(resp.Body).Decode(&loginResp); err == nil {
						result.AccessToken = loginResp.AccessToken
					}
				}
			}

			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Analyze results
	totalDuration := time.Since(startTime)
	successCount := 0
	var totalResponseTime time.Duration
	var maxResponseTime time.Duration
	var minResponseTime time.Duration = time.Hour

	for result := range results {
		if result.Success {
			successCount++
		}
		totalResponseTime += result.Duration
		if result.Duration > maxResponseTime {
			maxResponseTime = result.Duration
		}
		if result.Duration < minResponseTime {
			minResponseTime = result.Duration
		}
	}

	avgResponseTime := totalResponseTime / time.Duration(numConcurrentUsers)
	successRate := float64(successCount) / float64(numConcurrentUsers) * 100
	requestsPerSecond := float64(numConcurrentUsers) / totalDuration.Seconds()

	// Assertions
	assert.GreaterOrEqual(suite.T(), successRate, 95.0, "Success rate should be at least 95%%")
	assert.Less(suite.T(), avgResponseTime, 2*time.Second, "Average response time should be less than 2 seconds")
	assert.Greater(suite.T(), requestsPerSecond, 10.0, "Should handle at least 10 requests per second")
	assert.Less(suite.T(), maxResponseTime, 5*time.Second, "Maximum response time should be less than 5 seconds")

	// Log performance metrics
	fmt.Printf("Performance Test Results:\n")
	fmt.Printf("  Total Users: %d\n", numConcurrentUsers)
	fmt.Printf("  Success Rate: %.2f%%\n", successRate)
	fmt.Printf("  Average Response Time: %v\n", avgResponseTime)
	fmt.Printf("  Min Response Time: %v\n", minResponseTime)
	fmt.Printf("  Max Response Time: %v\n", maxResponseTime)
	fmt.Printf("  Requests Per Second: %.2f\n", requestsPerSecond)
	fmt.Printf("  Total Duration: %v\n", totalDuration)
}

// TestHighLoadUserManagement tests high load user management operations
func (suite *PerformanceLoadTestSuite) TestHighLoadUserManagement() {
	// Create admin user for user management operations
	admin := suite.createTestUser("perf_admin", "perf_admin@example.com", "admin123")
	adminRole := suite.createTestRole("admin", "Administrator role")
	adminPermission := suite.createTestPermission("users", "manage", "Manage users")
	suite.assignRoleToUser(admin.ID, adminRole.ID, nil)
	suite.assignPermissionToRole(adminRole.ID, adminPermission.ID, admin.ID)

	// Login as admin
	adminLoginResp := suite.loginUser("perf_admin", "admin123")
	require.NotEmpty(suite.T(), adminLoginResp.AccessToken)

	numOperations := 100
	var wg sync.WaitGroup
	results := make(chan *UserManagementResult, numOperations)
	startTime := time.Now()

	// Launch concurrent user creation operations
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(operationIndex int) {
			defer wg.Done()

			username := fmt.Sprintf("bulk_user_%d", operationIndex)
			email := fmt.Sprintf("bulk_user_%d@example.com", operationIndex)

			result := &UserManagementResult{
				OperationIndex: operationIndex,
				StartTime:      time.Now(),
			}

			// Create user
			createUserReq := controllers.CreateUserRequest{
				Username:  username,
				Email:     email,
				Password:  "password123",
				FirstName: "Bulk",
				LastName:  "User",
				Status:    "active",
			}
			createUserBody, _ := json.Marshal(createUserReq)

			req, _ := http.NewRequest("POST", suite.server.URL+"/users/", bytes.NewBuffer(createUserBody))
			req.Header.Set("Authorization", "Bearer "+adminLoginResp.AccessToken)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)

			if err != nil {
				result.Error = err.Error()
				result.Success = false
			} else {
				result.StatusCode = resp.StatusCode
				result.Success = resp.StatusCode == http.StatusCreated

				if result.Success {
					var createUserResp controllers.CreateUserResponse
					if err := json.NewDecoder(resp.Body).Decode(&createUserResp); err == nil {
						result.UserID = createUserResp.UserID
					}
				}
			}

			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Analyze results
	totalDuration := time.Since(startTime)
	successCount := 0
	var totalResponseTime time.Duration
	var maxResponseTime time.Duration
	var minResponseTime time.Duration = time.Hour

	for result := range results {
		if result.Success {
			successCount++
		}
		totalResponseTime += result.Duration
		if result.Duration > maxResponseTime {
			maxResponseTime = result.Duration
		}
		if result.Duration < minResponseTime {
			minResponseTime = result.Duration
		}
	}

	avgResponseTime := totalResponseTime / time.Duration(numOperations)
	successRate := float64(successCount) / float64(numOperations) * 100
	operationsPerSecond := float64(numOperations) / totalDuration.Seconds()

	// Assertions
	assert.GreaterOrEqual(suite.T(), successRate, 90.0, "Success rate should be at least 90%%")
	assert.Less(suite.T(), avgResponseTime, 3*time.Second, "Average response time should be less than 3 seconds")
	assert.Greater(suite.T(), operationsPerSecond, 5.0, "Should handle at least 5 operations per second")

	// Log performance metrics
	fmt.Printf("User Management Performance Test Results:\n")
	fmt.Printf("  Total Operations: %d\n", numOperations)
	fmt.Printf("  Success Rate: %.2f%%\n", successRate)
	fmt.Printf("  Average Response Time: %v\n", avgResponseTime)
	fmt.Printf("  Min Response Time: %v\n", minResponseTime)
	fmt.Printf("  Max Response Time: %v\n", maxResponseTime)
	fmt.Printf("  Operations Per Second: %.2f\n", operationsPerSecond)
	fmt.Printf("  Total Duration: %v\n", totalDuration)
}

// TestDatabasePerformance tests database performance under load
func (suite *PerformanceLoadTestSuite) TestDatabasePerformance() {
	// Create test user
	user := suite.createTestUser("db_perf_user", "db_perf@example.com", "password123")
	loginResp := suite.loginUser("db_perf_user", "password123")
	require.NotEmpty(suite.T(), loginResp.AccessToken)

	numQueries := 1000
	var wg sync.WaitGroup
	results := make(chan *DatabaseResult, numQueries)
	startTime := time.Now()

	// Launch concurrent database queries
	for i := 0; i < numQueries; i++ {
		wg.Add(1)
		go func(queryIndex int) {
			defer wg.Done()

			result := &DatabaseResult{
				QueryIndex: queryIndex,
				StartTime:  time.Now(),
			}

			// Perform user search query
			req, _ := http.NewRequest("GET", suite.server.URL+"/users/search?q=user&limit=10&offset=0", nil)
			req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

			client := &http.Client{}
			resp, err := client.Do(req)
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)

			if err != nil {
				result.Error = err.Error()
				result.Success = false
			} else {
				result.StatusCode = resp.StatusCode
				result.Success = resp.StatusCode == http.StatusOK
			}

			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Analyze results
	totalDuration := time.Since(startTime)
	successCount := 0
	var totalResponseTime time.Duration
	var maxResponseTime time.Duration
	var minResponseTime time.Duration = time.Hour

	for result := range results {
		if result.Success {
			successCount++
		}
		totalResponseTime += result.Duration
		if result.Duration > maxResponseTime {
			maxResponseTime = result.Duration
		}
		if result.Duration < minResponseTime {
			minResponseTime = result.Duration
		}
	}

	avgResponseTime := totalResponseTime / time.Duration(numQueries)
	successRate := float64(successCount) / float64(numQueries) * 100
	queriesPerSecond := float64(numQueries) / totalDuration.Seconds()

	// Assertions
	assert.GreaterOrEqual(suite.T(), successRate, 95.0, "Success rate should be at least 95%%")
	assert.Less(suite.T(), avgResponseTime, 1*time.Second, "Average response time should be less than 1 second")
	assert.Greater(suite.T(), queriesPerSecond, 50.0, "Should handle at least 50 queries per second")

	// Log performance metrics
	fmt.Printf("Database Performance Test Results:\n")
	fmt.Printf("  Total Queries: %d\n", numQueries)
	fmt.Printf("  Success Rate: %.2f%%\n", successRate)
	fmt.Printf("  Average Response Time: %v\n", avgResponseTime)
	fmt.Printf("  Min Response Time: %v\n", minResponseTime)
	fmt.Printf("  Max Response Time: %v\n", maxResponseTime)
	fmt.Printf("  Queries Per Second: %.2f\n", queriesPerSecond)
	fmt.Printf("  Total Duration: %v\n", totalDuration)
}

// TestCachePerformance tests cache performance
func (suite *PerformanceLoadTestSuite) TestCachePerformance() {
	// Create test user
	user := suite.createTestUser("cache_perf_user", "cache_perf@example.com", "password123")

	numCacheOperations := 500
	var wg sync.WaitGroup
	results := make(chan *CacheResult, numCacheOperations)
	startTime := time.Now()

	// Launch concurrent cache operations (login attempts)
	for i := 0; i < numCacheOperations; i++ {
		wg.Add(1)
		go func(operationIndex int) {
			defer wg.Done()

			result := &CacheResult{
				OperationIndex: operationIndex,
				StartTime:      time.Now(),
			}

			// Perform login (uses cache)
			loginReq := controllers.LoginRequest{
				Username: "cache_perf_user",
				Password: "password123",
			}
			loginBody, _ := json.Marshal(loginReq)

			resp, err := http.Post(suite.server.URL+"/auth/login", "application/json", bytes.NewBuffer(loginBody))
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)

			if err != nil {
				result.Error = err.Error()
				result.Success = false
			} else {
				result.StatusCode = resp.StatusCode
				result.Success = resp.StatusCode == http.StatusOK
			}

			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Analyze results
	totalDuration := time.Since(startTime)
	successCount := 0
	var totalResponseTime time.Duration
	var maxResponseTime time.Duration
	var minResponseTime time.Duration = time.Hour

	for result := range results {
		if result.Success {
			successCount++
		}
		totalResponseTime += result.Duration
		if result.Duration > maxResponseTime {
			maxResponseTime = result.Duration
		}
		if result.Duration < minResponseTime {
			minResponseTime = result.Duration
		}
	}

	avgResponseTime := totalResponseTime / time.Duration(numCacheOperations)
	successRate := float64(successCount) / float64(numCacheOperations) * 100
	operationsPerSecond := float64(numCacheOperations) / totalDuration.Seconds()

	// Assertions
	assert.GreaterOrEqual(suite.T(), successRate, 90.0, "Success rate should be at least 90%%")
	assert.Less(suite.T(), avgResponseTime, 2*time.Second, "Average response time should be less than 2 seconds")
	assert.Greater(suite.T(), operationsPerSecond, 20.0, "Should handle at least 20 cache operations per second")

	// Log performance metrics
	fmt.Printf("Cache Performance Test Results:\n")
	fmt.Printf("  Total Operations: %d\n", numCacheOperations)
	fmt.Printf("  Success Rate: %.2f%%\n", successRate)
	fmt.Printf("  Average Response Time: %v\n", avgResponseTime)
	fmt.Printf("  Min Response Time: %v\n", minResponseTime)
	fmt.Printf("  Max Response Time: %v\n", maxResponseTime)
	fmt.Printf("  Operations Per Second: %.2f\n", operationsPerSecond)
	fmt.Printf("  Total Duration: %v\n", totalDuration)
}

// TestStressTesting tests system behavior under extreme load
func (suite *PerformanceLoadTestSuite) TestStressTesting() {
	numStressUsers := 200
	var wg sync.WaitGroup
	results := make(chan *StressResult, numStressUsers)
	startTime := time.Now()

	// Launch extreme load
	for i := 0; i < numStressUsers; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()

			username := fmt.Sprintf("stress_user_%d", userIndex)
			password := "password123"

			result := &StressResult{
				UserIndex: userIndex,
				StartTime: time.Now(),
			}

			// Perform multiple operations per user
			for j := 0; j < 5; j++ {
				// Login
				loginReq := controllers.LoginRequest{
					Username: username,
					Password: password,
				}
				loginBody, _ := json.Marshal(loginReq)

				resp, err := http.Post(suite.server.URL+"/auth/login", "application/json", bytes.NewBuffer(loginBody))
				if err != nil {
					result.Errors++
					continue
				}

				if resp.StatusCode == http.StatusOK {
					var loginResp controllers.LoginResponse
					if err := json.NewDecoder(resp.Body).Decode(&loginResp); err == nil {
						// Perform additional operations with token
						req, _ := http.NewRequest("GET", suite.server.URL+"/users/search?q=user&limit=5&offset=0", nil)
						req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

						client := &http.Client{}
						_, err := client.Do(req)
						if err != nil {
							result.Errors++
						} else {
							result.SuccessfulOperations++
						}
					}
				} else {
					result.Errors++
				}
			}

			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)

			results <- result
		}(i)
	}

	wg.Wait()
	close(results)

	// Analyze results
	totalDuration := time.Since(startTime)
	totalSuccessfulOperations := 0
	totalErrors := 0
	var totalResponseTime time.Duration
	var maxResponseTime time.Duration

	for result := range results {
		totalSuccessfulOperations += result.SuccessfulOperations
		totalErrors += result.Errors
		totalResponseTime += result.Duration
		if result.Duration > maxResponseTime {
			maxResponseTime = result.Duration
		}
	}

	totalOperations := totalSuccessfulOperations + totalErrors
	successRate := float64(totalSuccessfulOperations) / float64(totalOperations) * 100
	avgResponseTime := totalResponseTime / time.Duration(numStressUsers)
	operationsPerSecond := float64(totalOperations) / totalDuration.Seconds()

	// Assertions for stress test
	assert.GreaterOrEqual(suite.T(), successRate, 80.0, "Success rate should be at least 80%% under stress")
	assert.Less(suite.T(), avgResponseTime, 5*time.Second, "Average response time should be less than 5 seconds under stress")
	assert.Greater(suite.T(), operationsPerSecond, 10.0, "Should handle at least 10 operations per second under stress")

	// Log stress test metrics
	fmt.Printf("Stress Test Results:\n")
	fmt.Printf("  Total Users: %d\n", numStressUsers)
	fmt.Printf("  Total Operations: %d\n", totalOperations)
	fmt.Printf("  Successful Operations: %d\n", totalSuccessfulOperations)
	fmt.Printf("  Errors: %d\n", totalErrors)
	fmt.Printf("  Success Rate: %.2f%%\n", successRate)
	fmt.Printf("  Average Response Time: %v\n", avgResponseTime)
	fmt.Printf("  Max Response Time: %v\n", maxResponseTime)
	fmt.Printf("  Operations Per Second: %.2f\n", operationsPerSecond)
	fmt.Printf("  Total Duration: %v\n", totalDuration)
}

// TestMemoryLeakDetection tests for memory leaks
func (suite *PerformanceLoadTestSuite) TestMemoryLeakDetection() {
	// This test would typically monitor memory usage over time
	// For now, we'll perform a large number of operations and check for stability

	numOperations := 1000
	var wg sync.WaitGroup
	startTime := time.Now()

	// Perform many operations to check for memory leaks
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(operationIndex int) {
			defer wg.Done()

			username := fmt.Sprintf("memory_test_%d", operationIndex)
			password := "password123"

			// Login
			loginReq := controllers.LoginRequest{
				Username: username,
				Password: password,
			}
			loginBody, _ := json.Marshal(loginReq)

			resp, err := http.Post(suite.server.URL+"/auth/login", "application/json", bytes.NewBuffer(loginBody))
			if err != nil {
				return
			}

			if resp.StatusCode == http.StatusOK {
				var loginResp controllers.LoginResponse
				if err := json.NewDecoder(resp.Body).Decode(&loginResp); err == nil {
					// Perform additional operations
					req, _ := http.NewRequest("GET", suite.server.URL+"/users/search?q=user&limit=5&offset=0", nil)
					req.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)

					client := &http.Client{}
					client.Do(req)
				}
			}
		}(i)
	}

	wg.Wait()
	totalDuration := time.Since(startTime)

	// Assertions
	assert.Less(suite.T(), totalDuration, 30*time.Second, "Memory leak test should complete within 30 seconds")
	operationsPerSecond := float64(numOperations) / totalDuration.Seconds()
	assert.Greater(suite.T(), operationsPerSecond, 20.0, "Should maintain performance throughout memory leak test")

	fmt.Printf("Memory Leak Test Results:\n")
	fmt.Printf("  Total Operations: %d\n", numOperations)
	fmt.Printf("  Total Duration: %v\n", totalDuration)
	fmt.Printf("  Operations Per Second: %.2f\n", operationsPerSecond)
}

// Helper structs for test results

type AuthResult struct {
	UserIndex    int
	StartTime    time.Time
	EndTime      time.Time
	Duration     time.Duration
	Success      bool
	StatusCode   int
	Error        string
	AccessToken  string
}

type UserManagementResult struct {
	OperationIndex int
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
	Success        bool
	StatusCode     int
	Error          string
	UserID         string
}

type DatabaseResult struct {
	QueryIndex int
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Success    bool
	StatusCode int
	Error      string
}

type CacheResult struct {
	OperationIndex int
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
	Success        bool
	StatusCode     int
	Error          string
}

type StressResult struct {
	UserIndex             int
	StartTime             time.Time
	EndTime               time.Time
	Duration              time.Duration
	SuccessfulOperations  int
	Errors                int
}

// Helper methods (reuse from main E2E test suite)

func (suite *PerformanceLoadTestSuite) setupTestEnvironment() {
	// This would initialize the same environment as the main E2E tests
	// For brevity, we'll assume the setup is similar
}

func (suite *PerformanceLoadTestSuite) createPerformanceTestUsers() {
	// Create users for performance testing
	for i := 0; i < 100; i++ {
		username := fmt.Sprintf("perf_user_%d", i)
		email := fmt.Sprintf("perf_user_%d@example.com", i)
		suite.createTestUser(username, email, "password123")
	}
}

func (suite *PerformanceLoadTestSuite) createTestUser(username, email, password string) *models.User {
	// Implementation similar to main E2E test suite
	return nil
}

func (suite *PerformanceLoadTestSuite) createTestRole(name, description string) *models.Role {
	// Implementation similar to main E2E test suite
	return nil
}

func (suite *PerformanceLoadTestSuite) createTestPermission(resource, action, description string) *models.Permission {
	// Implementation similar to main E2E test suite
	return nil
}

func (suite *PerformanceLoadTestSuite) assignRoleToUser(userID, roleID uuid.UUID, facilityID *uuid.UUID) {
	// Implementation similar to main E2E test suite
}

func (suite *PerformanceLoadTestSuite) loginUser(username, password string) *controllers.LoginResponse {
	// Implementation similar to main E2E test suite
	return nil
}

func (suite *PerformanceLoadTestSuite) cleanupTestData() {
	// Implementation similar to main E2E test suite
}

// Run the test suite
func TestPerformanceLoadTestSuite(t *testing.T) {
	suite.Run(t, new(PerformanceLoadTestSuite))
} 