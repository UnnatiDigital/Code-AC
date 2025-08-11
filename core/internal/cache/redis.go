package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bmad-method/hmis-core/internal/models"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

// RedisCache implements caching for sessions and permissions
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(addr, password string, db int) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisCache{client: client}, nil
}

// Close closes the Redis connection
func (c *RedisCache) Close() error {
	return c.client.Close()
}

// Session caching methods

// SetSession stores a user session in cache
func (c *RedisCache) SetSession(ctx context.Context, session *models.UserSession, ttl time.Duration) error {
	key := fmt.Sprintf("session:%s", session.SessionToken)
	
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	err = c.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set session in cache: %w", err)
	}

	return nil
}

// GetSession retrieves a user session from cache
func (c *RedisCache) GetSession(ctx context.Context, sessionToken string) (*models.UserSession, error) {
	key := fmt.Sprintf("session:%s", sessionToken)
	
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found in cache")
		}
		return nil, fmt.Errorf("failed to get session from cache: %w", err)
	}

	var session models.UserSession
	err = json.Unmarshal([]byte(data), &session)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// DeleteSession removes a user session from cache
func (c *RedisCache) DeleteSession(ctx context.Context, sessionToken string) error {
	key := fmt.Sprintf("session:%s", sessionToken)
	
	err := c.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete session from cache: %w", err)
	}

	return nil
}

// DeleteUserSessions removes all sessions for a user
func (c *RedisCache) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	pattern := fmt.Sprintf("session:*")
	
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get session keys: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	// Get all sessions and filter by user ID
	for _, key := range keys {
		data, err := c.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var session models.UserSession
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			continue
		}

		if session.UserID == userID {
			c.client.Del(ctx, key)
		}
	}

	return nil
}

// RefreshSession extends the TTL of a session
func (c *RedisCache) RefreshSession(ctx context.Context, sessionToken string, ttl time.Duration) error {
	key := fmt.Sprintf("session:%s", sessionToken)
	
	exists, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	}

	if exists == 0 {
		return fmt.Errorf("session not found in cache")
	}

	err = c.client.Expire(ctx, key, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to refresh session TTL: %w", err)
	}

	return nil
}

// Permission caching methods

// SetUserPermissions stores user permissions in cache
func (c *RedisCache) SetUserPermissions(ctx context.Context, userID uuid.UUID, permissions []string, ttl time.Duration) error {
	key := fmt.Sprintf("user_permissions:%s", userID)
	
	data, err := json.Marshal(permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	err = c.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set user permissions in cache: %w", err)
	}

	return nil
}

// GetUserPermissions retrieves user permissions from cache
func (c *RedisCache) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	key := fmt.Sprintf("user_permissions:%s", userID)
	
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("user permissions not found in cache")
		}
		return nil, fmt.Errorf("failed to get user permissions from cache: %w", err)
	}

	var permissions []string
	err = json.Unmarshal([]byte(data), &permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user permissions: %w", err)
	}

	return permissions, nil
}

// DeleteUserPermissions removes user permissions from cache
func (c *RedisCache) DeleteUserPermissions(ctx context.Context, userID uuid.UUID) error {
	key := fmt.Sprintf("user_permissions:%s", userID)
	
	err := c.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete user permissions from cache: %w", err)
	}

	return nil
}

// CheckUserPermission checks if a user has a specific permission
func (c *RedisCache) CheckUserPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	permissions, err := c.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm == permission {
			return true, nil
		}
	}

	return false, nil
}

// Role caching methods

// SetRolePermissions stores role permissions in cache
func (c *RedisCache) SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissions []string, ttl time.Duration) error {
	key := fmt.Sprintf("role_permissions:%s", roleID)
	
	data, err := json.Marshal(permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal role permissions: %w", err)
	}

	err = c.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set role permissions in cache: %w", err)
	}

	return nil
}

// GetRolePermissions retrieves role permissions from cache
func (c *RedisCache) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	key := fmt.Sprintf("role_permissions:%s", roleID)
	
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("role permissions not found in cache")
		}
		return nil, fmt.Errorf("failed to get role permissions from cache: %w", err)
	}

	var permissions []string
	err = json.Unmarshal([]byte(data), &permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal role permissions: %w", err)
	}

	return permissions, nil
}

// DeleteRolePermissions removes role permissions from cache
func (c *RedisCache) DeleteRolePermissions(ctx context.Context, roleID uuid.UUID) error {
	key := fmt.Sprintf("role_permissions:%s", roleID)
	
	err := c.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete role permissions from cache: %w", err)
	}

	return nil
}

// Rate limiting methods

// IncrementLoginAttempts increments failed login attempts for a user
func (c *RedisCache) IncrementLoginAttempts(ctx context.Context, username string, ttl time.Duration) (int, error) {
	key := fmt.Sprintf("login_attempts:%s", username)
	
	attempts, err := c.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to increment login attempts: %w", err)
	}

	// Set TTL on first attempt
	if attempts == 1 {
		err = c.client.Expire(ctx, key, ttl).Err()
		if err != nil {
			return 0, fmt.Errorf("failed to set TTL for login attempts: %w", err)
		}
	}

	return int(attempts), nil
}

// GetLoginAttempts gets the number of failed login attempts for a user
func (c *RedisCache) GetLoginAttempts(ctx context.Context, username string) (int, error) {
	key := fmt.Sprintf("login_attempts:%s", username)
	
	attempts, err := c.client.Get(ctx, key).Int()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get login attempts: %w", err)
	}

	return attempts, nil
}

// ResetLoginAttempts resets failed login attempts for a user
func (c *RedisCache) ResetLoginAttempts(ctx context.Context, username string) error {
	key := fmt.Sprintf("login_attempts:%s", username)
	
	err := c.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}

	return nil
}

// OTP caching methods

// SetOTP stores an OTP in cache
func (c *RedisCache) SetOTP(ctx context.Context, identifier string, otp string, ttl time.Duration) error {
	key := fmt.Sprintf("otp:%s", identifier)
	
	err := c.client.Set(ctx, key, otp, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set OTP in cache: %w", err)
	}

	return nil
}

// GetOTP retrieves an OTP from cache
func (c *RedisCache) GetOTP(ctx context.Context, identifier string) (string, error) {
	key := fmt.Sprintf("otp:%s", identifier)
	
	otp, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("OTP not found in cache")
		}
		return "", fmt.Errorf("failed to get OTP from cache: %w", err)
	}

	return otp, nil
}

// DeleteOTP removes an OTP from cache
func (c *RedisCache) DeleteOTP(ctx context.Context, identifier string) error {
	key := fmt.Sprintf("otp:%s", identifier)
	
	err := c.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete OTP from cache: %w", err)
	}

	return nil
}

// Utility methods

// ClearAll clears all cached data (use with caution)
func (c *RedisCache) ClearAll(ctx context.Context) error {
	err := c.client.FlushDB(ctx).Err()
	if err != nil {
		return fmt.Errorf("failed to clear all cache: %w", err)
	}

	return nil
}

// GetStats returns cache statistics
func (c *RedisCache) GetStats(ctx context.Context) (map[string]interface{}, error) {
	info, err := c.client.Info(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis info: %w", err)
	}

	// Parse basic stats
	stats := map[string]interface{}{
		"info": info,
	}

	// Get memory usage
	memory, err := c.client.MemoryUsage(ctx, "").Result()
	if err == nil {
		stats["memory_usage"] = memory
	}

	// Get database size
	dbSize, err := c.client.DBSize(ctx).Result()
	if err == nil {
		stats["db_size"] = dbSize
	}

	return stats, nil
} 