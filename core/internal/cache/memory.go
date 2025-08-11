package cache

import (
	"context"
	"sync"
	"time"
)

// InMemoryCache implements Cache interface using in-memory storage
type InMemoryCache struct {
	data map[string]cacheItem
	mu   sync.RWMutex
}

type cacheItem struct {
	value      interface{}
	expiration time.Time
}

// NewInMemoryCache creates a new in-memory cache
func NewInMemoryCache() *InMemoryCache {
	cache := &InMemoryCache{
		data: make(map[string]cacheItem),
	}
	
	// Start cleanup goroutine
	go cache.cleanup()
	
	return cache
}

// Set stores a value in the cache
func (c *InMemoryCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	var exp time.Time
	if expiration > 0 {
		exp = time.Now().Add(expiration)
	}
	
	c.data[key] = cacheItem{
		value:      value,
		expiration: exp,
	}
	
	return nil
}

// Get retrieves a value from the cache
func (c *InMemoryCache) Get(ctx context.Context, key string) (interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	item, exists := c.data[key]
	if !exists {
		return nil, ErrKeyNotFound
	}
	
	// Check if item has expired
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		// Remove expired item
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.data, key)
		c.mu.Unlock()
		c.mu.RLock()
		return nil, ErrKeyNotFound
	}
	
	return item.value, nil
}

// Delete removes a key from the cache
func (c *InMemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	delete(c.data, key)
	return nil
}

// Exists checks if a key exists in the cache
func (c *InMemoryCache) Exists(ctx context.Context, key string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	item, exists := c.data[key]
	if !exists {
		return false, nil
	}
	
	// Check if item has expired
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		return false, nil
	}
	
	return true, nil
}

// Expire sets expiration for a key
func (c *InMemoryCache) Expire(ctx context.Context, key string, expiration time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	item, exists := c.data[key]
	if !exists {
		return ErrKeyNotFound
	}
	
	item.expiration = time.Now().Add(expiration)
	c.data[key] = item
	
	return nil
}

// TTL returns the time to live for a key
func (c *InMemoryCache) TTL(ctx context.Context, key string) (time.Duration, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	item, exists := c.data[key]
	if !exists {
		return 0, ErrKeyNotFound
	}
	
	if item.expiration.IsZero() {
		return -1, nil // No expiration
	}
	
	ttl := time.Until(item.expiration)
	if ttl <= 0 {
		return 0, ErrKeyNotFound // Expired
	}
	
	return ttl, nil
}

// Incr increments a numeric value
func (c *InMemoryCache) Incr(ctx context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	item, exists := c.data[key]
	if !exists {
		// Create new item with value 1
		c.data[key] = cacheItem{
			value: int64(1),
		}
		return 1, nil
	}
	
	// Check if item has expired
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		delete(c.data, key)
		c.data[key] = cacheItem{
			value: int64(1),
		}
		return 1, nil
	}
	
	// Try to increment the value
	switch v := item.value.(type) {
	case int64:
		item.value = v + 1
		c.data[key] = item
		return item.value.(int64), nil
	case int:
		item.value = int64(v) + 1
		c.data[key] = item
		return item.value.(int64), nil
	default:
		return 0, ErrInvalidType
	}
}

// IncrBy increments a numeric value by a specified amount
func (c *InMemoryCache) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	item, exists := c.data[key]
	if !exists {
		// Create new item with the specified value
		c.data[key] = cacheItem{
			value: value,
		}
		return value, nil
	}
	
	// Check if item has expired
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		delete(c.data, key)
		c.data[key] = cacheItem{
			value: value,
		}
		return value, nil
	}
	
	// Try to increment the value
	switch v := item.value.(type) {
	case int64:
		item.value = v + value
		c.data[key] = item
		return item.value.(int64), nil
	case int:
		item.value = int64(v) + value
		c.data[key] = item
		return item.value.(int64), nil
	default:
		return 0, ErrInvalidType
	}
}

// Decr decrements a numeric value
func (c *InMemoryCache) Decr(ctx context.Context, key string) (int64, error) {
	return c.IncrBy(ctx, key, -1)
}

// DecrBy decrements a numeric value by a specified amount
func (c *InMemoryCache) DecrBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.IncrBy(ctx, key, -value)
}

// HSet sets a field in a hash
func (c *InMemoryCache) HSet(ctx context.Context, key string, field string, value interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	item, exists := c.data[key]
	if !exists {
		// Create new hash
		hash := make(map[string]interface{})
		hash[field] = value
		c.data[key] = cacheItem{
			value: hash,
		}
		return nil
	}
	
	// Check if item has expired
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		hash := make(map[string]interface{})
		hash[field] = value
		c.data[key] = cacheItem{
			value: hash,
		}
		return nil
	}
	
	// Try to set field in hash
	if hash, ok := item.value.(map[string]interface{}); ok {
		hash[field] = value
		item.value = hash
		c.data[key] = item
		return nil
	}
	
	return ErrInvalidType
}

// HGet gets a field from a hash
func (c *InMemoryCache) HGet(ctx context.Context, key string, field string) (interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	item, exists := c.data[key]
	if !exists {
		return nil, ErrKeyNotFound
	}
	
	// Check if item has expired
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		return nil, ErrKeyNotFound
	}
	
	// Try to get field from hash
	if hash, ok := item.value.(map[string]interface{}); ok {
		if value, exists := hash[field]; exists {
			return value, nil
		}
		return nil, ErrKeyNotFound
	}
	
	return nil, ErrInvalidType
}

// HGetAll gets all fields from a hash
func (c *InMemoryCache) HGetAll(ctx context.Context, key string) (map[string]interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	item, exists := c.data[key]
	if !exists {
		return nil, ErrKeyNotFound
	}
	
	// Check if item has expired
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		return nil, ErrKeyNotFound
	}
	
	// Try to get all fields from hash
	if hash, ok := item.value.(map[string]interface{}); ok {
		result := make(map[string]interface{})
		for k, v := range hash {
			result[k] = v
		}
		return result, nil
	}
	
	return nil, ErrInvalidType
}

// HDel deletes fields from a hash
func (c *InMemoryCache) HDel(ctx context.Context, key string, fields ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	item, exists := c.data[key]
	if !exists {
		return ErrKeyNotFound
	}
	
	// Check if item has expired
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		return ErrKeyNotFound
	}
	
	// Try to delete fields from hash
	if hash, ok := item.value.(map[string]interface{}); ok {
		for _, field := range fields {
			delete(hash, field)
		}
		item.value = hash
		c.data[key] = item
		return nil
	}
	
	return ErrInvalidType
}

// Close closes the cache (no-op for in-memory cache)
func (c *InMemoryCache) Close() error {
	return nil
}

// Ping checks if the cache is accessible (always true for in-memory cache)
func (c *InMemoryCache) Ping(ctx context.Context) error {
	return nil
}

// cleanup removes expired items from the cache
func (c *InMemoryCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, item := range c.data {
			if !item.expiration.IsZero() && now.After(item.expiration) {
				delete(c.data, key)
			}
		}
		c.mu.Unlock()
	}
} 