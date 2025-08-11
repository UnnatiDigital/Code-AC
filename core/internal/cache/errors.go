package cache

import "errors"

// Cache error definitions
var (
	ErrKeyNotFound = errors.New("key not found in cache")
	ErrInvalidType = errors.New("invalid type for cache operation")
) 