package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/k8s-security-baseline-checker/pkg/errors"
)

// RateLimiter implements token bucket rate limiting
// Enterprise requirement: API rate limiting (token bucket or fixed window) with configurable thresholds
type RateLimiter struct {
	mu            sync.RWMutex
	buckets       map[string]*tokenBucket
	refillRate    int           // tokens per second
	bucketSize    int           // maximum tokens
	cleanupTicker *time.Ticker
}

type tokenBucket struct {
	tokens     int
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(refillRate, bucketSize int, cleanupInterval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets:    make(map[string]*tokenBucket),
		refillRate: refillRate,
		bucketSize: bucketSize,
	}

	// Start cleanup goroutine to remove unused buckets
	rl.cleanupTicker = time.NewTicker(cleanupInterval)
	go rl.cleanup()

	return rl
}

// cleanup removes unused buckets periodically
func (rl *RateLimiter) cleanup() {
	for range rl.cleanupTicker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.buckets {
			bucket.mu.Lock()
			// Remove bucket if unused for more than 1 hour
			if now.Sub(bucket.lastRefill) > time.Hour {
				delete(rl.buckets, key)
			}
			bucket.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// getBucket gets or creates a token bucket for a key
func (rl *RateLimiter) getBucket(key string) *tokenBucket {
	rl.mu.RLock()
	bucket, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		bucket, exists = rl.buckets[key]
		if !exists {
			bucket = &tokenBucket{
				tokens:     rl.bucketSize,
				lastRefill: time.Now(),
			}
			rl.buckets[key] = bucket
		}
		rl.mu.Unlock()
	}

	return bucket
}

// refill refills tokens based on elapsed time
func (tb *tokenBucket) refill(refillRate int, bucketSize int) {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tokensToAdd := int(elapsed.Seconds() * float64(refillRate))

	if tokensToAdd > 0 {
		tb.tokens = min(tb.tokens+tokensToAdd, bucketSize)
		tb.lastRefill = now
	}
}

// Allow checks if a request is allowed (has tokens available)
func (rl *RateLimiter) Allow(key string) bool {
	bucket := rl.getBucket(key)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	bucket.refill(rl.refillRate, rl.bucketSize)

	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

// RateLimitMiddleware creates rate limiting middleware
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use IP address as the key for rate limiting
		key := c.ClientIP()

		// Allow request if tokens available
		if !limiter.Allow(key) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": errors.NewRateLimitError("rate limit exceeded").UserMessage(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByTokenMiddleware creates rate limiting middleware that uses token/user ID as key
func RateLimitByTokenMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get user ID from context (set by auth middleware)
		key := GetUserID(c)
		if key == "" {
			// Fallback to IP if no user ID
			key = c.ClientIP()
		}

		if !limiter.Allow(key) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": errors.NewRateLimitError("rate limit exceeded").UserMessage(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
