package compliance

import (
	"fmt"
	"sync"
	"time"
)

const (
	// MaxRateLimit is the maximum allowed requests per second
	MaxRateLimit = 100
	// DefaultRateLimit is the default requests per second
	DefaultRateLimit = 2
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	rate      float64
	nextPermit time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a rate limiter with the given requests per second
func NewRateLimiter(ratePerSecond int) *RateLimiter {
	if ratePerSecond <= 0 {
		ratePerSecond = DefaultRateLimit
	}
	if ratePerSecond > MaxRateLimit {
		fmt.Printf("[!] Rate limit capped from %d to %d req/s (maximum allowed)\n", ratePerSecond, MaxRateLimit)
		ratePerSecond = MaxRateLimit
	}
	return &RateLimiter{
		rate:       float64(ratePerSecond),
		nextPermit: time.Now(),
	}
}

// Wait blocks until a token is available
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	now := time.Now()
	permit := r.nextPermit
	if permit.Before(now) {
		permit = now
	}
	interval := time.Duration(float64(time.Second) / r.rate)
	r.nextPermit = permit.Add(interval)
	r.mu.Unlock()

	if wait := time.Until(permit); wait > 0 {
		time.Sleep(wait)
	}
}

// SetRate updates the rate limit (requests per second)
func (r *RateLimiter) SetRate(ratePerSecond int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ratePerSecond <= 0 {
		ratePerSecond = DefaultRateLimit
	}
	if ratePerSecond > MaxRateLimit {
		fmt.Printf("[!] Rate limit capped from %d to %d req/s (maximum allowed)\n", ratePerSecond, MaxRateLimit)
		ratePerSecond = MaxRateLimit
	}
	r.rate = float64(ratePerSecond)
	if r.nextPermit.Before(time.Now()) {
		r.nextPermit = time.Now()
	}
}

// GetRate returns the current rate limit
func (r *RateLimiter) GetRate() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int(r.rate)
}
