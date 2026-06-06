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
	rate       float64   // tokens per second
	tokens     float64   // current available tokens
	maxTokens  float64   // max burst size
	lastRefill time.Time // last token refill time
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
		tokens:     float64(ratePerSecond), // start full
		maxTokens:  float64(ratePerSecond),
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.tokens += elapsed * r.rate
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
	r.lastRefill = now

	if r.tokens < 1 {
		// Need to wait for a token
		waitTime := time.Duration((1 - r.tokens) / r.rate * float64(time.Second))
		r.mu.Unlock()
		time.Sleep(waitTime)
		r.mu.Lock()
		r.tokens = 0
		r.lastRefill = time.Now()
	} else {
		r.tokens--
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
	r.maxTokens = float64(ratePerSecond)
}

// GetRate returns the current rate limit
func (r *RateLimiter) GetRate() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int(r.rate)
}
