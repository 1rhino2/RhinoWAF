package conditional

import (
	"sync"
	"time"
)

type Schedule struct {
	StartHour int
	EndHour   int
	Days      []time.Weekday
	Limit     int
}

type Config struct {
	Enabled      bool
	DefaultLimit int
	Schedules    []Schedule
}

type Limiter struct {
	config   Config
	requests map[string][]time.Time
	mu       sync.RWMutex
}

func NewLimiter(config Config) *Limiter {
	if config.DefaultLimit == 0 {
		config.DefaultLimit = 100
	}

	l := &Limiter{
		config:   config,
		requests: make(map[string][]time.Time),
	}

	go l.cleanupLoop()
	return l
}

func (l *Limiter) Check(ip string) bool {
	if !l.config.Enabled {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	limit := l.getCurrentLimit(now)

	cutoff := now.Add(-time.Minute)
	l.requests[ip] = l.filterOld(l.requests[ip], cutoff)

	if len(l.requests[ip]) >= limit {
		return false
	}

	l.requests[ip] = append(l.requests[ip], now)
	return true
}

func (l *Limiter) getCurrentLimit(now time.Time) int {
	currentHour := now.Hour()
	currentDay := now.Weekday()

	for _, schedule := range l.config.Schedules {
		if l.matchesSchedule(schedule, currentHour, currentDay) {
			return schedule.Limit
		}
	}

	return l.config.DefaultLimit
}

func (l *Limiter) matchesSchedule(schedule Schedule, hour int, day time.Weekday) bool {
	if hour < schedule.StartHour || hour >= schedule.EndHour {
		return false
	}

	if len(schedule.Days) == 0 {
		return true
	}

	for _, scheduleDay := range schedule.Days {
		if scheduleDay == day {
			return true
		}
	}

	return false
}

func (l *Limiter) filterOld(timestamps []time.Time, cutoff time.Time) []time.Time {
	filtered := make([]time.Time, 0)
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			filtered = append(filtered, ts)
		}
	}
	return filtered
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		l.cleanup()
	}
}

func (l *Limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-2 * time.Minute)
	for ip, timestamps := range l.requests {
		filtered := l.filterOld(timestamps, cutoff)
		if len(filtered) > 0 {
			l.requests[ip] = filtered
		} else {
			delete(l.requests, ip)
		}
	}
}
