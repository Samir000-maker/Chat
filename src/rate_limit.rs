use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Debug)]
struct UserLimit {
    count: u32,
    reset_time: Instant,
}

pub struct RateLimiter {
    limits: HashMap<String, UserLimit>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        info!("🚦 RATE LIMITER: Initialized");
        info!("   Max requests: {}", max_requests);
        info!("   Window: {:?}", window);
        
        Self {
            limits: HashMap::new(),
            max_requests,
            window,
        }
    }

    pub fn check(&mut self, user_id: &str) -> bool {
        let now = Instant::now();
        let limit = self.limits.entry(user_id.to_string()).or_insert_with(|| {
            UserLimit {
                count: 0,
                reset_time: now + self.window,
            }
        });

        // Check if window has expired
        if now >= limit.reset_time {
            limit.count = 1;
            limit.reset_time = now + self.window;
            return true;
        }

        // Check if limit exceeded
        if limit.count >= self.max_requests {
            info!("🚦 RATE LIMITER: Limit exceeded for user {}", user_id);
            info!("   Count: {}/{}", limit.count, self.max_requests);
            return false;
        }

        // Increment and allow
        limit.count += 1;
        true
    }

    pub fn reset(&mut self, user_id: &str) {
        self.limits.remove(user_id);
        info!("🚦 RATE LIMITER: Reset for user {}", user_id);
    }

    pub fn clear(&mut self) {
        let count = self.limits.len();
        self.limits.clear();
        info!("🚦 RATE LIMITER: Cleared all limits ({} users)", count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(3, Duration::from_millis(100));
        
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(!limiter.check("user1")); // Should be rate limited

        // Wait for window to reset
        thread::sleep(Duration::from_millis(150));
        assert!(limiter.check("user1")); // Should work again
    }

    #[test]
    fn test_different_users() {
        let mut limiter = RateLimiter::new(2, Duration::from_secs(1));
        
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(!limiter.check("user1")); // user1 limited
        
        assert!(limiter.check("user2")); // user2 should still work
        assert!(limiter.check("user2"));
        assert!(!limiter.check("user2")); // user2 limited
    }
}
