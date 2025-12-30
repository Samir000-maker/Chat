use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    limits: HashMap<String, UserLimit>,
    max_requests: u32,
    window: Duration,
}

struct UserLimit {
    count: u32,
    reset_time: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            limits: HashMap::new(),
            max_requests,
            window,
        }
    }

    pub fn check(&mut self, user_id: &str) -> bool {
        let now = Instant::now();

        match self.limits.get_mut(user_id) {
            Some(limit) => {
                // Check if window has expired
                if now >= limit.reset_time {
                    limit.count = 1;
                    limit.reset_time = now + self.window;
                    true
                } else if limit.count >= self.max_requests {
                    false
                } else {
                    limit.count += 1;
                    true
                }
            }
            None => {
                self.limits.insert(
                    user_id.to_string(),
                    UserLimit {
                        count: 1,
                        reset_time: now + self.window,
                    },
                );
                true
            }
        }
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.limits.retain(|_, limit| now < limit.reset_time);
    }

    /// Get current count for a user
    pub fn get_count(&self, user_id: &str) -> Option<u32> {
        self.limits.get(user_id).map(|limit| limit.count)
    }

    /// Reset a user's rate limit
    pub fn reset_user(&mut self, user_id: &str) {
        self.limits.remove(user_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_rate_limit_basic() {
        let mut limiter = RateLimiter::new(3, Duration::from_millis(100));
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(!limiter.check("user1")); // Should be rate limited
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let mut limiter = RateLimiter::new(2, Duration::from_millis(50));
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(!limiter.check("user1"));

        sleep(Duration::from_millis(60));
        assert!(limiter.check("user1")); // Window reset, should allow again
    }

    #[test]
    fn test_rate_limit_multiple_users() {
        let mut limiter = RateLimiter::new(2, Duration::from_millis(100));
        assert!(limiter.check("user1"));
        assert!(limiter.check("user2"));
        assert!(limiter.check("user1"));
        assert!(limiter.check("user2"));
        
        assert!(!limiter.check("user1")); // user1 exceeded
        assert!(!limiter.check("user2")); // user2 exceeded
    }

    #[test]
    fn test_cleanup() {
        let mut limiter = RateLimiter::new(5, Duration::from_millis(50));
        limiter.check("user1");
        limiter.check("user2");
        
        assert_eq!(limiter.limits.len(), 2);
        sleep(Duration::from_millis(60));
        limiter.cleanup();
        assert_eq!(limiter.limits.len(), 0);
    }

    #[test]
    fn test_reset_user() {
        let mut limiter = RateLimiter::new(1, Duration::from_millis(100));
        assert!(limiter.check("user1"));
        assert!(!limiter.check("user1"));

        limiter.reset_user("user1");
        assert!(limiter.check("user1")); // Should work after reset
    }
}
