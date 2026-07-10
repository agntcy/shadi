use std::collections::hash_map::DefaultHasher;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

async fn retry<F, Fut, T, E>(f: F, max_attempts: u32, base_delay: Duration) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    debug_assert!(max_attempts > 0, "max_attempts must be at least 1");

    let mut last_error = None;

    for attempt in 0..max_attempts {
        match f().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < max_attempts {
                    let exponent = attempt.min(31);
                    let max_delay = base_delay.saturating_mul(1u32 << exponent);
                    sleep(full_jitter(max_delay, attempt)).await;
                }
            }
        }
    }

    Err(last_error.expect("retry loop ran at least once"))
}

fn full_jitter(max_delay: Duration, attempt: u32) -> Duration {
    let cap = max_delay.as_nanos();
    if cap == 0 {
        return Duration::ZERO;
    }

    let fraction = jitter_unit_interval(attempt);
    Duration::from_nanos(((cap * fraction) / u128::from(u64::MAX)) as u64)
}

fn jitter_unit_interval(attempt: u32) -> u128 {
    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    attempt.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    u128::from(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn succeeds_on_first_attempt() {
        let result = retry(|| async { Ok::<_, &str>(42) }, 3, Duration::from_millis(10)).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn returns_last_error_after_exhausting_attempts() {
        let calls = Rc::new(Cell::new(0u32));
        let calls_clone = Rc::clone(&calls);

        let result = retry(
            move || {
                let calls = Rc::clone(&calls_clone);
                async move {
                    calls.set(calls.get() + 1);
                    Err::<(), &str>("permanent failure")
                }
            },
            3,
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(result, Err("permanent failure"));
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test]
    async fn succeeds_after_transient_failures() {
        let attempts = Rc::new(AtomicU32::new(0));
        let attempts_clone = Rc::clone(&attempts);

        let result = retry(
            move || {
                let attempts = Rc::clone(&attempts_clone);
                async move {
                    let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 3 {
                        Err("not yet")
                    } else {
                        Ok("ok")
                    }
                }
            },
            5,
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(result, Ok("ok"));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn full_jitter_stays_within_bounds() {
        let cap = Duration::from_secs(10);
        for attempt in 0..100 {
            let delay = full_jitter(cap, attempt);
            assert!(delay <= cap);
        }
    }
}

fn main() {}
