// Compile the actual timer source, without enabling unrelated legacy lib tests.
// Existing tokio-test dev dependency supplies Tokio's test-util feature.
#[path = "../src/timer/ack_timer.rs"]
mod ack_timer;

use std::sync::Arc;

use ack_timer::{AckTimer, AckTimerObserver, ACK_INTERVAL};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::{advance, Duration};

#[derive(Default)]
struct Observer {
    callbacks: usize,
}

#[async_trait]
impl AckTimerObserver for Observer {
    async fn on_ack_timeout(&mut self) {
        self.callbacks += 1;
    }
}

fn fixture() -> (Arc<Mutex<Observer>>, AckTimer<Observer>) {
    let observer = Arc::new(Mutex::new(Observer::default()));
    let timer = AckTimer::new(Arc::downgrade(&observer), ACK_INTERVAL);
    (observer, timer)
}

async fn settle_tasks() {
    // Bounded scheduler turns, never wall-clock sleeps or timing tolerances.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn expiry_rearms_twice_without_stop() {
    let (observer, mut timer) = fixture();
    for expected in 1..=3 {
        assert!(timer.start());
        assert!(timer.is_running());
        settle_tasks().await;
        advance(ACK_INTERVAL - Duration::from_millis(1)).await;
        settle_tasks().await;
        assert_eq!(observer.lock().await.callbacks, expected - 1);
        assert!(timer.is_running());
        advance(Duration::from_millis(1)).await;
        settle_tasks().await;
        assert_eq!(observer.lock().await.callbacks, expected);
        assert!(!timer.is_running());
    }
    timer.stop();
    settle_tasks().await;
    assert_eq!(Arc::strong_count(&observer), 1);
}

#[tokio::test(start_paused = true)]
async fn cancellation_before_fire_does_not_expire_or_poison_restart() {
    let (observer, mut timer) = fixture();
    assert!(timer.start());
    settle_tasks().await;
    advance(ACK_INTERVAL / 2).await;
    timer.stop();
    assert!(!timer.is_running());
    settle_tasks().await;
    advance(ACK_INTERVAL).await;
    settle_tasks().await;
    assert_eq!(observer.lock().await.callbacks, 0);
    assert!(timer.start());
    settle_tasks().await;
    advance(ACK_INTERVAL).await;
    settle_tasks().await;
    assert_eq!(observer.lock().await.callbacks, 1);
    assert!(!timer.is_running());
    timer.stop();
}

#[tokio::test(start_paused = true)]
async fn cancellation_waiting_for_observer_cannot_fire_or_clear_restart() {
    let (observer, mut timer) = fixture();
    let guard = observer.lock().await;
    assert!(timer.start());
    settle_tasks().await;
    advance(ACK_INTERVAL).await;
    settle_tasks().await;
    // Nonvacuous witness: the expired task upgraded the weak observer and
    // holds it while waiting for this guard. No callback has acquired it.
    assert_eq!(Arc::strong_count(&observer), 2);
    assert_eq!(guard.callbacks, 0);
    assert!(timer.is_running());
    timer.stop();
    assert!(timer.start());
    settle_tasks().await;
    // The cancelled waiter released its actual strong reference even though
    // the observer is still locked; its completion did not clear the new start.
    assert_eq!(Arc::strong_count(&observer), 1);
    assert!(timer.is_running());
    drop(guard);
    settle_tasks().await;
    assert_eq!(observer.lock().await.callbacks, 0);
    advance(ACK_INTERVAL - Duration::from_millis(1)).await;
    settle_tasks().await;
    assert_eq!(observer.lock().await.callbacks, 0);
    assert!(timer.is_running());
    advance(Duration::from_millis(1)).await;
    settle_tasks().await;
    assert_eq!(observer.lock().await.callbacks, 1);
    assert!(!timer.is_running());
    timer.stop();
}

#[tokio::test(start_paused = true)]
async fn repeated_start_does_not_move_deadline_or_duplicate_expiry() {
    let (observer, mut timer) = fixture();
    assert!(timer.start());
    assert!(!timer.start());
    settle_tasks().await;
    advance(ACK_INTERVAL / 2).await;
    assert!(!timer.start());
    advance(ACK_INTERVAL / 2).await;
    settle_tasks().await;
    assert_eq!(observer.lock().await.callbacks, 1);
    assert!(!timer.is_running());
    advance(ACK_INTERVAL).await;
    settle_tasks().await;
    assert_eq!(observer.lock().await.callbacks, 1);
    timer.stop();
}
