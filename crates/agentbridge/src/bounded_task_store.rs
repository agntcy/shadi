//! A task store with a fixed capacity, for a listener that admits callers
//! nobody vetted: a flood of new tasks cannot grow it without bound.
//!
//! [`InMemoryTaskStore`](a2a_server::InMemoryTaskStore) keeps every task for
//! the life of the process. [`BoundedTaskStore`] keeps at most `capacity`
//! tasks. Tasks fall into three groups:
//!
//! - finished: `Completed`, `Failed`, `Canceled` and `Rejected`;
//! - parked, waiting on the caller: `AuthRequired` and `InputRequired`;
//! - running: every other state, i.e. `Submitted`, `Working` and
//!   `Unspecified`.
//!
//! To admit a new task when full, it evicts the task that finished earliest,
//! or failing that, the task that was parked earliest. It never evicts a
//! running task: when every task is running, `create` fails instead.
//!
//! An `AuthRequired` task also expires once it has been parked for longer than
//! the parked TTL, and from then on reads as a task that never existed.
//! `InputRequired` does not expire, as it may be waiting on a human.
//!
//! Apart from eviction and expiry, the semantics are `InMemoryTaskStore`'s.
//! The parity test below runs the same operations against both stores and
//! compares the results.

use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task, TaskId, TaskState};
use a2a_server::pagination::resolve_page_size;
use a2a_server::task_store::{StoredTask, TaskVersion};
use a2a_server::TaskStore;
use async_trait::async_trait;
use shadi_credential::nonce::NONCE_TTL_SECS;

/// The capacity a listener uses, so that its memory stays bounded when any
/// caller can create tasks. Finished tasks are evicted first, then parked
/// ones.
pub const DEFAULT_TASK_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

/// How long a listener keeps an `AuthRequired` task. A parked challenge is
/// useless once its nonce has expired: the caller can no longer answer it, so
/// the task could only ever take up room.
pub const DEFAULT_PARKED_TTL: Duration = {
    assert!(NONCE_TTL_SECS > 0, "the nonce TTL must be positive");
    Duration::from_secs(NONCE_TTL_SECS.unsigned_abs())
};

/// A [`TaskStore`] holding at most `capacity` tasks.
///
/// The bound is enforced in `create` only. Apart from that eviction, a task
/// disappears only when it expires: every method first drops the
/// `AuthRequired` tasks parked for longer than `parked_ttl`.
pub struct BoundedTaskStore {
    capacity: NonZeroUsize,
    parked_ttl: Duration,
    /// `Instant::now`, unless a test injects its own clock.
    now: Box<dyn Fn() -> Instant + Send + Sync>,
    tasks: Mutex<Tasks>,
}

#[derive(Default)]
struct Tasks {
    entries: HashMap<TaskId, Entry>,
    /// Ids of the finished tasks, the one that finished earliest first. A
    /// finished state never changes (see `update`), so each finished task is
    /// queued once, and it leaves the queue only when it is evicted. Only
    /// `AuthRequired` tasks expire, so the queue always holds exactly the
    /// finished entries.
    terminal: VecDeque<TaskId>,
    /// The `order` the next task to enter a parked state gets.
    next_park: u64,
}

struct Entry {
    stored: StoredTask,
    /// Set while the task is parked.
    parked: Option<Parked>,
}

/// When a task last entered a parked state.
struct Parked {
    /// For the age.
    since: Instant,
    /// For the eviction order: the clock is read under the lock and never goes
    /// back, so a lower `order` was parked no later, and ties are broken.
    order: u64,
}

impl BoundedTaskStore {
    /// An empty store that holds at most `capacity` tasks, and drops an
    /// `AuthRequired` task once it has been parked for longer than
    /// `parked_ttl`. The type rules out a zero capacity, which could hold no
    /// task at all.
    pub fn new(capacity: NonZeroUsize, parked_ttl: Duration) -> Self {
        Self::with_clock(capacity, parked_ttl, Instant::now)
    }

    fn with_clock(
        capacity: NonZeroUsize,
        parked_ttl: Duration,
        now: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self {
            capacity,
            parked_ttl,
            now: Box::new(now),
            tasks: Mutex::new(Tasks::default()),
        }
    }

    /// Locks the tasks and drops the expired ones, so that every method sees
    /// an expired task as one that never existed. Returns the time it swept
    /// at. Poisoning is ignored: the tokio lock that `InMemoryTaskStore` uses
    /// never poisons either.
    fn lock(&self) -> (MutexGuard<'_, Tasks>, Instant) {
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        let now = (self.now)();
        tasks
            .entries
            .retain(|_, entry| !entry.expired(now, self.parked_ttl));
        (tasks, now)
    }
}

impl Entry {
    /// Whether the task is `AuthRequired` and has been parked for longer than
    /// `ttl`. At exactly `ttl` it is still kept.
    fn expired(&self, now: Instant, ttl: Duration) -> bool {
        self.stored.task.status.state == TaskState::AuthRequired
            && self
                .parked
                .as_ref()
                .is_some_and(|parked| now.saturating_duration_since(parked.since) > ttl)
    }
}

/// The parked marker for a task now entering `state`: none unless `state` is
/// parked, and otherwise a new one, taking the next `order`. Every write of a
/// parked state restarts the age, as each `AuthRequired` carries a fresh
/// challenge.
fn park(next_park: &mut u64, state: &TaskState, now: Instant) -> Option<Parked> {
    if !matches!(state, TaskState::AuthRequired | TaskState::InputRequired) {
        return None;
    }
    let order = *next_park;
    *next_park += 1;
    Some(Parked { since: now, order })
}

impl Tasks {
    /// Evicts one task to make room: the one that finished earliest, else the
    /// one parked earliest. Returns false, evicting nothing, when every task is
    /// running.
    fn evict_one(&mut self) -> bool {
        let victim = self.terminal.pop_front().or_else(|| {
            self.entries
                .iter()
                .filter_map(|(id, entry)| Some((entry.parked.as_ref()?.order, id)))
                .min()
                .map(|(_, id)| id.clone())
        });
        match victim {
            Some(id) => self.entries.remove(&id).is_some(),
            None => false,
        }
    }
}

#[async_trait]
impl TaskStore for BoundedTaskStore {
    /// Stores `task` as version 1.
    ///
    /// When the store is full, the expired tasks are already gone, and one
    /// more task is evicted: the one that finished earliest, else the one
    /// parked earliest. If every task is running, nothing is evicted and this
    /// fails with `INTERNAL_ERROR`. Of the A2A codes, `INVALID_REQUEST` would
    /// blame the caller, who sent a valid task, and none names a full store.
    /// Evicting a running task would silently lose its work. The failure is
    /// the server's, so the detail is logged and the client gets the generic
    /// message.
    async fn create(&self, task: Task) -> Result<TaskVersion, A2AError> {
        let (mut guard, now) = self.lock();
        let tasks = &mut *guard;
        if tasks.entries.contains_key(&task.id) {
            return Err(sanitized_internal_error("task already exists"));
        }
        if tasks.entries.len() >= self.capacity.get() && !tasks.evict_one() {
            return Err(sanitized_internal_error(format!(
                "task store is full of running tasks ({} of {})",
                tasks.entries.len(),
                self.capacity
            )));
        }
        let id = task.id.clone();
        let finished = task.status.state.is_terminal();
        let parked = park(&mut tasks.next_park, &task.status.state, now);
        tasks.entries.insert(
            id.clone(),
            Entry {
                stored: StoredTask { task, version: 1 },
                parked,
            },
        );
        if finished {
            tasks.terminal.push_back(id);
        }
        Ok(1)
    }

    async fn update(&self, task: Task) -> Result<TaskVersion, A2AError> {
        let (mut guard, now) = self.lock();
        let tasks = &mut *guard;
        let entry = tasks
            .entries
            .get_mut(&task.id)
            .ok_or_else(|| A2AError::task_not_found(&task.id))?;
        let state = &entry.stored.task.status.state;
        // A finished state can be re-applied (idempotent re-emission, e.g. from
        // cancel flows) but never replaced by a different state.
        if state.is_terminal() && *state != task.status.state {
            return Err(A2AError::invalid_request(format!(
                "task {} is in terminal state {:?} and cannot transition to {:?}",
                task.id, state, task.status.state
            )));
        }
        let finishes = !state.is_terminal() && task.status.state.is_terminal();
        entry.stored.version += 1;
        let version = entry.stored.version;
        if finishes {
            tasks.terminal.push_back(task.id.clone());
        }
        entry.parked = park(&mut tasks.next_park, &task.status.state, now);
        entry.stored.task = task;
        Ok(version)
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        Ok(self
            .lock()
            .0
            .entries
            .get(task_id)
            .map(|entry| entry.stored.task.clone()))
    }

    async fn list(&self, req: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        let mut matching: Vec<Task> = self
            .lock()
            .0
            .entries
            .values()
            .filter(|entry| matches_filters(&entry.stored.task, req))
            .map(|entry| entry.stored.task.clone())
            .collect();
        // Sorted by id, so that pages are deterministic.
        matching.sort_by(|a, b| a.id.cmp(&b.id));

        // Paging matches `InMemoryTaskStore`: an unparseable token is an
        // error, and a token past the end yields an empty page with no token.
        let page_size = resolve_page_size(req.page_size);
        let start = match &req.page_token {
            Some(token) => token
                .parse::<usize>()
                .map_err(|_| A2AError::invalid_params("invalid page token"))?,
            None => 0,
        };
        let total_size = matching.len();
        let start = start.min(total_size);
        let end = start.saturating_add(page_size).min(total_size);
        let next_page_token = if end < total_size {
            end.to_string()
        } else {
            String::new()
        };
        let tasks = matching
            .into_iter()
            .skip(start)
            .take(page_size)
            .map(|mut task| {
                apply_history_length(&mut task, req.history_length);
                task
            })
            .collect();

        Ok(ListTasksResponse {
            tasks,
            next_page_token,
            page_size: page_size as i32,
            total_size: total_size as i32,
        })
    }

    /// Takes the task from its non-finished state to `CANCELED`, under the same
    /// lock as the check, so two concurrent cancels cannot both succeed.
    async fn begin_cancel(&self, task_id: &str) -> Result<Task, A2AError> {
        let (mut guard, _) = self.lock();
        let tasks = &mut *guard;
        let entry = tasks
            .entries
            .get_mut(task_id)
            .ok_or_else(|| A2AError::task_not_found(task_id))?;
        if entry.stored.task.status.state.is_terminal() {
            return Err(A2AError::task_not_cancelable(task_id));
        }
        entry.stored.version += 1;
        entry.stored.task.status.state = TaskState::Canceled;
        // Same value as `chrono::Utc::now()`. `chrono` is not a direct dependency
        // of this crate, so the conversion from `SystemTime` stands in for it.
        entry.stored.task.status.timestamp = Some(SystemTime::now().into());
        entry.parked = None;
        let task = entry.stored.task.clone();
        tasks.terminal.push_back(task_id.to_string());
        Ok(task)
    }
}

/// The `list` filters, applied as `InMemoryTaskStore` applies them.
fn matches_filters(task: &Task, req: &ListTasksRequest) -> bool {
    if req
        .context_id
        .as_ref()
        .is_some_and(|context_id| task.context_id != *context_id)
    {
        return false;
    }
    if req
        .status
        .as_ref()
        .is_some_and(|state| task.status.state != *state)
    {
        return false;
    }
    // A task with no status timestamp cannot satisfy an "after" filter, and one
    // stamped at the bound does ("greater than or equal").
    req.status_timestamp_after.is_none_or(|after| {
        task.status
            .timestamp
            .is_some_and(|timestamp| timestamp >= after)
    })
}

/// `InMemoryTaskStore`'s `history_length` rule, which `a2a_server` keeps
/// crate-private: `None` leaves the history alone, `Some(n)` keeps the last
/// `n` messages, and `n <= 0` clears it.
fn apply_history_length(task: &mut Task, history_length: Option<i32>) {
    let (Some(requested), Some(history)) = (history_length, task.history.as_mut()) else {
        return;
    };
    let keep = usize::try_from(requested).unwrap_or(0);
    let excess = history.len().saturating_sub(keep);
    history.drain(..excess);
}

/// `a2a_server`'s crate-private `sanitized_internal_error`, repeated here: the
/// detail goes to the log, and the client gets the same generic error.
fn sanitized_internal_error(detail: impl Display) -> A2AError {
    tracing::error!(error = %detail, "internal error; returning a generic message to the client");
    A2AError::internal("Internal error")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use a2a::{error_code, Message, Part, Role, TaskStatus};
    use a2a_server::InMemoryTaskStore;

    use super::*;

    const TTL: Duration = Duration::from_secs(60);

    /// A clock that moves only when the test advances it.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<Instant>>);

    impl TestClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }

        fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    /// A store with a parked TTL of `TTL`, reading `clock`.
    fn clocked_store(capacity: usize, clock: &TestClock) -> BoundedTaskStore {
        let clock = clock.clone();
        BoundedTaskStore::with_clock(
            NonZeroUsize::new(capacity).expect("non-zero capacity"),
            TTL,
            move || clock.now(),
        )
    }

    /// A store whose clock never moves, so nothing ever expires.
    fn store(capacity: usize) -> BoundedTaskStore {
        clocked_store(capacity, &TestClock::new())
    }

    /// Creates `id` as `Submitted` and then moves it to `state`, as the
    /// handler does with a task the listener parks.
    async fn create_then_set(store: &BoundedTaskStore, id: &str, state: TaskState) {
        store
            .create(task(id, "c1", TaskState::Submitted))
            .await
            .unwrap();
        store.update(task(id, "c1", state)).await.unwrap();
    }

    fn task(id: &str, context_id: &str, state: TaskState) -> Task {
        Task {
            id: id.to_string(),
            context_id: context_id.to_string(),
            status: TaskStatus {
                state,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        }
    }

    fn stamped(mut task: Task, secs: u64) -> Task {
        task.status.timestamp = Some(at(secs).into());
        task
    }

    /// `secs` after the epoch. Convert with `.into()` where a `DateTime<Utc>`
    /// is expected.
    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// A `list` with no filters, no paging and no history limit.
    fn list_all() -> ListTasksRequest {
        ListTasksRequest {
            context_id: None,
            status: None,
            page_size: None,
            page_token: None,
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: None,
            tenant: None,
        }
    }

    async fn listed_ids(store: &BoundedTaskStore) -> Vec<String> {
        store
            .list(&list_all())
            .await
            .unwrap()
            .tasks
            .into_iter()
            .map(|task| task.id)
            .collect()
    }

    #[tokio::test]
    async fn create_then_get_round_trips_the_task() {
        let store = store(4);
        let created = task("t1", "c1", TaskState::Submitted);
        assert_eq!(store.create(created.clone()).await.unwrap(), 1);
        assert_eq!(store.get("t1").await.unwrap(), Some(created));
        assert_eq!(store.get("missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn create_of_an_existing_id_is_an_internal_error() {
        let store = store(4);
        store
            .create(task("t1", "c1", TaskState::Submitted))
            .await
            .unwrap();
        let err = store
            .create(task("t1", "c1", TaskState::Submitted))
            .await
            .unwrap_err();
        assert_eq!(err.code, error_code::INTERNAL_ERROR);
        assert_eq!(err.message, "Internal error");
    }

    /// `update` takes no expected version, and `InMemoryTaskStore` checks none,
    /// so there is no stale-version rejection to match. Every update is applied
    /// and bumps the version by one.
    #[tokio::test]
    async fn update_returns_the_next_version_each_time() {
        let store = store(4);
        store
            .create(task("t1", "c1", TaskState::Submitted))
            .await
            .unwrap();
        assert_eq!(
            store
                .update(task("t1", "c1", TaskState::Working))
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            store
                .update(task("t1", "c1", TaskState::Working))
                .await
                .unwrap(),
            3
        );
        let got = store.get("t1").await.unwrap().unwrap();
        assert_eq!(got.status.state, TaskState::Working);
    }

    #[tokio::test]
    async fn update_of_an_unknown_task_is_task_not_found() {
        let store = store(4);
        let err = store
            .update(task("missing", "c1", TaskState::Working))
            .await
            .unwrap_err();
        assert_eq!(err.code, error_code::TASK_NOT_FOUND);
    }

    #[tokio::test]
    async fn a_finished_task_cannot_leave_its_state_but_may_repeat_it() {
        let store = store(4);
        store
            .create(task("t1", "c1", TaskState::Completed))
            .await
            .unwrap();
        for state in [
            TaskState::Submitted,
            TaskState::Working,
            TaskState::Canceled,
            TaskState::Failed,
        ] {
            let err = store.update(task("t1", "c1", state)).await.unwrap_err();
            assert_eq!(err.code, error_code::INVALID_REQUEST);
        }
        assert_eq!(
            store
                .update(task("t1", "c1", TaskState::Completed))
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn begin_cancel_moves_a_live_task_to_canceled_once() {
        let store = store(4);
        store
            .create(task("t1", "c1", TaskState::Working))
            .await
            .unwrap();
        let canceled = store.begin_cancel("t1").await.unwrap();
        assert_eq!(canceled.status.state, TaskState::Canceled);
        assert!(canceled.status.timestamp.is_some());
        assert_eq!(store.get("t1").await.unwrap(), Some(canceled));

        let err = store.begin_cancel("t1").await.unwrap_err();
        assert_eq!(err.code, error_code::TASK_NOT_CANCELABLE);
        let err = store.begin_cancel("missing").await.unwrap_err();
        assert_eq!(err.code, error_code::TASK_NOT_FOUND);
    }

    #[tokio::test]
    async fn begin_cancel_refuses_a_finished_task_and_leaves_it_unchanged() {
        let store = store(4);
        store
            .create(task("t1", "c1", TaskState::Completed))
            .await
            .unwrap();
        let err = store.begin_cancel("t1").await.unwrap_err();
        assert_eq!(err.code, error_code::TASK_NOT_CANCELABLE);
        let got = store.get("t1").await.unwrap().unwrap();
        assert_eq!(got.status.state, TaskState::Completed);
        assert!(got.status.timestamp.is_none());
    }

    #[tokio::test]
    async fn list_pages_through_tasks_sorted_by_id() {
        let store = store(8);
        for id in ["t3", "t1", "t4", "t2", "t5"] {
            store
                .create(task(id, "c1", TaskState::Submitted))
                .await
                .unwrap();
        }
        let page = |page_size: i32, page_token: Option<&str>| ListTasksRequest {
            page_size: Some(page_size),
            page_token: page_token.map(str::to_string),
            ..list_all()
        };
        let ids = |resp: &ListTasksResponse| -> Vec<String> {
            resp.tasks.iter().map(|task| task.id.clone()).collect()
        };

        let first = store.list(&page(2, None)).await.unwrap();
        assert_eq!(ids(&first), ["t1", "t2"]);
        assert_eq!(first.next_page_token, "2");
        assert_eq!(first.total_size, 5);

        let second = store.list(&page(2, Some("2"))).await.unwrap();
        assert_eq!(ids(&second), ["t3", "t4"]);
        assert_eq!(second.next_page_token, "4");

        let last = store.list(&page(2, Some("4"))).await.unwrap();
        assert_eq!(ids(&last), ["t5"]);
        assert_eq!(last.next_page_token, "");

        let past_end = store.list(&page(2, Some("999"))).await.unwrap();
        assert!(past_end.tasks.is_empty());
        assert_eq!(past_end.next_page_token, "");
        assert_eq!(past_end.total_size, 5);

        let err = store.list(&page(2, Some("x"))).await.unwrap_err();
        assert_eq!(err.code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn create_at_capacity_evicts_the_oldest_finished_task() {
        let store = store(2);
        store
            .create(task("t1", "c1", TaskState::Completed))
            .await
            .unwrap();
        store
            .create(task("t2", "c1", TaskState::Completed))
            .await
            .unwrap();
        store
            .create(task("t3", "c1", TaskState::Working))
            .await
            .unwrap();

        assert_eq!(listed_ids(&store).await, ["t2", "t3"]);
        assert!(store.get("t2").await.unwrap().is_some());
    }

    /// An evicted task must be indistinguishable from one that never existed.
    #[tokio::test]
    async fn an_evicted_task_reads_as_one_that_never_existed() {
        let store = store(2);
        store
            .create(task("t1", "c1", TaskState::Completed))
            .await
            .unwrap();
        store
            .create(task("t2", "c1", TaskState::Working))
            .await
            .unwrap();
        store
            .create(task("t3", "c1", TaskState::Working))
            .await
            .unwrap();

        assert_eq!(store.get("t1").await.unwrap(), None);
        let err = store
            .update(task("t1", "c1", TaskState::Working))
            .await
            .unwrap_err();
        assert_eq!(err.code, error_code::TASK_NOT_FOUND);
        let err = store.begin_cancel("t1").await.unwrap_err();
        assert_eq!(err.code, error_code::TASK_NOT_FOUND);
        assert_eq!(listed_ids(&store).await, ["t2", "t3"]);
    }

    #[tokio::test]
    async fn an_evicted_id_can_be_created_again() {
        let store = store(2);
        store
            .create(task("t1", "c1", TaskState::Completed))
            .await
            .unwrap();
        store
            .create(task("t2", "c1", TaskState::Completed))
            .await
            .unwrap();
        store
            .create(task("t3", "c1", TaskState::Working))
            .await
            .unwrap(); // evicts t1

        assert_eq!(
            store
                .create(task("t1", "c1", TaskState::Working))
                .await
                .unwrap(),
            1
        ); // evicts t2, the oldest finished task left
        assert_eq!(listed_ids(&store).await, ["t1", "t3"]);
    }

    /// Eviction follows the order in which tasks finished, not the order in
    /// which they were created, and re-applying a finished state does not
    /// queue a task again.
    #[tokio::test]
    async fn eviction_order_is_by_when_a_task_finished() {
        let store = store(2);
        store
            .create(task("t1", "c1", TaskState::Working))
            .await
            .unwrap();
        store
            .create(task("t2", "c1", TaskState::Working))
            .await
            .unwrap();
        store
            .update(task("t2", "c1", TaskState::Completed))
            .await
            .unwrap();
        store
            .update(task("t1", "c1", TaskState::Completed))
            .await
            .unwrap();
        store
            .update(task("t2", "c1", TaskState::Completed))
            .await
            .unwrap();

        store
            .create(task("t3", "c1", TaskState::Submitted))
            .await
            .unwrap();
        assert_eq!(listed_ids(&store).await, ["t1", "t3"]);
    }

    #[tokio::test]
    async fn create_at_capacity_with_only_running_tasks_fails_and_evicts_nothing() {
        let store = store(2);
        store
            .create(task("t1", "c1", TaskState::Working))
            .await
            .unwrap();
        store
            .create(task("t2", "c1", TaskState::Submitted))
            .await
            .unwrap();

        let err = store
            .create(task("t3", "c1", TaskState::Working))
            .await
            .unwrap_err();
        assert_eq!(err.code, error_code::INTERNAL_ERROR);
        assert_eq!(err.message, "Internal error");
        assert_eq!(listed_ids(&store).await, ["t1", "t2"]);
        assert_eq!(store.get("t3").await.unwrap(), None);
    }

    #[tokio::test]
    async fn running_tasks_are_never_evicted() {
        let store = store(3);
        store
            .create(task("live", "c1", TaskState::Working))
            .await
            .unwrap();
        for i in 0..20 {
            store
                .create(task(&format!("done{i}"), "c1", TaskState::Completed))
                .await
                .unwrap();
            assert!(
                store.get("live").await.unwrap().is_some(),
                "live task evicted after {i} creates"
            );
        }
        assert_eq!(listed_ids(&store).await, ["done18", "done19", "live"]);
    }

    #[tokio::test]
    async fn capacity_one_holds_a_single_task() {
        let store = store(1);
        store
            .create(task("t1", "c1", TaskState::Completed))
            .await
            .unwrap();
        store
            .create(task("t2", "c1", TaskState::Working))
            .await
            .unwrap();
        assert_eq!(listed_ids(&store).await, ["t2"]);

        let err = store
            .create(task("t3", "c1", TaskState::Working))
            .await
            .unwrap_err();
        assert_eq!(err.code, error_code::INTERNAL_ERROR);

        store.begin_cancel("t2").await.unwrap();
        store
            .create(task("t3", "c1", TaskState::Working))
            .await
            .unwrap();
        assert_eq!(listed_ids(&store).await, ["t3"]);
    }

    #[test]
    fn the_default_parked_ttl_is_the_nonce_ttl() {
        assert_eq!(DEFAULT_PARKED_TTL, Duration::from_secs(60));
    }

    /// A store holding `t1`, parked `AuthRequired` and now just past the TTL,
    /// and `t2`, working. Each method is checked on a fresh one, so each is
    /// shown to drop the expired task by itself.
    async fn store_with_an_expired_task() -> BoundedTaskStore {
        let clock = TestClock::new();
        let store = clocked_store(4, &clock);
        create_then_set(&store, "t1", TaskState::AuthRequired).await;
        store
            .create(task("t2", "c1", TaskState::Working))
            .await
            .unwrap();
        clock.advance(TTL + Duration::from_nanos(1));
        store
    }

    #[tokio::test]
    async fn an_expired_auth_required_task_reads_as_one_that_never_existed() {
        let store = store_with_an_expired_task().await;
        assert_eq!(store.get("t1").await.unwrap(), None);

        let store = store_with_an_expired_task().await;
        assert_eq!(listed_ids(&store).await, ["t2"]);
        let resp = store.list(&list_all()).await.unwrap();
        assert_eq!(resp.total_size, 1);

        let store = store_with_an_expired_task().await;
        let expired = store
            .update(task("t1", "c1", TaskState::Working))
            .await
            .unwrap_err();
        let unknown = store
            .update(task("missing", "c1", TaskState::Working))
            .await
            .unwrap_err();
        assert_eq!(expired.code, error_code::TASK_NOT_FOUND);
        assert_eq!(expired.message, unknown.message.replace("missing", "t1"));

        let store = store_with_an_expired_task().await;
        let expired = store.begin_cancel("t1").await.unwrap_err();
        let unknown = store.begin_cancel("missing").await.unwrap_err();
        assert_eq!(expired.code, error_code::TASK_NOT_FOUND);
        assert_eq!(expired.message, unknown.message.replace("missing", "t1"));

        let store = store_with_an_expired_task().await;
        let recreated = task("t1", "c1", TaskState::Submitted);
        assert_eq!(store.create(recreated.clone()).await.unwrap(), 1);
        assert_eq!(store.get("t1").await.unwrap(), Some(recreated));
    }

    /// Expired means older than the TTL: at exactly the TTL the task stays.
    #[tokio::test]
    async fn an_auth_required_task_expires_only_once_older_than_the_ttl() {
        let clock = TestClock::new();
        let store = clocked_store(4, &clock);
        create_then_set(&store, "t1", TaskState::AuthRequired).await;

        clock.advance(TTL);
        assert!(store.get("t1").await.unwrap().is_some());
        clock.advance(Duration::from_nanos(1));
        assert_eq!(store.get("t1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn re_parking_restarts_the_age() {
        let clock = TestClock::new();
        let store = clocked_store(4, &clock);
        create_then_set(&store, "again", TaskState::AuthRequired).await;
        create_then_set(&store, "via_working", TaskState::AuthRequired).await;

        clock.advance(TTL);
        store
            .update(task("again", "c1", TaskState::AuthRequired))
            .await
            .unwrap();
        store
            .update(task("via_working", "c1", TaskState::Working))
            .await
            .unwrap();
        store
            .update(task("via_working", "c1", TaskState::AuthRequired))
            .await
            .unwrap();

        clock.advance(TTL);
        assert_eq!(listed_ids(&store).await, ["again", "via_working"]);
        clock.advance(Duration::from_nanos(1));
        assert!(listed_ids(&store).await.is_empty());
    }

    #[tokio::test]
    async fn leaving_the_parked_state_stops_the_expiry() {
        let clock = TestClock::new();
        let store = clocked_store(4, &clock);
        for id in ["canceled", "completed", "working"] {
            create_then_set(&store, id, TaskState::AuthRequired).await;
        }
        store
            .update(task("working", "c1", TaskState::Working))
            .await
            .unwrap();
        store
            .update(task("completed", "c1", TaskState::Completed))
            .await
            .unwrap();
        store.begin_cancel("canceled").await.unwrap();

        clock.advance(TTL * 10);
        assert_eq!(
            listed_ids(&store).await,
            ["canceled", "completed", "working"]
        );
    }

    #[tokio::test]
    async fn input_required_never_expires_by_age() {
        let clock = TestClock::new();
        let store = clocked_store(4, &clock);
        create_then_set(&store, "t1", TaskState::InputRequired).await;
        store
            .create(task("t2", "c1", TaskState::InputRequired))
            .await
            .unwrap();

        clock.advance(TTL * 1000);
        assert_eq!(listed_ids(&store).await, ["t1", "t2"]);
        assert_eq!(
            store
                .update(task("t1", "c1", TaskState::Working))
                .await
                .unwrap(),
            3
        );
    }

    /// The order is by when a task was parked, not when it was created, and a
    /// running task is never the one evicted.
    #[tokio::test]
    async fn a_full_store_with_no_finished_task_evicts_the_earliest_parked() {
        let clock = TestClock::new();
        let store = clocked_store(4, &clock);
        store
            .create(task("working", "c1", TaskState::Working))
            .await
            .unwrap();
        store
            .create(task("submitted", "c1", TaskState::Submitted))
            .await
            .unwrap();
        store
            .create(task("auth", "c1", TaskState::Submitted))
            .await
            .unwrap();
        create_then_set(&store, "input", TaskState::InputRequired).await;
        clock.advance(Duration::from_secs(1));
        store
            .update(task("auth", "c1", TaskState::AuthRequired))
            .await
            .unwrap();

        store
            .create(task("new1", "c1", TaskState::Submitted))
            .await
            .unwrap();
        assert_eq!(
            listed_ids(&store).await,
            ["auth", "new1", "submitted", "working"]
        );
        store
            .create(task("new2", "c1", TaskState::Submitted))
            .await
            .unwrap();
        assert_eq!(
            listed_ids(&store).await,
            ["new1", "new2", "submitted", "working"]
        );

        let err = store
            .create(task("new3", "c1", TaskState::Submitted))
            .await
            .unwrap_err();
        assert_eq!(err.code, error_code::INTERNAL_ERROR);
        assert_eq!(
            listed_ids(&store).await,
            ["new1", "new2", "submitted", "working"]
        );
    }

    #[tokio::test]
    async fn finished_tasks_are_evicted_before_parked_ones() {
        let clock = TestClock::new();
        let store = clocked_store(3, &clock);
        create_then_set(&store, "parked", TaskState::AuthRequired).await;
        store
            .create(task("working", "c1", TaskState::Working))
            .await
            .unwrap();
        clock.advance(Duration::from_secs(1));
        create_then_set(&store, "done", TaskState::Completed).await;

        store
            .create(task("new", "c1", TaskState::Submitted))
            .await
            .unwrap();
        assert_eq!(listed_ids(&store).await, ["new", "parked", "working"]);
    }

    /// Unsigned messages park tasks as fast as anyone can send them. They must
    /// not lock signed callers out, and they must not outlive their nonce.
    #[tokio::test]
    async fn a_store_filled_with_auth_required_tasks_still_admits_new_ones() {
        let clock = TestClock::new();
        let store = {
            let clock = clock.clone();
            BoundedTaskStore::with_clock(DEFAULT_TASK_CAPACITY, DEFAULT_PARKED_TTL, move || {
                clock.now()
            })
        };
        let capacity = DEFAULT_TASK_CAPACITY.get();
        for i in 0..capacity {
            create_then_set(&store, &format!("unsigned{i:04}"), TaskState::AuthRequired).await;
            clock.advance(Duration::from_millis(1));
        }

        store
            .create(task("signed", "c1", TaskState::Submitted))
            .await
            .unwrap();
        assert_eq!(store.get("unsigned0000").await.unwrap(), None);
        assert!(store.get("unsigned0001").await.unwrap().is_some());
        let resp = store.list(&list_all()).await.unwrap();
        assert_eq!(resp.total_size, i32::try_from(capacity).unwrap());

        clock.advance(DEFAULT_PARKED_TTL);
        assert_eq!(listed_ids(&store).await, ["signed"]);
    }

    /// One operation of the parity script.
    enum Op {
        Create(Task),
        Update(Task),
        Get(&'static str),
        Cancel(&'static str),
        List(ListTasksRequest),
    }

    /// What an operation returned, reduced to what both stores must agree on.
    #[derive(Debug, PartialEq)]
    enum Outcome {
        Created(TaskVersion),
        Updated(TaskVersion),
        Got(Option<Task>),
        Listed(ListTasksResponse),
        Canceled(Task),
        Failed(i32, String),
    }

    /// `begin_cancel` stamps the wall clock, which differs between the two
    /// runs, so canceled tasks are compared without their timestamp. The
    /// stamp's presence is checked where it is produced.
    fn unstamped(mut task: Task) -> Task {
        if task.status.state == TaskState::Canceled {
            task.status.timestamp = None;
        }
        task
    }

    fn failed(err: A2AError) -> Outcome {
        Outcome::Failed(err.code, err.message)
    }

    async fn run(store: &impl TaskStore, ops: &[Op]) -> Vec<Outcome> {
        let mut outcomes = Vec::with_capacity(ops.len());
        for op in ops {
            let outcome = match op {
                Op::Create(task) => store
                    .create(task.clone())
                    .await
                    .map_or_else(failed, Outcome::Created),
                Op::Update(task) => store
                    .update(task.clone())
                    .await
                    .map_or_else(failed, Outcome::Updated),
                Op::Get(id) => store
                    .get(id)
                    .await
                    .map(|task| Outcome::Got(task.map(unstamped)))
                    .unwrap_or_else(failed),
                Op::Cancel(id) => store
                    .begin_cancel(id)
                    .await
                    .map(|task| {
                        assert!(
                            task.status.timestamp.is_some(),
                            "begin_cancel stamps the task"
                        );
                        Outcome::Canceled(unstamped(task))
                    })
                    .unwrap_or_else(failed),
                Op::List(req) => store
                    .list(req)
                    .await
                    .map(|mut resp| {
                        resp.tasks = resp.tasks.into_iter().map(unstamped).collect();
                        Outcome::Listed(resp)
                    })
                    .unwrap_or_else(failed),
            };
            outcomes.push(outcome);
        }
        outcomes
    }

    /// The same operations, with ample capacity, must give the same results
    /// from `BoundedTaskStore` as from `InMemoryTaskStore::new()`.
    #[tokio::test]
    async fn parity_with_in_memory_task_store() {
        let mut ops = vec![
            Op::Create(task("t1", "c1", TaskState::Submitted)),
            Op::Create(task("t1", "c1", TaskState::Submitted)),
            Op::Create(stamped(task("t2", "c2", TaskState::Working), 100)),
            Op::Create(stamped(task("t3", "c1", TaskState::Completed), 200)),
            Op::Create(task("t4", "c1", TaskState::Completed)),
            Op::Get("t1"),
            Op::Get("missing"),
            Op::Update(task("t1", "c1", TaskState::Working)),
            Op::Update(task("t1", "c1", TaskState::Working)),
            Op::Update(task("t3", "c1", TaskState::Working)),
            Op::Update(task("t3", "c1", TaskState::Canceled)),
            Op::Update(task("t3", "c1", TaskState::Completed)),
            Op::Update(task("missing", "c1", TaskState::Working)),
            Op::Cancel("t2"),
            Op::Cancel("t2"),
            Op::Cancel("t3"),
            Op::Cancel("missing"),
            Op::Update(task("t2", "c2", TaskState::Canceled)),
            Op::Get("t2"),
            Op::List(list_all()),
            Op::List(ListTasksRequest {
                context_id: Some("c1".into()),
                ..list_all()
            }),
            Op::List(ListTasksRequest {
                status: Some(TaskState::Completed),
                ..list_all()
            }),
            Op::List(ListTasksRequest {
                status_timestamp_after: Some(at(150).into()),
                ..list_all()
            }),
        ];
        // More than one page, so the page size cap and the tokens are exercised.
        ops.extend(
            (0..120).map(|i| Op::Create(task(&format!("p{i:03}"), "bulk", TaskState::Submitted))),
        );
        ops.extend([
            Op::List(ListTasksRequest {
                page_size: Some(2),
                ..list_all()
            }),
            Op::List(ListTasksRequest {
                page_size: Some(2),
                page_token: Some("2".into()),
                ..list_all()
            }),
            Op::List(ListTasksRequest {
                page_size: Some(1000),
                ..list_all()
            }),
            Op::List(ListTasksRequest {
                page_size: Some(0),
                ..list_all()
            }),
            Op::List(ListTasksRequest {
                page_token: Some("999".into()),
                ..list_all()
            }),
            Op::List(ListTasksRequest {
                page_token: Some("abc".into()),
                ..list_all()
            }),
        ]);

        let mut with_history = task("h1", "hist", TaskState::Working);
        with_history.history = Some(
            ["1", "2", "3"]
                .map(|text| Message::new(Role::User, vec![Part::text(text)]))
                .into(),
        );
        ops.push(Op::Create(with_history));
        for history_length in [None, Some(1), Some(0), Some(-1)] {
            ops.push(Op::List(ListTasksRequest {
                context_id: Some("hist".into()),
                history_length,
                ..list_all()
            }));
        }

        let expected = run(&InMemoryTaskStore::new(), &ops).await;
        let actual = run(&store(1000), &ops).await;
        assert_eq!(actual, expected);
    }
}
