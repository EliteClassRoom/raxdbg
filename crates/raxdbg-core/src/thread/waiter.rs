//! Futex waiters: what a blocking syscall parks a thread on.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/Waiter.java`
//! and `AbstractEmulator.waiters`@7f5da98e.
//!
//! unidbg's concurrency is cooperative, so "blocking" means: register a waiter,
//! return [`crate::backend::RunError::ThreadSwitch`], and let the dispatcher run
//! somebody else. A `futex(FUTEX_WAKE)` on the same address marks the waiters
//! woken; the dispatcher resumes them on its next pass and the syscall they were
//! in returns to the guest. This is how `pthread_join`, `pthread_cond_wait` and
//! `pthread_mutex_lock`'s slow path all work, because bionic implements every
//! one of them over `futex`.

use std::cell::{Cell, RefCell};

/// A thread parked on an address.
#[derive(Debug)]
pub struct Waiter {
    id: usize,
    address: u64,
    task: Cell<Option<usize>>,
    /// Whether a task has taken this waiter as its own.
    claimed: Cell<bool>,
    woken: Cell<bool>,
}

impl Waiter {
    /// The waiter's id.
    pub fn id(&self) -> usize {
        self.id
    }

    /// The address it is parked on.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The guest thread that is parked, when the waiter was registered by the
    /// dispatcher rather than by a host-driven call.
    pub fn task(&self) -> Option<usize> {
        self.task.get()
    }

    /// Whether something woke it.
    pub fn is_woken(&self) -> bool {
        self.woken.get()
    }
}

/// Every parked thread.
///
/// Port of unidbg: `AbstractEmulator.waiters`, a `List<Waiter>` guarded by a
/// lock — unidbg uses a real lock because its waiters can be touched from a
/// hook, but only one guest thread ever runs here, so a `RefCell` is enough.
#[derive(Debug, Default)]
pub struct Waiters {
    waiters: RefCell<Vec<Waiter>>,
    next_id: Cell<usize>,
}

impl Waiters {
    /// An empty registry.
    pub fn new() -> Self {
        Waiters {
            waiters: RefCell::new(Vec::new()),
            next_id: Cell::new(0),
        }
    }

    /// Parks a thread on `address`, returning the waiter's id.
    ///
    /// Port of unidbg: `AbstractEmulator.createWaiter` plus the `FUTEX_WAIT`
    /// arm of `ARM64SyscallHandler.futex`, which registers the waiter and then
    /// throws `ThreadContextSwitchException`.
    pub fn wait(&self, address: u64) -> usize {
        self.wait_for(address, None)
    }

    /// Parks `task` on `address`, returning the waiter's id.
    pub fn wait_for(&self, address: u64, task: Option<usize>) -> usize {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        self.waiters.borrow_mut().push(Waiter {
            id,
            address,
            task: Cell::new(task),
            claimed: Cell::new(task.is_some()),
            woken: Cell::new(false),
        });
        id
    }

    /// Gives the newest unclaimed waiter to `task`.
    ///
    /// A syscall handler does not know which guest thread it is running for, so
    /// it registers a waiter and the dispatcher claims it when the
    /// [`crate::backend::RunError::ThreadSwitch`] comes back — that is how the
    /// thread that parked becomes the thread that resumes.
    pub fn claim_unclaimed(&self, task: usize) -> Option<usize> {
        let mut waiters = self.waiters.borrow_mut();
        let waiter = waiters
            .iter()
            .rev()
            .find(|waiter| !waiter.claimed.get() && waiter.task.get().is_none())?;
        waiter.claimed.set(true);
        waiter.task.set(Some(task));
        Some(waiter.id)
    }

    /// Whether any waiter is still unclaimed.
    pub fn has_unclaimed(&self) -> bool {
        self.waiters
            .borrow()
            .iter()
            .any(|waiter| !waiter.claimed.get() && waiter.task.get().is_none())
    }

    /// Wakes up to `count` threads parked on `address`.
    ///
    /// Port of unidbg: the `FUTEX_WAKE` arm of
    /// `AndroidSyscallHandler.futex`, which wakes until `count >= val` — so a
    /// `val` of zero wakes one waiter, because the first successful wake takes
    /// the counter to one and the loop breaks. The kernel's `futex_wake` does
    /// the same (`mark_wake_futex` then `if (++ret >= nr_wake) break`).
    pub fn wake(&self, address: u64, count: usize) -> usize {
        let limit = if count == 0 { 1 } else { count };
        let mut woken = 0;
        for waiter in self.waiters.borrow().iter() {
            if woken == limit {
                break;
            }
            if waiter.address == address && !waiter.is_woken() {
                waiter.woken.set(true);
                woken += 1;
            }
        }
        woken
    }

    /// Wakes every parked thread, whatever it is waiting on.
    ///
    /// Port of unidbg: `AbstractEmulator.wakeUpWaiters`, which a `StopEmulator`
    /// or a thread exit uses so nothing is left parked forever.
    pub fn wake_all(&self) -> usize {
        let mut woken = 0;
        for waiter in self.waiters.borrow().iter() {
            if !waiter.is_woken() {
                waiter.woken.set(true);
                woken += 1;
            }
        }
        woken
    }

    /// Whether the waiter with `id` has been woken.
    pub fn is_woken(&self, id: usize) -> bool {
        self.waiters
            .borrow()
            .iter()
            .find(|waiter| waiter.id() == id)
            .map(|waiter| waiter.is_woken())
            .unwrap_or(false)
    }

    /// Whether the task is parked and woken.
    pub fn task_woken(&self, task: usize) -> bool {
        self.waiters
            .borrow()
            .iter()
            .any(|waiter| waiter.task() == Some(task) && waiter.is_woken())
    }

    /// Forgets a waiter.
    pub fn remove(&self, id: usize) {
        self.waiters.borrow_mut().retain(|waiter| waiter.id() != id);
    }

    /// How many threads are parked.
    pub fn len(&self) -> usize {
        self.waiters.borrow().len()
    }

    /// Whether nothing is parked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many threads are parked on `address`.
    pub fn waiting_on(&self, address: u64) -> usize {
        self.waiters
            .borrow()
            .iter()
            .filter(|waiter| waiter.address() == address)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_waiter_starts_asleep_and_waking_marks_it() {
        let waiters = Waiters::new();
        let id = waiters.wait(0x1000);
        assert_eq!(waiters.len(), 1);
        assert!(!waiters.is_woken(id));
        assert_eq!(waiters.wake(0x1000, 1), 1);
        assert!(waiters.is_woken(id));
    }

    #[test]
    fn waking_one_address_leaves_the_others_parked() {
        let waiters = Waiters::new();
        let first = waiters.wait(0x1000);
        let second = waiters.wait(0x2000);
        assert_eq!(waiters.wake(0x2000, 1), 1);
        assert!(!waiters.is_woken(first));
        assert!(waiters.is_woken(second));
        assert_eq!(waiters.waiting_on(0x1000), 1);
    }

    #[test]
    fn waking_stops_at_the_requested_count() {
        let waiters = Waiters::new();
        let first = waiters.wait(0x1000);
        let second = waiters.wait(0x1000);
        let third = waiters.wait(0x1000);
        assert_eq!(waiters.wake(0x1000, 2), 2);
        assert!(waiters.is_woken(first));
        assert!(waiters.is_woken(second));
        assert!(!waiters.is_woken(third), "only two were asked for");
    }

    #[test]
    fn a_count_of_zero_wakes_one_as_unidbg_and_the_kernel_do() {
        let waiters = Waiters::new();
        let first = waiters.wait(0x1000);
        let second = waiters.wait(0x1000);
        assert_eq!(waiters.wake(0x1000, 0), 1);
        assert!(waiters.is_woken(first));
        assert!(!waiters.is_woken(second));
    }

    #[test]
    fn an_already_woken_waiter_is_not_woken_twice() {
        let waiters = Waiters::new();
        waiters.wait(0x1000);
        assert_eq!(waiters.wake(0x1000, 1), 1);
        assert_eq!(waiters.wake(0x1000, 1), 0, "it is already awake");
    }

    #[test]
    fn an_unclaimed_waiter_is_given_to_the_task_that_asked_for_the_switch() {
        let waiters = Waiters::new();
        waiters.wait(0x1000);
        assert!(waiters.has_unclaimed());
        let id = waiters.claim_unclaimed(7).expect("a waiter to claim");
        assert_eq!(waiters.waiters.borrow()[0].task(), Some(7));
        assert!(!waiters.has_unclaimed(), "it is claimed now");
        assert_eq!(waiters.claim_unclaimed(8), None, "there is only one");
        assert!(waiters.is_woken(id) == false);
    }

    #[test]
    fn waking_a_task_that_is_parked_is_visible_by_task_id() {
        let waiters = Waiters::new();
        waiters.wait_for(0x1000, Some(7));
        assert!(!waiters.task_woken(7));
        assert_eq!(waiters.wake(0x1000, 1), 1);
        assert!(waiters.task_woken(7));
        assert!(!waiters.task_woken(8), "a task that is not parked");
    }

    #[test]
    fn wake_all_clears_the_registry() {
        let waiters = Waiters::new();
        waiters.wait(0x1000);
        waiters.wait(0x2000);
        assert_eq!(waiters.wake_all(), 2);
        assert_eq!(waiters.wake_all(), 0);
    }

    #[test]
    fn a_removed_waiter_is_forgotten() {
        let waiters = Waiters::new();
        let id = waiters.wait(0x1000);
        waiters.remove(id);
        assert!(waiters.is_empty());
        assert!(!waiters.is_woken(id));
    }
}
