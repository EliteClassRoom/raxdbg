//! The thread dispatcher: cooperative preemption over guest threads.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/UniThreadDispatcher.java`,
//! `unidbg-android/src/main/java/com/github/unidbg/linux/thread/ThreadTask.java` and
//! `unidbg-api/src/main/java/com/github/unidbg/arm/context/ThreadContext.java`@7f5da98e.
//!
//! unidbg has no instruction-count hook and no host threads per guest thread.
//! A guest thread is a *task*: a saved register file, a stack, and a function to
//! run. A syscall that cannot make progress (a `futex` with no one to wake it, a
//! `nanosleep`, a `pthread_join`) registers a waiter and returns
//! [`RunError::ThreadSwitch`]; the dispatcher saves the running task's context,
//! picks the next runnable one, restores it and resumes. The task that finishes
//! reaches the exit stub and returns [`RunError::PopContext`], which retires it.
//!
//! This is the whole of unidbg's concurrency model, and it is why a port needs
//! no locks: exactly one guest thread is ever executing.

use std::collections::VecDeque;

use std::rc::Rc;

use crate::backend::{Backend, ContextId, RunError};
use crate::reg::RegId;
use crate::thread::waiter::Waiters;

/// What a task is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    /// Created, never run: its registers still have to be set up.
    New,
    /// Started and not finished: it has a saved context to restore.
    Running,
    /// Returned from its function.
    Finished,
}

/// One guest thread.
///
/// Port of unidbg: `ThreadTask`, which pairs a `ThreadContext` with the
/// function the thread was created for.
#[derive(Debug)]
pub struct ThreadTask {
    id: usize,
    context: Option<ContextId>,
    stack: u64,
    function: u64,
    args: Vec<u64>,
    result: Option<u64>,
    state: TaskState,
    /// The waiter this task is parked on, once a blocking syscall parked it.
    waiter: Option<usize>,
}

impl ThreadTask {
    /// The task's id, which is also the value `pthread_t` holds.
    pub fn id(&self) -> usize {
        self.id
    }

    /// The function the task runs.
    pub fn function(&self) -> u64 {
        self.function
    }

    /// The arguments it was created with.
    pub fn args(&self) -> &[u64] {
        &self.args
    }

    /// The stack pointer it runs on.
    pub fn stack(&self) -> u64 {
        self.stack
    }

    /// What the task's function returned, once it has finished.
    pub fn result(&self) -> Option<u64> {
        self.result
    }

    /// Where the task is.
    pub fn state(&self) -> TaskState {
        self.state
    }

    /// Whether the task is parked on a waiter.
    pub fn is_parked(&self) -> bool {
        self.waiter.is_some()
    }

    /// The waiter it is parked on.
    pub fn waiter(&self) -> Option<usize> {
        self.waiter
    }

    /// The saved context, once the task has been switched away from.
    pub fn context(&self) -> Option<ContextId> {
        self.context
    }
}

/// Runs guest threads one at a time.
///
/// Port of unidbg: `UniThreadDispatcher.run`, which loops over its tasks and
/// swaps the running one whenever a `ThreadContextSwitchException` comes up.
#[derive(Debug)]
pub struct ThreadDispatcher {
    tasks: Vec<ThreadTask>,
    /// The task that is currently executing, if any.
    current: Option<usize>,
    /// The task ids that are ready to run, in the order they should run.
    ready: VecDeque<usize>,
    next_id: usize,
    exit_stub: u64,
    is_64bit: bool,
    /// How many times the dispatcher switched tasks, for tests.
    switches: usize,
    /// The futex registry, when the emulator installed one. A task parked on a
    /// waiter does not run again until that waiter is woken.
    waiters: Option<Rc<Waiters>>,
}

impl ThreadDispatcher {
    /// A dispatcher whose threads return to `exit_stub`.
    ///
    /// `exit_stub` is the address a task's `lr` is set to, so that the task's
    /// `ret` lands on an SVC stub which returns [`RunError::PopContext`].
    pub fn new(exit_stub: u64, is_64bit: bool) -> Self {
        ThreadDispatcher {
            tasks: Vec::new(),
            current: None,
            ready: VecDeque::new(),
            next_id: 0,
            exit_stub,
            is_64bit,
            switches: 0,
            waiters: None,
        }
    }

    /// Installs the futex registry, so parking and waking work.
    pub fn set_waiters(&mut self, waiters: Rc<Waiters>) {
        self.waiters = Some(waiters);
    }

    /// Parks the running task on `waiter`.
    ///
    /// Port of unidbg: `AbstractEmulator.createWaiter` followed by the
    /// `ThreadContextSwitchException` a blocking syscall raises. The task stays
    /// out of the ready queue until something wakes the waiter, which is what
    /// makes `pthread_join` and `pthread_cond_wait` block rather than spin.
    pub fn park_current(&mut self, waiter: usize) {
        if let Some(id) = self.current {
            if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                task.waiter = Some(waiter);
            }
        }
        self.current = None;
    }

    /// Parks a specific task, for a caller that is not inside `run`.
    pub fn park(&mut self, id: usize, waiter: usize) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
            task.waiter = Some(waiter);
        }
    }

    /// Runs `on_finish` for each parked joiner whose thread has just finished,
    /// waking it and clearing its parking.
    ///
    /// A `pthread_join` parks the joiner on a waiter and gives the address its
    /// result belongs at; when the thread's task retires, the dispatcher hands
    /// the result over and wakes the joiner. Without this a joiner would stay
    /// parked forever, which looks exactly like a deadlock.
    pub fn finish_join(&mut self, on_finish: &mut dyn FnMut(usize, u64)) {
        let woken: Vec<(usize, u64)> = self
            .waiters
            .as_ref()
            .map(|waiters| {
                self.tasks
                    .iter()
                    .filter(|task| task.state == TaskState::Finished)
                    .filter_map(|task| task.waiter.map(|waiter| (waiter, task.result.unwrap_or(0))))
                    .filter(|(waiter, _)| waiters.is_woken(*waiter))
                    .collect()
            })
            .unwrap_or_default();
        for (waiter, result) in woken {
            if let Some(task) = self
                .tasks
                .iter_mut()
                .find(|task| task.waiter == Some(waiter))
            {
                task.waiter = None;
            }
            if let Some(waiters) = self.waiters.as_ref() {
                waiters.remove(waiter);
            }
            on_finish(waiter, result);
        }
    }

    /// Whether any task is still parked.
    pub fn parked(&self) -> usize {
        self.tasks.iter().filter(|task| task.is_parked()).count()
    }

    /// Creates a task that will call `function` on `stack` with `args`.
    ///
    /// Returns the task's id, which is what a `pthread_t` will hold.
    pub fn create(&mut self, function: u64, args: &[u64], stack: u64) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.tasks.push(ThreadTask {
            id,
            context: None,
            stack,
            function,
            args: args.to_vec(),
            result: None,
            state: TaskState::New,
            waiter: None,
        });
        self.ready.push_back(id);
        id
    }

    /// The task with `id`.
    pub fn task(&self, id: usize) -> Option<&ThreadTask> {
        self.tasks.iter().find(|task| task.id == id)
    }

    /// How many tasks exist.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// How many tasks are still to finish.
    pub fn pending(&self) -> usize {
        self.tasks
            .iter()
            .filter(|task| task.state != TaskState::Finished)
            .count()
    }

    /// How many times the dispatcher swapped tasks.
    pub fn switches(&self) -> usize {
        self.switches
    }

    /// The id of the task that is running, if any.
    pub fn current(&self) -> Option<usize> {
        self.current
    }

    /// Yields the running task, so the next one gets a turn.
    ///
    /// Port of unidbg: `ThreadContextSwitchException` handling — the current
    /// task goes back on the ready queue and the dispatcher moves on.
    pub fn yield_current(&mut self) {
        if let Some(id) = self.current.take() {
            if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                if task.state == TaskState::Running {
                    self.ready.push_back(id);
                }
            }
        }
    }

    /// Marks a task finished with `result`, as `PopContext` does.
    pub fn finish(&mut self, id: usize, result: u64) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
            task.state = TaskState::Finished;
            task.result = Some(result);
        }
        if self.current == Some(id) {
            self.current = None;
        }
    }

    /// Runs every task to completion.
    ///
    /// Port of unidbg: `UniThreadDispatcher.run` plus `ThreadTask.run`, which
    /// sets the thread's registers from its arguments and calls the function.
    /// Returns the results in the order the tasks finished.
    pub fn run(&mut self, backend: &mut dyn Backend) -> Result<Vec<(usize, u64)>, RunError> {
        let mut finished = Vec::new();
        loop {
            let Some(id) = self.ready.pop_front() else {
                break;
            };
            let (state, context, stack, function, args, waiter) = {
                let task = self
                    .tasks
                    .iter()
                    .find(|task| task.id == id)
                    .expect("a queued task exists");
                (
                    task.state,
                    task.context,
                    task.stack,
                    task.function,
                    task.args.clone(),
                    task.waiter,
                )
            };
            if state == TaskState::Finished {
                continue;
            }
            if let Some(waiter) = waiter {
                // Parked: it runs again only once its waiter is woken.
                let woken = self
                    .waiters
                    .as_ref()
                    .map(|waiters| waiters.is_woken(waiter))
                    .unwrap_or(true);
                if !woken {
                    continue;
                }
                if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                    task.waiter = None;
                }
                if let Some(waiters) = self.waiters.as_ref() {
                    waiters.remove(waiter);
                }
            }

            match state {
                TaskState::New => {
                    // `ThreadTask.run`: the arguments go in the argument
                    // registers, the return address is the exit stub, and the
                    // stack is the thread's own.
                    for (index, arg) in args.iter().enumerate() {
                        let register = if self.is_64bit {
                            RegId::X(index as u8)
                        } else {
                            RegId::R(index as u8)
                        };
                        backend.reg_write(register, *arg)?;
                    }
                    backend.reg_write(RegId::Sp, stack)?;
                    backend.reg_write(RegId::Lr, self.exit_stub)?;
                    backend.reg_write(RegId::Pc, function)?;
                    if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                        task.state = TaskState::Running;
                    }
                }
                TaskState::Running => {
                    let context = context.expect("a running task has a saved context");
                    backend.context_restore(context);
                }
                TaskState::Finished => continue,
            }
            self.current = Some(id);

            // The task runs until it yields or finishes. Both arrive as a
            // `RunError`, which is what plan D5 replaced unidbg's exceptions
            // with.
            let outcome = backend.emu_start(
                backend.reg_read(RegId::Pc)?,
                self.exit_stub,
                0,
                0,
            );
            match outcome {
                Ok(_) => {
                    // The run stopped at the exit stub without the stub raising,
                    // which only happens if the `ret` never reached it. Retire
                    // the task with whatever its function left in the return
                    // register.
                    let result = if self.is_64bit {
                        backend.reg_read(RegId::X(0))?
                    } else {
                        backend.reg_read(RegId::R(0))?
                    };
                    self.finish(id, result);
                    finished.push((id, result));
                }
                Err(RunError::ThreadSwitch) => {
                    // Save this task's registers and let the next one run.
                    //
                    // The new snapshot *replaces* the old one: the task has
                    // moved on since it was last switched away from, so keeping
                    // both would restore a stale point forever and leak a
                    // context slot on every yield.
                    let context = backend.context_save();
                    let previous = self
                        .tasks
                        .iter_mut()
                        .find(|task| task.id == id)
                        .and_then(|task| task.context.replace(context));
                    if let Some(previous) = previous {
                        backend.context_free(previous);
                    }
                    // A blocking syscall registered a waiter and then asked for
                    // the switch; the dispatcher gives it to this task, which is
                    // how the thread that parked becomes the thread that
                    // resumes when something wakes it.
                    if let Some(waiters) = self.waiters.as_ref() {
                        if let Some(waiter) = waiters.claim_unclaimed(id) {
                            if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
                                task.waiter = Some(waiter);
                            }
                        }
                        // A `FUTEX_WAKE` marks waiters woken and then yields, so
                        // this is where the threads it woke go back on the ready
                        // queue.
                        let woken: Vec<usize> = self
                            .tasks
                            .iter()
                            .filter(|task| {
                                task.waiter
                                    .map(|waiter| waiters.is_woken(waiter))
                                    .unwrap_or(false)
                            })
                            .map(|task| task.id)
                            .collect();
                        for woken_id in woken {
                            let waiter = self
                                .tasks
                                .iter_mut()
                                .find(|task| task.id == woken_id)
                                .and_then(|task| task.waiter.take());
                            if let Some(waiter) = waiter {
                                waiters.remove(waiter);
                            }
                            if self.tasks.iter().any(|task| task.id == woken_id)
                                && !self.ready.contains(&woken_id)
                            {
                                self.ready.push_back(woken_id);
                            }
                        }
                    }
                    self.switches += 1;
                    self.current = None;
                    self.ready.push_back(id);
                }
                Err(RunError::PopContext) => {
                    let result = if self.is_64bit {
                        backend.reg_read(RegId::X(0))?
                    } else {
                        backend.reg_read(RegId::R(0))?
                    };
                    if let Some(context) = self
                        .tasks
                        .iter()
                        .find(|task| task.id == id)
                        .and_then(|task| task.context)
                    {
                        backend.context_free(context);
                    }
                    self.finish(id, result);
                    finished.push((id, result));
                }
                Err(error) => return Err(error),
            }
        }
        if self.pending() > 0 && self.parked() > 0 {
            // Every thread is blocked on something nothing will wake. unidbg
            // stops the emulator here; reporting it beats hanging.
            return Err(RunError::Backend(crate::backend::BackendError::Other(
                format!(
                    "every thread is parked: {} of {} tasks are waiting",
                    self.parked(),
                    self.pending()
                ),
            )));
        }
        Ok(finished)
    }
}

impl Default for ThreadDispatcher {
    fn default() -> Self {
        ThreadDispatcher::new(0, true)
    }
}
