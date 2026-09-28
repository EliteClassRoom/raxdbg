//! Bounded ring buffer of recent `(pc, registers)` snapshots.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/CodeHistory.java@7f5da98e`.
//!
//! unidbg's `CodeHistory` records `(address, size, thumb)` for every traced
//! instruction; this Rust port additionally snapshots a register file so the
//! `t` (backtrace) command in the console debugger has something to walk
//! (`CodeHistory` is the fallback when `.eh_frame`/`PT_ARM_EXIDX` is
//! insufficient). The buffer has a fixed capacity and silently drops the
//! oldest entry once full, matching the unidbg ring buffer sized at
//! `OPTION_CODE_TRACE_BUFFER_SIZE = 1024`.

use std::collections::{BTreeMap, VecDeque};

use crate::reg::RegId;

/// One entry in the [`CodeHistory`] ring.
#[derive(Clone, Debug)]
pub struct HistoryEntry {
    /// The program counter at the time of the snapshot.
    pub pc: u64,
    /// The register file captured alongside the PC.
    pub registers: BTreeMap<RegId, u64>,
    /// The decoded instruction size in bytes. `0` when unknown.
    pub size: u32,
}

impl HistoryEntry {
    fn new(pc: u64, registers: BTreeMap<RegId, u64>, size: u32) -> Self {
        Self {
            pc,
            registers,
            size,
        }
    }
}

/// A bounded ring buffer of [`HistoryEntry`] snapshots.
///
/// When `capacity` entries have been recorded and a new one is pushed, the
/// oldest is silently dropped. This matches unidbg's `CodeHistory` semantics:
/// backtraces and register dumps always look at the most recent run, never at
/// a specific moment in the past.
pub struct CodeHistory {
    capacity: usize,
    entries: VecDeque<HistoryEntry>,
}

impl CodeHistory {
    /// Creates a new buffer with the given `capacity` (must be `> 0`).
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "CodeHistory capacity must be > 0");
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
        }
    }

    /// Returns the configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records `(pc, registers, size)`. If the buffer is full, the oldest
    /// entry is evicted.
    pub fn add(&mut self, pc: u64, registers: BTreeMap<RegId, u64>, size: u32) {
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(HistoryEntry::new(pc, registers, size));
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterates over the entries, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &HistoryEntry> {
        self.entries.iter()
    }

    /// Returns the last `n` entries, oldest first. If fewer than `n` entries
    /// are stored, returns all of them.
    pub fn last(&self, n: usize) -> Vec<&HistoryEntry> {
        let start = self.entries.len().saturating_sub(n);
        self.entries.range(start..).collect()
    }

    /// The most recent entry, if any.
    pub fn latest(&self) -> Option<&HistoryEntry> {
        self.entries.back()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regmap(values: &[(RegId, u64)]) -> BTreeMap<RegId, u64> {
        values.iter().copied().collect()
    }

    #[test]
    fn add_grows_up_to_capacity() {
        let mut history = CodeHistory::new(3);
        for pc in 0..3 {
            history.add(pc * 0x1000, regmap(&[(RegId::Pc, pc * 0x1000)]), 4);
        }
        assert_eq!(history.len(), 3);
        assert_eq!(
            history.iter().map(|e| e.pc).collect::<Vec<_>>(),
            vec![0x0, 0x1000, 0x2000]
        );
    }

    #[test]
    fn add_past_capacity_evicts_oldest() {
        let mut history = CodeHistory::new(2);
        for pc in 0..4 {
            history.add(pc * 0x1000, regmap(&[(RegId::Pc, pc * 0x1000)]), 4);
        }
        assert_eq!(history.len(), 2);
        assert_eq!(
            history.iter().map(|e| e.pc).collect::<Vec<_>>(),
            vec![0x2000, 0x3000]
        );
    }

    #[test]
    fn last_returns_the_recent_window() {
        let mut history = CodeHistory::new(5);
        for pc in 0..8u64 {
            history.add(pc * 0x1000, regmap(&[(RegId::Pc, pc * 0x1000)]), 4);
        }
        let window: Vec<u64> = history.last(3).into_iter().map(|e| e.pc).collect();
        assert_eq!(window, vec![0x5000, 0x6000, 0x7000]);
    }

    #[test]
    fn last_returns_everything_when_underflow() {
        let mut history = CodeHistory::new(10);
        history.add(0x42, regmap(&[(RegId::Pc, 0x42)]), 4);
        let window: Vec<u64> = history.last(5).into_iter().map(|e| e.pc).collect();
        assert_eq!(window, vec![0x42]);
    }

    #[test]
    fn clear_wipes_the_buffer() {
        let mut history = CodeHistory::new(4);
        for pc in 0..4 {
            history.add(pc, regmap(&[(RegId::Pc, pc)]), 4);
        }
        assert!(!history.is_empty());
        history.clear();
        assert!(history.is_empty());
        assert_eq!(history.len(), 0);
    }
}
