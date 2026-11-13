//! Per-direction replay window.
//!
//! A sliding bitmap of at least 1024 bits. The window is only ever advanced
//! after the frame MAC has been verified, so an attacker cannot move it.

/// Width of the sliding window in bits.
pub const WINDOW_BITS: u32 = 1024;

/// Replay window for one direction of one session.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: u64,
    seen: [u64; (WINDOW_BITS / 64) as usize],
    started: bool,
}

/// Why a sequence number was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReject {
    /// Already accepted.
    Duplicate,
    /// Older than the window allows.
    TooOld,
}

impl ReplayWindow {
    /// A fresh window that has accepted nothing.
    pub const fn new() -> Self {
        Self {
            highest: 0,
            seen: [0; (WINDOW_BITS / 64) as usize],
            started: false,
        }
    }

    /// The highest sequence accepted so far, if any.
    pub const fn highest(&self) -> Option<u64> {
        if self.started {
            Some(self.highest)
        } else {
            None
        }
    }

    /// Number of slots currently marked.
    pub fn count(&self) -> u32 {
        self.seen.iter().map(|w| w.count_ones()).sum()
    }

    /// Test whether `seq` would be accepted, without mutating.
    pub fn would_accept(&self, seq: u64) -> Result<(), ReplayReject> {
        if !self.started {
            return Ok(());
        }
        if seq > self.highest {
            return Ok(());
        }
        let age = self.highest - seq;
        if age >= u64::from(WINDOW_BITS) {
            return Err(ReplayReject::TooOld);
        }
        if self.bit(seq) {
            return Err(ReplayReject::Duplicate);
        }
        Ok(())
    }

    /// Accept `seq`, advancing the window. Call only after MAC verification.
    pub fn accept(&mut self, seq: u64) -> Result<(), ReplayReject> {
        self.would_accept(seq)?;
        if !self.started {
            self.started = true;
            self.highest = seq;
            self.set_bit(seq);
            return Ok(());
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.shift(shift);
            self.highest = seq;
        }
        self.set_bit(seq);
        Ok(())
    }

    fn bit(&self, seq: u64) -> bool {
        let age = self.highest - seq;
        let word = (age / 64) as usize;
        let bit = age % 64;
        self.seen[word] & (1u64 << bit) != 0
    }

    fn set_bit(&mut self, seq: u64) {
        let age = self.highest - seq;
        let word = (age / 64) as usize;
        let bit = age % 64;
        self.seen[word] |= 1u64 << bit;
    }

    fn shift(&mut self, by: u64) {
        if by >= u64::from(WINDOW_BITS) {
            self.seen = [0; (WINDOW_BITS / 64) as usize];
            return;
        }
        let words = (by / 64) as usize;
        let bits = (by % 64) as u32;
        let len = self.seen.len();
        if words > 0 {
            self.seen.copy_within(0..len - words, words);
            self.seen[..words].fill(0);
        }
        if bits > 0 {
            // Walk high to low so seen[i - 1] is still the pre-shift value.
            for i in (0..len).rev() {
                let carry = if i == 0 {
                    0
                } else {
                    self.seen[i - 1] >> (64 - bits)
                };
                self.seen[i] = (self.seen[i] << bits) | carry;
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_window_accepts_anything_once() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.highest(), None);
        assert!(w.accept(7).is_ok());
        assert_eq!(w.highest(), Some(7));
        assert_eq!(w.accept(7), Err(ReplayReject::Duplicate));
    }

    #[test]
    fn in_order_and_out_of_order_within_window_are_accepted() {
        let mut w = ReplayWindow::new();
        for seq in [10u64, 11, 12, 15, 13, 14, 9] {
            assert!(w.accept(seq).is_ok(), "seq {seq}");
        }
        assert_eq!(w.highest(), Some(15));
        assert_eq!(w.count(), 7);
    }

    #[test]
    fn duplicates_are_refused() {
        let mut w = ReplayWindow::new();
        w.accept(100).unwrap();
        w.accept(99).unwrap();
        assert_eq!(w.accept(100), Err(ReplayReject::Duplicate));
        assert_eq!(w.accept(99), Err(ReplayReject::Duplicate));
    }

    #[test]
    fn window_boundary_is_exact() {
        let mut w = ReplayWindow::new();
        w.accept(u64::from(WINDOW_BITS) + 1000).unwrap();
        // age == WINDOW_BITS - 1 is still inside
        assert!(w.accept(1001).is_ok());
        // age == WINDOW_BITS is outside
        assert_eq!(w.accept(1000), Err(ReplayReject::TooOld));
        assert_eq!(w.accept(0), Err(ReplayReject::TooOld));
    }

    #[test]
    fn large_jump_clears_the_window_without_panicking() {
        let mut w = ReplayWindow::new();
        for seq in 0..100u64 {
            w.accept(seq).unwrap();
        }
        assert!(w.accept(1_000_000).is_ok());
        assert_eq!(w.highest(), Some(1_000_000));
        assert_eq!(w.count(), 1);
        assert_eq!(w.accept(50), Err(ReplayReject::TooOld));
    }

    #[test]
    fn many_small_shifts_keep_recent_history() {
        let mut w = ReplayWindow::new();
        w.accept(0).unwrap();
        for seq in 1..2000u64 {
            w.accept(seq).unwrap();
        }
        assert_eq!(w.highest(), Some(1999));
        // Every one of the most recent 1024 is remembered exactly once.
        assert_eq!(w.count(), WINDOW_BITS);
        for seq in (2000 - u64::from(WINDOW_BITS))..2000 {
            assert_eq!(
                w.would_accept(seq),
                Err(ReplayReject::Duplicate),
                "seq {seq}"
            );
        }
    }

    #[test]
    fn shift_by_word_multiples_is_correct() {
        let mut w = ReplayWindow::new();
        w.accept(0).unwrap();
        w.accept(1).unwrap();
        w.accept(64).unwrap();
        assert_eq!(w.would_accept(1), Err(ReplayReject::Duplicate));
        assert!(w.accept(65).is_ok());
        w.accept(200).unwrap();
        // Still inside the window, so it is remembered rather than too old.
        assert_eq!(w.would_accept(0), Err(ReplayReject::Duplicate));
        // Far outside the window it becomes TooOld.
        w.accept(200 + u64::from(WINDOW_BITS)).unwrap();
        assert_eq!(w.would_accept(0), Err(ReplayReject::TooOld));
    }

    #[test]
    fn sequence_zero_can_never_be_a_session_frame() {
        // Session frames start at 1; this documents that the window itself does
        // not special-case zero, the caller enforces the rule.
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());
    }
}
