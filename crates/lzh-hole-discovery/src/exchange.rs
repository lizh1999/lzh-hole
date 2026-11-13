//! Bounded request/reply correlation after signed-message verification.

use std::collections::{HashSet, VecDeque};

use crate::message::{MessageKind, RequestId, VerifiedPayload};
use crate::record::AcceptOutcome;

/// Maximum number of live request IDs remembered for reply de-duplication.
pub const MAX_REPLIED_REQUESTS: usize = 1024;
/// Maximum number of locally initiated requests awaiting a live reply.
pub const MAX_PENDING_REQUESTS: usize = 64;

/// ntfy delivery classification. Cached data is always only a historical hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Observed on a live subscription with a server timestamp at/after subscribe.
    Live,
    /// Replayed after `since=all`, or not provably newer than this subscription.
    /// ntfy has second-resolution timestamps, so an ambiguous same-second message
    /// is conservatively Cached; daemon recovery always sends a fresh live request.
    Cached,
}

/// What the daemon should do with correlation after independent verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeAction {
    /// Publish at most one reply with this same request ID and a fresh reserved seq.
    ReplyOnce(RequestId),
    /// A cached message; use candidates as hints but do not reply or complete a request.
    Cached,
    /// A duplicate/idempotent request; do not reply again.
    DuplicateRequest,
    /// A live reply matched a locally registered request; request is now complete.
    ReplyMatched(RequestId),
    /// A valid but unsolicited or already-consumed reply; no state transition.
    UnmatchedReply,
}

/// Why a local request could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeError {
    /// The bounded pending-request table is full; wait for replies or cancel one.
    #[error("too many pending signaling requests")]
    TooManyPending,
    /// Request IDs must not be reused while still pending.
    #[error("request ID is already pending")]
    DuplicateRequestId,
}

/// Bounded request/reply correlation and one-reply state.
///
/// This logic runs AFTER signature and `PeerRecordCache` verification. Thus an
/// unauthenticated forged ID cannot suppress a legitimate peer's request.
#[derive(Debug, Default)]
pub struct ExchangeTracker {
    pending: HashSet<RequestId>,
    replied: HashSet<RequestId>,
    replied_order: VecDeque<RequestId>,
}

impl ExchangeTracker {
    /// Register an outgoing request before queueing it. The bound is explicit.
    pub fn register_request(&mut self, request_id: RequestId) -> Result<(), ExchangeError> {
        if self.pending.contains(&request_id) {
            return Err(ExchangeError::DuplicateRequestId);
        }
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(ExchangeError::TooManyPending);
        }
        self.pending.insert(request_id);
        Ok(())
    }

    /// Remove a timed-out or cancelled local request without accepting later replies.
    pub fn cancel_request(&mut self, request_id: RequestId) -> bool {
        self.pending.remove(&request_id)
    }

    /// Apply live/cached and one-reply semantics to an already verified message.
    pub fn on_verified(&mut self, message: &VerifiedPayload, delivery: Delivery) -> ExchangeAction {
        if delivery == Delivery::Cached {
            return ExchangeAction::Cached;
        }
        match message.kind {
            MessageKind::Request => {
                // The durable record cache supplies a second line of defence after
                // process restart or bounded in-memory ID eviction.
                if message.accept_outcome == AcceptOutcome::Idempotent
                    || self.replied.contains(&message.request_id)
                {
                    return ExchangeAction::DuplicateRequest;
                }
                self.replied.insert(message.request_id);
                self.replied_order.push_back(message.request_id);
                if self.replied_order.len() > MAX_REPLIED_REQUESTS {
                    let oldest = self
                        .replied_order
                        .pop_front()
                        .expect("length exceeds the replied-request bound");
                    self.replied.remove(&oldest);
                }
                ExchangeAction::ReplyOnce(message.request_id)
            }
            MessageKind::Reply => {
                if self.pending.remove(&message.request_id) {
                    ExchangeAction::ReplyMatched(message.request_id)
                } else {
                    ExchangeAction::UnmatchedReply
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
