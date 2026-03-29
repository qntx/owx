//! Policy system: declarative evaluation and executable policies.
//!
//! Policy types ([`Policy`], [`PolicyRule`], [`PolicyContext`], [`PolicyResult`])
//! live in [`owx_core::policy`] and are re-exported here for convenience.

pub mod engine;
pub mod error;
pub mod executable;

pub use engine::evaluate;
pub use error::PolicyError;
pub use owx_core::policy::{
    Policy, PolicyAction, PolicyContext, PolicyResult, PolicyRule, SpendingContext,
    TransactionContext,
};
