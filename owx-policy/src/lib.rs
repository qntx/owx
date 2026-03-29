//! Policy system: rule types, declarative evaluation, and executable policies.

pub mod engine;
pub mod error;
pub mod executable;
pub mod types;

pub use engine::evaluate;
pub use error::PolicyError;
pub use types::{Policy, PolicyAction, PolicyContext, PolicyResult, PolicyRule};
