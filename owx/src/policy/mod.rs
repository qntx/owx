//! Policy types and declarative + executable evaluation engine.

mod engine;
mod executable;
mod types;

pub use engine::evaluate;
pub use types::{
    Policy, PolicyContext, PolicyResult, PolicyRule, SpendingContext, TransactionContext,
};

use crate::Error;

/// Load a policy from the vault store, returning a domain error on miss.
pub fn load_policy(store: &owx_vault::Store, id: &str) -> Result<Policy, Error> {
    store
        .load::<Policy>("policies", id)
        .map_err(|_| Error::PolicyNotFound(id.to_owned()))
}

/// List all policies sorted alphabetically by name.
pub fn list_policies(store: &owx_vault::Store) -> Result<Vec<Policy>, Error> {
    let mut policies: Vec<Policy> = store.list("policies")?;
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(policies)
}
