//! Policy subcommands.

use clap::Subcommand;
use owx::Owx;

use crate::output::print_json;

#[derive(Subcommand)]
pub enum PolicyAction {
    Create {
        id: String,
        #[arg(long)]
        json: String,
    },
    List,
    Info {
        id: String,
    },
    Delete {
        id: String,
    },
}

#[allow(clippy::print_stdout)]
pub fn run(action: PolicyAction, owx: &Owx) -> Result<(), owx::Error> {
    let store = owx.store();
    match action {
        PolicyAction::Create { id, json } => {
            store.save_raw("policies", &id, &json)?;
            print_json(&serde_json::json!({ "status": "created", "id": id }))
        }
        PolicyAction::List => {
            let policies = owx::policy::list_policies(store)?;
            print_json(&policies)
        }
        PolicyAction::Info { id } => {
            let raw = store.load_raw("policies", &id)?;
            let value: serde_json::Value = serde_json::from_str(&raw)?;
            print_json(&value)
        }
        PolicyAction::Delete { id } => {
            store.delete("policies", &id)?;
            print_json(&serde_json::json!({ "status": "deleted", "id": id }))
        }
    }
}
