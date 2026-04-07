//! Policy subcommands.

use clap::Subcommand;
use owx::Owx;

use crate::output::print_json;

#[derive(Subcommand)]
pub(crate) enum PolicyAction {
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

pub(crate) fn run(action: PolicyAction, owx: &Owx) -> Result<(), owx::OwxError> {
    match action {
        PolicyAction::Create { id, json } => {
            owx.create_policy(&id, &json)?;
            print_json(&serde_json::json!({ "status": "created", "id": id }))
        }
        PolicyAction::List => print_json(&owx.list_policies()?),
        PolicyAction::Info { id } => print_json(&owx.get_policy(&id)?),
        PolicyAction::Delete { id } => {
            owx.delete_policy(&id)?;
            print_json(&serde_json::json!({ "status": "deleted", "id": id }))
        }
    }
}
