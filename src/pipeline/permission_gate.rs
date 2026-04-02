//! Stage 4: Permission Gate (Elicitation)
//!
//! For dangerous commands, uses MCP elicitation to ask the user for permission.
//! If elicitation is not supported by the client, defaults to DENY.

use rmcp::{
    elicit_safe,
    schemars::JsonSchema,
    service::{RequestContext, RoleServer},
};
use serde::{Deserialize, Serialize};

/// Elicitation schema for command permission.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CommandPermission {
    #[schemars(description = "Do you approve this command execution?")]
    pub approved: bool,
}

elicit_safe!(CommandPermission);

/// The gate decision after elicitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    Approved,
    Denied { reason: String },
}

/// Ask the user for permission to execute a dangerous command.
pub async fn gate(
    context: &RequestContext<RoleServer>,
    command_display: &str,
    danger_reason: &str,
) -> GateDecision {
    let message = format!(
        "DANGEROUS COMMAND DETECTED\n\
         Command: {command_display}\n\
         Reason: {danger_reason}\n\
         \n\
         Do you approve execution?"
    );

    match context.peer.elicit::<CommandPermission>(message).await {
        Ok(Some(permission)) => {
            if permission.approved {
                GateDecision::Approved
            } else {
                GateDecision::Denied {
                    reason: "User declined command execution".to_string(),
                }
            }
        }
        Ok(None) => GateDecision::Denied {
            reason: "User cancelled the elicitation".to_string(),
        },
        Err(e) => {
            tracing::warn!("Elicitation failed (client may not support it): {e}");
            GateDecision::Denied {
                reason: format!("Elicitation not supported or failed: {e}. Defaulting to DENY."),
            }
        }
    }
}
