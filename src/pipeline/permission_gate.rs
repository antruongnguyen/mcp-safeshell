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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_decision_approved_equality() {
        assert_eq!(GateDecision::Approved, GateDecision::Approved);
    }

    #[test]
    fn gate_decision_denied_equality() {
        let a = GateDecision::Denied {
            reason: "test".into(),
        };
        let b = GateDecision::Denied {
            reason: "test".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn gate_decision_approved_not_denied() {
        let denied = GateDecision::Denied {
            reason: "nope".into(),
        };
        assert_ne!(GateDecision::Approved, denied);
    }

    #[test]
    fn gate_decision_denied_different_reasons() {
        let a = GateDecision::Denied {
            reason: "reason a".into(),
        };
        let b = GateDecision::Denied {
            reason: "reason b".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn command_permission_serde_roundtrip() {
        let perm = CommandPermission { approved: true };
        let json = serde_json::to_string(&perm).unwrap();
        let deser: CommandPermission = serde_json::from_str(&json).unwrap();
        assert!(deser.approved);
    }

    #[test]
    fn command_permission_false_roundtrip() {
        let perm = CommandPermission { approved: false };
        let json = serde_json::to_string(&perm).unwrap();
        let deser: CommandPermission = serde_json::from_str(&json).unwrap();
        assert!(!deser.approved);
    }
}
