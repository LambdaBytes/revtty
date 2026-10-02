use serde::{Deserialize, Serialize};

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Hello {
        version: u16,
        agent_id: String,
        agent_version: String,
    },
    Heartbeat {
        version: u16,
        active_sessions: u32,
    },
    SessionOffer {
        version: u16,
        session_id: String,
        expires_at_unix: u64,
        tunnel_token: String,
    },
    SessionAccept {
        version: u16,
        session_id: String,
    },
    SessionReject {
        version: u16,
        session_id: String,
        reason: String,
    },
    SessionCancel {
        version: u16,
        session_id: String,
    },
}
