use serde::{Deserialize, Serialize};

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
pub const OPERATOR_AUTH_NAMESPACE: &str = "revtty-control-v1";
pub const SESSION_ERROR_PREFIX: &str = "revtty-error:";

pub fn operator_auth_message(agent_name: &str, challenge: &str) -> String {
    format!("revtty-control-v1\nagent={agent_name}\nchallenge={challenge}\n")
}

pub fn operator_list_auth_message(challenge: &str) -> String {
    format!("revtty-control-v1\nscope=list\nchallenge={challenge}\n")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRejectReason {
    Busy,
    IncompatibleVersion,
    InternalError,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Hello {
        version: u16,
        name: String,
        agent_version: String,
        #[serde(default)]
        active_sessions: usize,
        #[serde(default)]
        max_sessions: usize,
    },
    Heartbeat {
        version: u16,
        #[serde(default)]
        active_sessions: usize,
    },
    ProbeOffer {
        version: u16,
        session_id: String,
        tunnel_token: String,
    },
    ShellOffer {
        version: u16,
        session_id: String,
        tunnel_token: String,
    },
    SessionAccept {
        version: u16,
        session_id: String,
    },
    SessionReject {
        version: u16,
        session_id: String,
        reason: SessionRejectReason,
    },
    SessionCancel {
        version: u16,
        session_id: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusResponse {
    pub id: String,
    pub name: String,
    pub online: bool,
    pub active_sessions: usize,
    pub max_sessions: Option<usize>,
    pub created_at: i64,
    pub last_seen: Option<i64>,
    pub version: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub name: String,
    pub os: String,
    pub arch: String,
    pub version: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub host_key: String,
    pub version: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub name: String,
    pub control_token: String,
    pub operator_key: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorChallengeResponse {
    pub challenge: String,
    pub expires_in_secs: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorListRequest {
    pub operator_key: String,
    pub challenge: String,
    pub signature: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentListResponse {
    pub agents: Vec<AgentStatusResponse>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAuthRequest {
    pub challenge: String,
    pub signature: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAuthResponse {
    pub session_token: String,
    pub expires_in_secs: u64,
    pub host_key: String,
}

#[cfg(test)]
mod tests {
    use super::{
        AgentListResponse, AgentStatusResponse, ControlMessage, EnrollRequest, EnrollResponse,
        OperatorAuthRequest, OperatorAuthResponse, OperatorChallengeResponse, OperatorListRequest,
        ProbeResult, SessionRejectReason, operator_auth_message, operator_list_auth_message,
    };

    #[test]
    fn control_message_round_trips() {
        let message = ControlMessage::ProbeOffer {
            version: 1,
            session_id: "session".to_owned(),
            tunnel_token: "rvs_probe".to_owned(),
        };
        let json = serde_json::to_string(&message).expect("serialize");
        let decoded: ControlMessage = serde_json::from_str(&json).expect("deserialize");
        assert!(decoded == message);
    }

    #[test]
    fn shell_offer_round_trips() {
        let message = ControlMessage::ShellOffer {
            version: 1,
            session_id: "shell-session".to_owned(),
            tunnel_token: "rvs_shell".to_owned(),
        };
        let json = serde_json::to_string(&message).expect("serialize shell offer");
        let decoded: ControlMessage = serde_json::from_str(&json).expect("deserialize shell offer");
        assert!(decoded == message);
    }

    #[test]
    fn session_lifecycle_messages_round_trip() {
        for message in [
            ControlMessage::SessionAccept {
                version: 1,
                session_id: "session".to_owned(),
            },
            ControlMessage::SessionReject {
                version: 1,
                session_id: "session".to_owned(),
                reason: SessionRejectReason::Busy,
            },
            ControlMessage::SessionCancel {
                version: 1,
                session_id: "session".to_owned(),
            },
        ] {
            let json = serde_json::to_string(&message).expect("serialize lifecycle message");
            let decoded: ControlMessage =
                serde_json::from_str(&json).expect("deserialize lifecycle message");
            assert!(decoded == message);
        }
    }

    #[test]
    fn enrollment_messages_round_trip() {
        let request = EnrollRequest {
            token: "rve_secret".to_owned(),
            host_key: "ssh-ed25519 AAAA".to_owned(),
            version: "0.1.0".to_owned(),
        };
        let encoded = serde_json::to_string(&request).expect("serialize enrollment request");
        let decoded: EnrollRequest =
            serde_json::from_str(&encoded).expect("deserialize enrollment request");
        assert!(decoded == request);

        let response = EnrollResponse {
            agent_id: "agent-id".to_owned(),
            name: "store-042".to_owned(),
            control_token: "rva_secret".to_owned(),
            operator_key: "ssh-ed25519 BBBB".to_owned(),
        };
        let encoded = serde_json::to_string(&response).expect("serialize enrollment response");
        let decoded: EnrollResponse =
            serde_json::from_str(&encoded).expect("deserialize enrollment response");
        assert!(decoded == response);
    }

    #[test]
    fn operator_auth_messages_round_trip() {
        let challenge = OperatorChallengeResponse {
            challenge: "rvc_random".to_owned(),
            expires_in_secs: 30,
        };
        let encoded = serde_json::to_string(&challenge).expect("serialize challenge");
        let decoded: OperatorChallengeResponse =
            serde_json::from_str(&encoded).expect("deserialize challenge");
        assert!(decoded == challenge);

        let request = OperatorAuthRequest {
            challenge: challenge.challenge.clone(),
            signature: "-----BEGIN SSH SIGNATURE-----".to_owned(),
        };
        let encoded = serde_json::to_string(&request).expect("serialize auth request");
        let decoded: OperatorAuthRequest =
            serde_json::from_str(&encoded).expect("deserialize auth request");
        assert!(decoded == request);

        let response = OperatorAuthResponse {
            session_token: "rvo_secret".to_owned(),
            expires_in_secs: 30,
            host_key: "ssh-ed25519 AAAA host".to_owned(),
        };
        let encoded = serde_json::to_string(&response).expect("serialize auth response");
        let decoded: OperatorAuthResponse =
            serde_json::from_str(&encoded).expect("deserialize auth response");
        assert!(decoded == response);

        assert_eq!(
            operator_auth_message("store-042", "rvc_random"),
            "revtty-control-v1\nagent=store-042\nchallenge=rvc_random\n"
        );
    }

    #[test]
    fn operator_list_messages_round_trip() {
        let request = OperatorListRequest {
            operator_key: "ssh-ed25519 AAAA operator".to_owned(),
            challenge: "rvc_list".to_owned(),
            signature: "-----BEGIN SSH SIGNATURE-----".to_owned(),
        };
        let json = serde_json::to_string(&request).expect("serialize operator list request");
        let decoded: OperatorListRequest =
            serde_json::from_str(&json).expect("deserialize operator list request");
        assert!(decoded == request);

        let response = AgentListResponse {
            agents: vec![AgentStatusResponse {
                id: "agent-id".to_owned(),
                name: "store-042".to_owned(),
                online: false,
                active_sessions: 0,
                max_sessions: None,
                created_at: 1_700_000_000,
                last_seen: Some(1_700_000_030),
                version: Some("0.1.0".to_owned()),
            }],
        };
        let json = serde_json::to_string(&response).expect("serialize agent list");
        let decoded: AgentListResponse =
            serde_json::from_str(&json).expect("deserialize agent list");
        assert!(decoded == response);

        assert_eq!(
            operator_list_auth_message("rvc_list"),
            "revtty-control-v1\nscope=list\nchallenge=rvc_list\n"
        );
    }

    #[test]
    fn agent_status_round_trips() {
        let status = AgentStatusResponse {
            id: "agent-id".to_owned(),
            name: "store-042".to_owned(),
            online: true,
            active_sessions: 2,
            max_sessions: Some(4),
            created_at: 1_700_000_000,
            last_seen: Some(1_700_000_030),
            version: Some("0.1.0".to_owned()),
        };
        let json = serde_json::to_string(&status).expect("serialize agent status");
        let decoded: AgentStatusResponse =
            serde_json::from_str(&json).expect("deserialize agent status");
        assert!(decoded == status);
    }

    #[test]
    fn probe_result_round_trips() {
        let result = ProbeResult {
            name: "store-042".to_owned(),
            os: "linux".to_owned(),
            arch: "aarch64".to_owned(),
            version: "0.1.0".to_owned(),
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let decoded: ProbeResult = serde_json::from_str(&json).expect("deserialize");
        assert!(decoded == result);
    }
}
