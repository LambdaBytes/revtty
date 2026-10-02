use serde::{Deserialize, Serialize};

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Hello { version: u16, name: String },
    Heartbeat { version: u16 },
    ProbeOffer { version: u16, session_id: String },
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

#[cfg(test)]
mod tests {
    use super::{ControlMessage, EnrollRequest, EnrollResponse, ProbeResult};

    #[test]
    fn control_message_round_trips() {
        let message = ControlMessage::ProbeOffer {
            version: 1,
            session_id: "session".to_owned(),
        };
        let json = serde_json::to_string(&message).expect("serialize");
        let decoded: ControlMessage = serde_json::from_str(&json).expect("deserialize");
        assert!(decoded == message);
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
