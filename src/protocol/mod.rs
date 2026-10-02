mod control;

pub use control::{CONTROL_PROTOCOL_VERSION, ControlMessage};

#[cfg(test)]
mod tests {
    use super::{CONTROL_PROTOCOL_VERSION, ControlMessage};

    #[test]
    fn control_message_round_trips() {
        let message = ControlMessage::Heartbeat {
            version: CONTROL_PROTOCOL_VERSION,
            active_sessions: 1,
        };

        let json = serde_json::to_string(&message).expect("serialize control message");
        let decoded: ControlMessage =
            serde_json::from_str(&json).expect("deserialize control message");

        assert!(decoded == message);
    }
}
