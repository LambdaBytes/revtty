use crate::error::RevttyError;

pub async fn enroll(_relay: &str, _token: &str) -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent enrollment"))
}

pub async fn run() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent runtime"))
}

pub fn status() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent status"))
}

pub fn doctor() -> Result<(), RevttyError> {
    println!("agent scaffold: ok");
    println!("control protocol v{}", crate::protocol::CONTROL_PROTOCOL_VERSION);
    Ok(())
}
