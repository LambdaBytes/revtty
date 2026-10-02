use crate::error::RevttyError;

pub fn init() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("relay initialization"))
}

pub async fn serve() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("relay server"))
}

pub fn doctor() -> Result<(), RevttyError> {
    println!("relay scaffold: ok");
    println!(
        "control protocol v{}",
        crate::protocol::CONTROL_PROTOCOL_VERSION
    );
    Ok(())
}
