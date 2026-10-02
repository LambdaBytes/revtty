use crate::config::Paths;
use crate::error::RevttyError;

pub fn init() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("operator initialization"))
}

pub fn list() -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent listing"))
}

pub fn status(_target: &str) -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("agent status"))
}

pub async fn connect(_target: &str) -> Result<(), RevttyError> {
    Err(RevttyError::NotImplemented("remote terminal connection"))
}

pub fn doctor() -> Result<(), RevttyError> {
    let paths = Paths::new("~/.config/revtty", "~/.local/share/revtty");
    println!("revtty {}", env!("CARGO_PKG_VERSION"));
    println!(
        "control protocol v{}",
        crate::protocol::CONTROL_PROTOCOL_VERSION
    );
    println!("default transport: {}", crate::transport::DEFAULT_TRANSPORT);
    println!("config: {}", paths.config_dir.display());
    println!("state: {}", paths.state_dir.display());
    Ok(())
}
