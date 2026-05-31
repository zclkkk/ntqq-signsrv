use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Toml(toml::de::Error),
    Hex(hex::FromHexError),
    DlOpen(String),
    VersionNotFound(String),
    Config(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "IO error: {}", e),
            AppError::Json(e) => write!(f, "JSON error: {}", e),
            AppError::Toml(e) => write!(f, "TOML error: {}", e),
            AppError::Hex(e) => write!(f, "Hex decode error: {}", e),
            AppError::DlOpen(msg) => write!(f, "dlopen error: {}", msg),
            AppError::VersionNotFound(key) => write!(f, "version not found: {}", key),
            AppError::Config(msg) => write!(f, "config error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self { AppError::Io(e) }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self { AppError::Json(e) }
}

impl From<toml::de::Error> for AppError {
    fn from(e: toml::de::Error) -> Self { AppError::Toml(e) }
}

impl From<hex::FromHexError> for AppError {
    fn from(e: hex::FromHexError) -> Self { AppError::Hex(e) }
}
