use joinstr::interface;

/// Error thrown across the binding. Carries a human-readable message.
#[derive(Debug, Clone)]
pub struct JoinstrError {
    pub message: String,
}

impl JoinstrError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for JoinstrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for JoinstrError {}

impl From<interface::Error> for JoinstrError {
    fn from(value: interface::Error) -> Self {
        JoinstrError::new(value.to_string())
    }
}
