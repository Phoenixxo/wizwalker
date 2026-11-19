//! Read local executables and find Wizard101 hook candidates.
#![forbid(unsafe_code)]
pub mod pe;
pub mod wizard101;
pub mod x64;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct Error {
    pub context: String,
    pub message: String,
}
impl Error {
    pub fn new(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            context: context.into(),
            message: message.into(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.context, self.message)
    }
}
impl std::error::Error for Error {}
