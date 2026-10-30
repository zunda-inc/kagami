use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum KagamiError {
    OptionalGuard(String),
    FailedToResolveConfigFilePath(),
}

impl Display for KagamiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KagamiError::OptionalGuard(s) => {
                write!(f, "`{}` must not be None value.", s)
            }
            KagamiError::FailedToResolveConfigFilePath() => {
                write!(f, "Failed to resolve config file path.")
            }
        }
    }
}

impl Error for KagamiError {}
