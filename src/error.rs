use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum KagamiError {
    OptionalGuard(String),
    VersionRangeInconsistent(String),
}

impl Display for KagamiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KagamiError::OptionalGuard(s) => {
                write!(f, "`{}` must not be None value.", s)
            }
            KagamiError::VersionRangeInconsistent(s) => {
                write!(f, "`{}` is unexpected version range.", s)
            }
        }
    }
}

impl Error for KagamiError {}
